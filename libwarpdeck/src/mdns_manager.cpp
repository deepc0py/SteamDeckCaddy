#include "mdns_manager.h"
#include "discovery_manager.h"
#include "logger.h"
#include "../../third_party/mjansson_mdns/mdns.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#endif

namespace warpdeck {

MdnsManager::MdnsManager() 
    : should_stop_(false)
    , is_publishing_(false)
    , is_discovering_(false) {
    Logger::instance().instance().info("MdnsManager", "MdnsManager initialized");
}

MdnsManager::~MdnsManager() {
    stop_publishing();
    stop_discovery();
    
    if (network_thread_.joinable()) {
        should_stop_ = true;
        thread_cv_.notify_all();
        network_thread_.join();
    }
    
    cleanup_sockets();
    Logger::instance().instance().info("MdnsManager", "MdnsManager destroyed");
}

bool MdnsManager::publish_service(const std::string& device_id, const std::string& fingerprint, int port) {
    std::lock_guard<std::mutex> lock(service_mutex_);
    
    if (is_publishing_.load()) {
        Logger::instance().instance().warn("MdnsManager", "Service already being published");
        return false;
    }
    
    service_info_.device_id = device_id;
    service_info_.fingerprint = fingerprint;
    service_info_.port = port;
    
    if (!initialize_sockets()) {
        Logger::instance().instance().error("MdnsManager", "Failed to initialize sockets for publishing");
        return false;
    }
    
    // Start network thread if not already running
    if (!network_thread_.joinable()) {
        should_stop_ = false;
        network_thread_ = std::thread(&MdnsManager::network_thread_main, this);
    }
    
    is_publishing_ = true;
    thread_cv_.notify_all();
    
    Logger::instance().instance().info("MdnsManager", "Started publishing service for device: " + device_id);
    return true;
}

void MdnsManager::stop_publishing() {
    if (!is_publishing_.load()) {
        return;
    }
    
    // Send goodbye packets before stopping
    {
        std::lock_guard<std::mutex> service_lock(service_mutex_);
        std::lock_guard<std::mutex> socket_lock(sockets_mutex_);
        
        char buffer[2048];
        std::string hostname = get_local_hostname();
        std::string service_instance = service_info_.device_id + "._warpdeck._tcp.local.";
        std::string service_type = "_warpdeck._tcp.local.";
        std::string target_host = hostname + ".local.";
        
        // Create goodbye records
        mdns_record_t goodbye_records[3];
        size_t record_count = 0;
        
        // PTR record goodbye
        goodbye_records[record_count].name.str = service_type.c_str();
        goodbye_records[record_count].name.length = service_type.length();
        goodbye_records[record_count].type = MDNS_RECORDTYPE_PTR;
        goodbye_records[record_count].data.ptr.name.str = service_instance.c_str();
        goodbye_records[record_count].data.ptr.name.length = service_instance.length();
        record_count++;
        
        // SRV record goodbye
        goodbye_records[record_count].name.str = service_instance.c_str();
        goodbye_records[record_count].name.length = service_instance.length();
        goodbye_records[record_count].type = MDNS_RECORDTYPE_SRV;
        goodbye_records[record_count].data.srv.priority = 0;
        goodbye_records[record_count].data.srv.weight = 0;
        goodbye_records[record_count].data.srv.port = service_info_.port;
        goodbye_records[record_count].data.srv.name.str = target_host.c_str();
        goodbye_records[record_count].data.srv.name.length = target_host.length();
        record_count++;
        
        // TXT record goodbye - empty TXT record
        goodbye_records[record_count].name.str = service_instance.c_str();
        goodbye_records[record_count].name.length = service_instance.length();
        goodbye_records[record_count].type = MDNS_RECORDTYPE_TXT;
        goodbye_records[record_count].data.txt.key.str = "";
        goodbye_records[record_count].data.txt.key.length = 0;
        goodbye_records[record_count].data.txt.value.str = "";
        goodbye_records[record_count].data.txt.value.length = 0;
        record_count++;
        
        // Send goodbye packets on all sockets
        for (int sock : sockets_) {
            for (size_t i = 0; i < record_count; ++i) {
                int result = mdns_goodbye_multicast(sock, buffer, sizeof(buffer), 
                                                  goodbye_records[i], nullptr, 0, nullptr, 0);
                if (result < 0) {
                    Logger::instance().warn("MdnsManager", "Failed to send goodbye packet: " + std::to_string(result));
                } else {
                    Logger::instance().debug("MdnsManager", "Sent goodbye packet for record type: " + 
                                std::to_string(goodbye_records[i].type));
                }
            }
        }
    }
    
    is_publishing_ = false;
    Logger::instance().info("MdnsManager", "Stopped publishing service and sent goodbye packets");
}

bool MdnsManager::start_discovery(PeerDiscoveredCallback on_discovered, PeerLostCallback on_lost) {
    std::lock_guard<std::mutex> lock(discovery_mutex_);
    
    if (is_discovering_.load()) {
        Logger::instance().warn("MdnsManager", "Discovery already running");
        return false;
    }
    
    peer_discovered_callback_ = on_discovered;
    peer_lost_callback_ = on_lost;
    
    if (!initialize_sockets()) {
        Logger::instance().error("MdnsManager", "Failed to initialize sockets for discovery");
        return false;
    }
    
    // Start network thread if not already running
    if (!network_thread_.joinable()) {
        should_stop_ = false;
        network_thread_ = std::thread(&MdnsManager::network_thread_main, this);
    }
    
    is_discovering_ = true;
    thread_cv_.notify_all();
    
    Logger::instance().info("MdnsManager", "Started service discovery");
    return true;
}

void MdnsManager::stop_discovery() {
    if (!is_discovering_.load()) {
        return;
    }
    
    is_discovering_ = false;
    
    // Clear discovered peers
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        discovered_peers_.clear();
    }
    
    Logger::instance().info("MdnsManager", "Stopped service discovery");
}

bool MdnsManager::is_publishing() const {
    return is_publishing_.load();
}

bool MdnsManager::is_discovering() const {
    return is_discovering_.load();
}

std::map<std::string, PeerInfo> MdnsManager::get_discovered_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::map<std::string, PeerInfo> result;
    for (const auto& [device_id, discovered_peer] : discovered_peers_) {
        result[device_id] = discovered_peer.info;
    }
    return result;
}

std::string MdnsManager::get_debug_info() const {
    std::ostringstream debug_info;
    
    debug_info << "MdnsManager Debug Information:\n";
    debug_info << "  Publishing: " << (is_publishing_.load() ? "Yes" : "No") << "\n";
    debug_info << "  Discovering: " << (is_discovering_.load() ? "Yes" : "No") << "\n";
    debug_info << "  Network Thread Running: " << (network_thread_.joinable() && !should_stop_.load() ? "Yes" : "No") << "\n";
    
    // Socket information
    {
        std::lock_guard<std::mutex> lock(sockets_mutex_);
        debug_info << "  Active Sockets: " << sockets_.size() << "\n";
        for (size_t i = 0; i < sockets_.size(); ++i) {
            debug_info << "    Socket " << i << ": " << sockets_[i] << "\n";
        }
    }
    
    // Service information
    if (is_publishing_.load()) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        debug_info << "  Published Service:\n";
        debug_info << "    Device ID: " << service_info_.device_id << "\n";
        debug_info << "    Port: " << service_info_.port << "\n";
        debug_info << "    Fingerprint: " << service_info_.fingerprint.substr(0, 16) << "...\n";
    }
    
    // Discovered peers
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        debug_info << "  Discovered Peers: " << discovered_peers_.size() << "\n";
        for (const auto& [device_id, discovered_peer] : discovered_peers_) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - discovered_peer.last_seen);
            debug_info << "    " << device_id << " (" << discovered_peer.info.name 
                      << ") - Last seen: " << age.count() << "s ago\n";
        }
    }
    
    // Network interfaces
    debug_info << "  Local Hostname: " << get_local_hostname() << "\n";
    auto addresses = get_local_addresses();
    debug_info << "  Local Addresses: " << addresses.size() << "\n";
    for (const auto& addr : addresses) {
        debug_info << "    " << addr << "\n";
    }
    
    return debug_info.str();
}

void MdnsManager::network_thread_main() {
    Logger::instance().info("MdnsManager", "mDNS network thread started");
    
    const auto query_interval = std::chrono::seconds(5);
    const auto timeout_check_interval = std::chrono::seconds(10);
    auto last_query_time = std::chrono::steady_clock::now();
    auto last_timeout_check = std::chrono::steady_clock::now();
    
    while (!should_stop_.load()) {
        auto now = std::chrono::steady_clock::now();
        
        // Send discovery queries periodically
        if (is_discovering_.load() && (now - last_query_time) >= query_interval) {
            send_discovery_query();
            last_query_time = now;
        }
        
        // Check for peer timeouts
        if (is_discovering_.load() && (now - last_timeout_check) >= timeout_check_interval) {
            process_peer_timeout();
            last_timeout_check = now;
        }
        
        // Listen for incoming mDNS packets
        {
            std::lock_guard<std::mutex> lock(sockets_mutex_);
            for (int sock : sockets_) {
                fd_set readfs;
                FD_ZERO(&readfs);
                FD_SET(sock, &readfs);
                
                struct timeval timeout;
                timeout.tv_sec = 0;
                timeout.tv_usec = 100000; // 100ms
                
                if (select(sock + 1, &readfs, nullptr, nullptr, &timeout) > 0) {
                    if (FD_ISSET(sock, &readfs)) {
                        char buffer[2048];
                        struct sockaddr_storage from_addr;
                        socklen_t from_len = sizeof(from_addr);
                        
                        ssize_t bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                               (struct sockaddr*)&from_addr, &from_len);
                        
                        if (bytes > 0) {
                            if (is_publishing_.load()) {
                                handle_mdns_query(sock, (struct sockaddr*)&from_addr, from_len,
                                                 buffer, static_cast<size_t>(bytes));
                            }
                            
                            if (is_discovering_.load()) {
                                handle_mdns_response(buffer, static_cast<size_t>(bytes),
                                                   (struct sockaddr*)&from_addr, from_len);
                            }
                        }
                    }
                }
            }
        }
        
        // Wait for notification or timeout
        std::unique_lock<std::mutex> lock(thread_mutex_);
        thread_cv_.wait_for(lock, std::chrono::milliseconds(100));
    }
    
    Logger::instance().info("MdnsManager", "mDNS network thread stopped");
}

bool MdnsManager::initialize_sockets() {
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    
    if (!sockets_.empty()) {
        return true; // Already initialized
    }
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Logger::instance().error("MdnsManager", "Failed to initialize Winsock");
        return false;
    }
#endif
    
    // Create IPv4 socket
    int ipv4_sock = mdns_socket_open_ipv4(nullptr);
    if (ipv4_sock >= 0) {
        sockets_.push_back(ipv4_sock);
        Logger::instance().debug("MdnsManager", "Opened IPv4 mDNS socket: " + std::to_string(ipv4_sock));
    } else {
        Logger::instance().error("MdnsManager", "Failed to open IPv4 mDNS socket");
    }
    
    // Create IPv6 socket
    int ipv6_sock = mdns_socket_open_ipv6(nullptr);
    if (ipv6_sock >= 0) {
        sockets_.push_back(ipv6_sock);
        Logger::instance().debug("MdnsManager", "Opened IPv6 mDNS socket: " + std::to_string(ipv6_sock));
    } else {
        Logger::instance().warn("MdnsManager", "Failed to open IPv6 mDNS socket (this may be normal)");
    }
    
    if (sockets_.empty()) {
        Logger::instance().error("MdnsManager", "Failed to open any mDNS sockets");
        return false;
    }
    
    return true;
}

void MdnsManager::cleanup_sockets() {
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    
    for (int sock : sockets_) {
        mdns_socket_close(sock);
        Logger::instance().debug("MdnsManager", "Closed mDNS socket: " + std::to_string(sock));
    }
    sockets_.clear();
    
#ifdef _WIN32
    WSACleanup();
#endif
}

void MdnsManager::handle_mdns_query(int sock, const struct sockaddr* from, size_t addrlen,
                                    const void* buffer, size_t size) {
    // Parse mDNS packet header and records directly from buffer
    if (size < 12) { // mDNS header is 12 bytes
        return;
    }
    
    const uint16_t* data = static_cast<const uint16_t*>(buffer);
    uint16_t query_id = ntohs(data[0]);
    uint16_t flags = ntohs(data[1]);
    uint16_t questions = ntohs(data[2]);
    uint16_t answer_rrs = ntohs(data[3]);
    uint16_t authority_rrs = ntohs(data[4]);
    uint16_t additional_rrs = ntohs(data[5]);
    
    // Start parsing after the header
    size_t offset = 12;
    
    // Parse questions (we handle these as before)
    for (uint16_t i = 0; i < questions && offset < size; ++i) {
        size_t question_offset = offset;
        // Skip question name
        if (mdns_string_skip(buffer, size, &offset) < 0) break;
        if (offset + 4 > size) break;
        
        const uint16_t* question_data = reinterpret_cast<const uint16_t*>(static_cast<const char*>(buffer) + offset);
        uint16_t rtype = ntohs(question_data[0]);
        uint16_t rclass = ntohs(question_data[1]);
        offset += 4;
        
        size_t name_length = offset - question_offset - 4;
        query_callback(sock, from, addrlen, MDNS_ENTRYTYPE_QUESTION, query_id,
                      rtype, rclass, 0, buffer, size, question_offset, name_length,
                      question_offset, name_length, this);
    }
    
    // Parse answer records
    for (uint16_t i = 0; i < answer_rrs && offset < size; ++i) {
        size_t name_offset = offset;
        if (mdns_string_skip(buffer, size, &offset) < 0) break;
        if (offset + 10 > size) break;
        
        size_t name_length = offset - name_offset;
        const uint16_t* record_data = reinterpret_cast<const uint16_t*>(static_cast<const char*>(buffer) + offset);
        uint16_t rtype = ntohs(record_data[0]);
        uint16_t rclass = ntohs(record_data[1]);
        uint32_t ttl = (static_cast<uint32_t>(ntohs(record_data[2])) << 16) | ntohs(record_data[3]);
        uint16_t record_length = ntohs(record_data[4]);
        offset += 10;
        
        size_t record_offset = offset;
        if (offset + record_length > size) break;
        offset += record_length;
        
        query_callback(sock, from, addrlen, MDNS_ENTRYTYPE_ANSWER, query_id,
                      rtype, rclass, ttl, buffer, size, name_offset, name_length,
                      record_offset, record_length, this);
    }
    
    // Parse authority records  
    for (uint16_t i = 0; i < authority_rrs && offset < size; ++i) {
        size_t name_offset = offset;
        if (mdns_string_skip(buffer, size, &offset) < 0) break;
        if (offset + 10 > size) break;
        
        size_t name_length = offset - name_offset;
        const uint16_t* record_data = reinterpret_cast<const uint16_t*>(static_cast<const char*>(buffer) + offset);
        uint16_t rtype = ntohs(record_data[0]);
        uint16_t rclass = ntohs(record_data[1]);
        uint32_t ttl = (static_cast<uint32_t>(ntohs(record_data[2])) << 16) | ntohs(record_data[3]);
        uint16_t record_length = ntohs(record_data[4]);
        offset += 10;
        
        size_t record_offset = offset;
        if (offset + record_length > size) break;
        offset += record_length;
        
        query_callback(sock, from, addrlen, MDNS_ENTRYTYPE_AUTHORITY, query_id,
                      rtype, rclass, ttl, buffer, size, name_offset, name_length,
                      record_offset, record_length, this);
    }
    
    // Parse additional records
    for (uint16_t i = 0; i < additional_rrs && offset < size; ++i) {
        size_t name_offset = offset;
        if (mdns_string_skip(buffer, size, &offset) < 0) break;
        if (offset + 10 > size) break;
        
        size_t name_length = offset - name_offset;
        const uint16_t* record_data = reinterpret_cast<const uint16_t*>(static_cast<const char*>(buffer) + offset);
        uint16_t rtype = ntohs(record_data[0]);
        uint16_t rclass = ntohs(record_data[1]);
        uint32_t ttl = (static_cast<uint32_t>(ntohs(record_data[2])) << 16) | ntohs(record_data[3]);
        uint16_t record_length = ntohs(record_data[4]);
        offset += 10;
        
        size_t record_offset = offset;
        if (offset + record_length > size) break;
        offset += record_length;
        
        query_callback(sock, from, addrlen, MDNS_ENTRYTYPE_ADDITIONAL, query_id,
                      rtype, rclass, ttl, buffer, size, name_offset, name_length,
                      record_offset, record_length, this);
    }
}

void MdnsManager::send_discovery_query() {
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    
    for (int sock : sockets_) {
        const char* service_name = "_warpdeck._tcp.local.";
        char buffer[256];
        mdns_query_send(sock, MDNS_RECORDTYPE_PTR, service_name, strlen(service_name), 
                       buffer, sizeof(buffer), 0);
    }
    
    Logger::instance().debug("MdnsManager", "Sent discovery query for _warpdeck._tcp.local.");
}

void MdnsManager::handle_mdns_response(const void* buffer, size_t size,
                                      const struct sockaddr* from, size_t addrlen) {
    if (!is_discovering_.load()) {
        return;
    }
    
    Logger::instance().debug("MdnsManager", "Received mDNS response from " + sockaddr_to_string(from) + " size: " + std::to_string(size));
    
    // For now, we'll implement a basic response handler that looks for _warpdeck._tcp services
    // This is a simplified implementation that will be enhanced later
    
    // Simple check for our service type in the response
    std::string response_str(static_cast<const char*>(buffer), size);
    if (response_str.find("_warpdeck._tcp") != std::string::npos) {
        Logger::instance().info("MdnsManager", "Detected _warpdeck._tcp service in response from " + sockaddr_to_string(from));
        
        // For now, create a minimal peer entry
        // This will be properly implemented when we have more complete mDNS parsing
        PeerInfo peer_info;
        peer_info.id = "unknown-" + sockaddr_to_string(from);
        peer_info.name = peer_info.id;
        peer_info.platform = "unknown";
        peer_info.host_address = sockaddr_to_string(from);
        peer_info.port = 8080; // Default port
        peer_info.fingerprint = "unknown";
        
        // Update discovered peers map
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            
            auto now = std::chrono::steady_clock::now();
            auto it = discovered_peers_.find(peer_info.id);
            
            if (it == discovered_peers_.end()) {
                // New peer discovered
                DiscoveredPeer discovered_peer;
                discovered_peer.info = peer_info;
                discovered_peer.last_seen = now;
                discovered_peer.ttl = 300; // 5 minutes default TTL
                
                discovered_peers_[peer_info.id] = discovered_peer;
                
                // Notify callback
                if (peer_discovered_callback_) {
                    peer_discovered_callback_(peer_info);
                }
                
                Logger::instance().info("MdnsManager", "Discovered new peer: " + peer_info.id);
            } else {
                // Update existing peer
                it->second.last_seen = now;
                Logger::instance().debug("MdnsManager", "Updated existing peer: " + peer_info.id);
            }
        }
    }
}

void MdnsManager::process_mdns_response(int sock, const struct sockaddr* from, size_t addrlen,
                                       mdns_entry_type_t entry, uint16_t rtype, uint32_t ttl,
                                       const void* data, size_t size, size_t name_offset,
                                       size_t name_length, size_t record_offset, size_t record_length) {
    // Parse mDNS responses to extract peer information
    static std::map<std::string, PeerInfo> pending_peers; // Track partial peer information
    static std::mutex pending_peers_mutex;
    
    std::string sender_address = sockaddr_to_string(from);
    PeerInfo peer_info;
    bool peer_complete = false;
    
    try {
        char name_buffer[256];
        mdns_string_t record_name = mdns_string_extract(data, size, &name_offset,
                                                       name_buffer, sizeof(name_buffer));
        std::string name_str(record_name.str, record_name.length);
        
        Logger::instance().debug("MdnsManager", "Processing " + std::to_string(rtype) + " record: " + name_str);
        
        // Initialize peer info with sender address
        peer_info.host_address = sender_address;
        peer_info.platform = "unknown";
        
        if (rtype == MDNS_RECORDTYPE_PTR) {
            // PTR record: extract service instance name
            char ptr_buffer[256];
            mdns_string_t ptr_name = mdns_string_extract(data, size, &record_offset,
                                                        ptr_buffer, sizeof(ptr_buffer));
            std::string instance_name(ptr_name.str, ptr_name.length);
            
            // Extract device ID from instance name (format: deviceid._warpdeck._tcp.local.)
            size_t dot_pos = instance_name.find('.');
            if (dot_pos != std::string::npos) {
                peer_info.id = instance_name.substr(0, dot_pos);
                peer_info.name = peer_info.id; // Default name to ID
                Logger::instance().debug("MdnsManager", "Found peer ID from PTR: " + peer_info.id);
            }
        }
        else if (rtype == MDNS_RECORDTYPE_SRV) {
            // SRV record: extract port and hostname
            if (record_length >= 6) {
                const uint8_t* srv_data = static_cast<const uint8_t*>(data) + record_offset;
                uint16_t priority = (srv_data[0] << 8) | srv_data[1];
                uint16_t weight = (srv_data[2] << 8) | srv_data[3];
                uint16_t port = (srv_data[4] << 8) | srv_data[5];
                
                peer_info.port = port;
                
                // Extract device ID from record name
                size_t dot_pos = name_str.find('.');
                if (dot_pos != std::string::npos) {
                    peer_info.id = name_str.substr(0, dot_pos);
                }
                
                Logger::instance().debug("MdnsManager", "Found peer port from SRV: " + std::to_string(port));
            }
        }
        else if (rtype == MDNS_RECORDTYPE_TXT) {
            // TXT record: extract device metadata
            if (record_length > 0) {
                const uint8_t* txt_data = static_cast<const uint8_t*>(data) + record_offset;
                size_t offset = 0;
                
                while (offset < record_length) {
                    uint8_t len = txt_data[offset++];
                    if (len == 0 || offset + len > record_length) break;
                    
                    std::string txt_entry(reinterpret_cast<const char*>(&txt_data[offset]), len);
                    offset += len;
                    
                    size_t eq_pos = txt_entry.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string key = txt_entry.substr(0, eq_pos);
                        std::string value = txt_entry.substr(eq_pos + 1);
                        
                        if (key == "deviceid") {
                            peer_info.id = value;
                        } else if (key == "fingerprint") {
                            peer_info.fingerprint = value;
                        } else if (key == "name") {
                            peer_info.name = value;
                        } else if (key == "platform") {
                            peer_info.platform = value;
                        }
                    }
                }
                
                // Extract device ID from record name if not found in TXT
                if (peer_info.id.empty()) {
                    size_t dot_pos = name_str.find('.');
                    if (dot_pos != std::string::npos) {
                        peer_info.id = name_str.substr(0, dot_pos);
                    }
                }
                
                Logger::instance().debug("MdnsManager", "Found peer metadata from TXT for: " + peer_info.id);
            }
        }
        
        // Merge with existing pending peer info
        {
            std::lock_guard<std::mutex> lock(pending_peers_mutex);
            
            std::string key = peer_info.id.empty() ? sender_address : peer_info.id;
            auto it = pending_peers.find(key);
            
            if (it != pending_peers.end()) {
                // Merge information
                PeerInfo& existing = it->second;
                if (!peer_info.id.empty()) existing.id = peer_info.id;
                if (!peer_info.name.empty() && peer_info.name != peer_info.id) existing.name = peer_info.name;
                if (!peer_info.platform.empty() && peer_info.platform != "unknown") existing.platform = peer_info.platform;
                if (!peer_info.fingerprint.empty()) existing.fingerprint = peer_info.fingerprint;
                if (peer_info.port != 0) existing.port = peer_info.port;
                if (!peer_info.host_address.empty()) existing.host_address = peer_info.host_address;
                
                peer_info = existing;
            } else {
                // Set defaults for missing fields
                if (peer_info.id.empty()) peer_info.id = "peer-" + sender_address;
                if (peer_info.name.empty()) peer_info.name = peer_info.id;
                if (peer_info.port == 0) peer_info.port = 54321; // Default WarpDeck port
                if (peer_info.fingerprint.empty()) peer_info.fingerprint = "unknown";
                
                pending_peers[key] = peer_info;
            }
            
            // Check if we have enough information to consider the peer complete
            if (!peer_info.id.empty() && peer_info.port != 0 && !peer_info.host_address.empty()) {
                peer_complete = true;
                pending_peers.erase(key); // Remove from pending
            }
        }
        
        // If peer info is complete, add to discovered peers
        if (peer_complete) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            
            auto now = std::chrono::steady_clock::now();
            auto it = discovered_peers_.find(peer_info.id);
            
            if (it == discovered_peers_.end()) {
                // New peer discovered
                DiscoveredPeer discovered_peer;
                discovered_peer.info = peer_info;
                discovered_peer.last_seen = now;
                discovered_peer.ttl = ttl > 0 ? ttl : 300; // Use TTL from record or default to 5 minutes
                
                discovered_peers_[peer_info.id] = discovered_peer;
                
                // Notify callback
                if (peer_discovered_callback_) {
                    peer_discovered_callback_(peer_info);
                }
                
                Logger::instance().info("MdnsManager", "Discovered new peer: " + peer_info.id + 
                                       " (" + peer_info.name + ") at " + peer_info.host_address + ":" + std::to_string(peer_info.port));
            } else {
                // Update existing peer
                it->second.last_seen = now;
                it->second.info = peer_info; // Update with latest info
                Logger::instance().debug("MdnsManager", "Updated existing peer: " + peer_info.id);
            }
        }
        
    } catch (const std::exception& e) {
        Logger::instance().error("MdnsManager", "Error processing mDNS response: " + std::string(e.what()));
    }
}

void MdnsManager::process_peer_timeout() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> expired_peers;
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        
        for (auto it = discovered_peers_.begin(); it != discovered_peers_.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen);
            if (age.count() > it->second.ttl) {
                expired_peers.push_back(it->first);
                it = discovered_peers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Notify callbacks about lost peers
    if (peer_lost_callback_) {
        for (const auto& device_id : expired_peers) {
            peer_lost_callback_(device_id);
            Logger::instance().info("MdnsManager", "Peer expired: " + device_id);
        }
    }
}

std::string MdnsManager::sockaddr_to_string(const struct sockaddr* addr) {
    char str[INET6_ADDRSTRLEN];
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, str, INET_ADDRSTRLEN);
        return std::string(str) + ":" + std::to_string(ntohs(addr_in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* addr_in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, str, INET6_ADDRSTRLEN);
        return std::string("[") + str + "]:" + std::to_string(ntohs(addr_in6->sin6_port));
    }
    
    return "unknown";
}

int MdnsManager::query_callback(int sock, const struct sockaddr* from, size_t addrlen,
                               mdns_entry_type_t entry, uint16_t query_id,
                               uint16_t rtype, uint16_t rclass, uint32_t ttl,
                               const void* data, size_t size, size_t name_offset,
                               size_t name_length, size_t record_offset,
                               size_t record_length, void* user_data) {
    MdnsManager* manager = static_cast<MdnsManager*>(user_data);
    
    if (entry == MDNS_ENTRYTYPE_QUESTION && rtype == MDNS_RECORDTYPE_PTR) {
        // Extract the query name to check if it's for our service
        char name_buffer[256];
        mdns_string_t name = mdns_string_extract(data, size, &name_offset,
                                                name_buffer, sizeof(name_buffer));
        
        std::string query_name(name.str, name.length);
        if (query_name.find("_warpdeck._tcp") != std::string::npos) {
            Logger::instance().debug("MdnsManager", "Received PTR query for _warpdeck._tcp service");
            manager->send_service_response(sock, from, addrlen, query_name, rtype);
        }
    }
    else if (entry == MDNS_ENTRYTYPE_ANSWER || entry == MDNS_ENTRYTYPE_ADDITIONAL) {
        // Handle answers and additional records from other WarpDeck devices
        char name_buffer[256];
        mdns_string_t name = mdns_string_extract(data, size, &name_offset,
                                                name_buffer, sizeof(name_buffer));
        
        std::string record_name(name.str, name.length);
        if (record_name.find("_warpdeck._tcp") != std::string::npos) {
            Logger::instance().debug("MdnsManager", "Received mDNS response for _warpdeck._tcp service from " + 
                                   manager->sockaddr_to_string(from));
            manager->process_mdns_response(sock, from, addrlen, entry, rtype, ttl, data, size, 
                                         name_offset, name_length, record_offset, record_length);
        }
    }
    
    return 0;
}

void MdnsManager::send_service_response(int sock, const struct sockaddr* to, size_t addrlen,
                                       const std::string& query_name, uint16_t query_type) {
    std::lock_guard<std::mutex> lock(service_mutex_);
    
    if (!is_publishing_.load()) {
        return;
    }
    
    char buffer[2048];
    std::string hostname = get_local_hostname();
    std::string service_instance = service_info_.device_id + "._warpdeck._tcp.local.";
    std::string service_type = "_warpdeck._tcp.local.";
    std::string target_host = hostname + ".local.";
    
    // Create TXT record data
    std::vector<std::string> txt_entries;
    txt_entries.push_back("deviceid=" + service_info_.device_id);
    txt_entries.push_back("fingerprint=" + service_info_.fingerprint);
    
    // Prepare TXT record data
    std::string txt_data;
    for (const auto& entry : txt_entries) {
        txt_data += static_cast<char>(entry.length());
        txt_data += entry;
    }
    
    // Prepare the answer records
    mdns_record_t answer;
    mdns_record_t additional[3];  // SRV, TXT, A/AAAA records
    size_t additional_count = 0;
    
    if (query_type == MDNS_RECORDTYPE_PTR) {
        // PTR record response
        answer.name.str = service_type.c_str();
        answer.name.length = service_type.length();
        answer.type = MDNS_RECORDTYPE_PTR;
        answer.data.ptr.name.str = service_instance.c_str();
        answer.data.ptr.name.length = service_instance.length();
        
        // Add SRV record
        additional[additional_count].name.str = service_instance.c_str();
        additional[additional_count].name.length = service_instance.length();
        additional[additional_count].type = MDNS_RECORDTYPE_SRV;
        additional[additional_count].data.srv.priority = 0;
        additional[additional_count].data.srv.weight = 0;
        additional[additional_count].data.srv.port = service_info_.port;
        additional[additional_count].data.srv.name.str = target_host.c_str();
        additional[additional_count].data.srv.name.length = target_host.length();
        additional_count++;
        
        // Add TXT record - simplified for now
        additional[additional_count].name.str = service_instance.c_str();
        additional[additional_count].name.length = service_instance.length();
        additional[additional_count].type = MDNS_RECORDTYPE_TXT;
        additional[additional_count].data.txt.key.str = "deviceid";
        additional[additional_count].data.txt.key.length = 8;
        additional[additional_count].data.txt.value.str = service_info_.device_id.c_str();
        additional[additional_count].data.txt.value.length = service_info_.device_id.length();
        additional_count++;
        
        // Add A record for IPv4 addresses
        std::vector<std::string> addresses = get_local_addresses();
        for (const auto& addr : addresses) {
            if (additional_count >= 3) break; // Limit to prevent buffer overflow
            
            struct sockaddr_in addr_in;
            if (inet_pton(AF_INET, addr.c_str(), &addr_in.sin_addr) == 1) {
                additional[additional_count].name.str = target_host.c_str();
                additional[additional_count].name.length = target_host.length();
                additional[additional_count].type = MDNS_RECORDTYPE_A;
                additional[additional_count].data.a.addr = addr_in;
                additional_count++;
                break; // Only add one A record for now
            }
        }
        
        Logger::instance().debug("MdnsManager", "Sending PTR response for service: " + service_instance);
    } else if (query_type == MDNS_RECORDTYPE_SRV) {
        // SRV record response
        answer.name.str = service_instance.c_str();
        answer.name.length = service_instance.length();
        answer.type = MDNS_RECORDTYPE_SRV;
        answer.data.srv.priority = 0;
        answer.data.srv.weight = 0;
        answer.data.srv.port = service_info_.port;
        answer.data.srv.name.str = target_host.c_str();
        answer.data.srv.name.length = target_host.length();
        
        Logger::instance().debug("MdnsManager", "Sending SRV response for service: " + service_instance);
    } else if (query_type == MDNS_RECORDTYPE_TXT) {
        // TXT record response - simplified
        answer.name.str = service_instance.c_str();
        answer.name.length = service_instance.length();
        answer.type = MDNS_RECORDTYPE_TXT;
        answer.data.txt.key.str = "deviceid";
        answer.data.txt.key.length = 8;
        answer.data.txt.value.str = service_info_.device_id.c_str();
        answer.data.txt.value.length = service_info_.device_id.length();
        
        Logger::instance().debug("MdnsManager", "Sending TXT response for service: " + service_instance);
    } else {
        return; // Unsupported query type
    }
    
    // Send the response
    int result = mdns_query_answer_multicast(sock, buffer, sizeof(buffer), answer,
                                           nullptr, 0, additional, additional_count);
    
    if (result < 0) {
        Logger::instance().error("MdnsManager", "Failed to send mDNS response: " + std::to_string(result));
    } else {
        Logger::instance().debug("MdnsManager", "Successfully sent mDNS response");
    }
}

std::string MdnsManager::get_local_hostname() const {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "warpdeck-host";
}

std::vector<std::string> MdnsManager::get_local_addresses() const {
    std::vector<std::string> addresses;
    
#ifdef _WIN32
    // Windows implementation for getting local addresses
    ULONG buffer_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, 
                        nullptr, nullptr, &buffer_size);
    
    std::vector<char> buffer(buffer_size);
    PIP_ADAPTER_ADDRESSES adapter_addresses = (PIP_ADAPTER_ADDRESSES)buffer.data();
    
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                            nullptr, adapter_addresses, &buffer_size) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses; adapter; adapter = adapter->Next) {
            for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress; 
                 unicast; unicast = unicast->Next) {
                char addr_str[INET6_ADDRSTRLEN];
                int family = unicast->Address.lpSockaddr->sa_family;
                if (family == AF_INET) {
                    inet_ntop(AF_INET, &((struct sockaddr_in*)unicast->Address.lpSockaddr)->sin_addr,
                             addr_str, INET_ADDRSTRLEN);
                    addresses.push_back(addr_str);
                } else if (family == AF_INET6) {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6*)unicast->Address.lpSockaddr)->sin6_addr,
                             addr_str, INET6_ADDRSTRLEN);
                    addresses.push_back(addr_str);
                }
            }
        }
    }
#else
    // Unix implementation for getting local addresses
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs* ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            
            char addr_str[INET6_ADDRSTRLEN];
            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr,
                         addr_str, INET_ADDRSTRLEN);
                addresses.push_back(addr_str);
            } else if (family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr,
                         addr_str, INET6_ADDRSTRLEN);
                addresses.push_back(addr_str);
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
#endif
    
    return addresses;
}


} // namespace warpdeck
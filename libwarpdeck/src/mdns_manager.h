#pragma once

#include <string>
#include <map>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>

#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

extern "C" {
#include "mdns.h"
}

#include "discovery_manager.h"

namespace warpdeck {

class MdnsManager {
public:
    using PeerDiscoveredCallback = std::function<void(const PeerInfo&)>;
    using PeerLostCallback = std::function<void(const std::string& device_id)>;
    
    MdnsManager();
    ~MdnsManager();
    
    // Non-copyable
    MdnsManager(const MdnsManager&) = delete;
    MdnsManager& operator=(const MdnsManager&) = delete;
    
    // Publishing interface
    bool publish_service(const std::string& device_id, const std::string& fingerprint, int port);
    void stop_publishing();
    
    // Discovery interface
    bool start_discovery(PeerDiscoveredCallback on_discovered, PeerLostCallback on_lost);
    void stop_discovery();
    
    // Status queries
    bool is_publishing() const;
    bool is_discovering() const;
    
    // Debug information
    std::map<std::string, PeerInfo> get_discovered_peers() const;
    std::string get_debug_info() const;
    
private:
    struct ServiceInfo {
        std::string device_id;
        std::string fingerprint;
        int port;
    };
    
    
    struct DiscoveredPeer {
        PeerInfo info;
        std::chrono::steady_clock::time_point last_seen;
        uint32_t ttl;
    };
    
    // Threading
    std::thread network_thread_;
    std::atomic<bool> should_stop_;
    std::condition_variable thread_cv_;
    std::mutex thread_mutex_;
    
    // Publishing state
    std::atomic<bool> is_publishing_;
    ServiceInfo service_info_;
    mutable std::mutex service_mutex_;
    
    // Discovery state
    std::atomic<bool> is_discovering_;
    PeerDiscoveredCallback peer_discovered_callback_;
    PeerLostCallback peer_lost_callback_;
    std::mutex discovery_mutex_;
    
    // Peer tracking
    std::map<std::string, DiscoveredPeer> discovered_peers_;
    mutable std::mutex peers_mutex_;
    
    // Socket management
    std::vector<int> sockets_;
    mutable std::mutex sockets_mutex_;
    
    // Core methods
    void network_thread_main();
    bool initialize_sockets();
    void cleanup_sockets();
    
    // Publishing implementation
    void handle_mdns_query(int sock, const struct sockaddr* from, size_t addrlen, 
                          const void* buffer, size_t size);
    void send_service_response(int sock, const struct sockaddr* to, size_t addrlen,
                              const std::string& query_name, uint16_t query_type);
    
    // Discovery implementation
    void send_discovery_query();
    void handle_mdns_response(const void* buffer, size_t size, 
                             const struct sockaddr* from, size_t addrlen);
    void process_peer_timeout();
    
    // Utility methods
    std::string get_local_hostname() const;
    std::vector<std::string> get_local_addresses() const;
    static std::string sockaddr_to_string(const struct sockaddr* addr);
    
    // mDNS callback helpers
    static int query_callback(int sock, const struct sockaddr* from, size_t addrlen,
                             mdns_entry_type_t entry, uint16_t query_id,
                             uint16_t rtype, uint16_t rclass, uint32_t ttl,
                             const void* data, size_t size, size_t name_offset,
                             size_t name_length, size_t record_offset, 
                             size_t record_length, void* user_data);
    
    // Process mDNS responses to discover peers
    void process_mdns_response(int sock, const struct sockaddr* from, size_t addrlen,
                              mdns_entry_type_t entry, uint16_t rtype, uint32_t ttl,
                              const void* data, size_t size, size_t name_offset,
                              size_t name_length, size_t record_offset, size_t record_length);
    
};

} // namespace warpdeck
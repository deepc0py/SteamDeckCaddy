#include "discovery_manager.h"
#include "mdns_manager.h"
#include "utils.h"
#include "logger.h"
#include <thread>
#include <chrono>

namespace warpdeck {


DiscoveryManager::DiscoveryManager() : running_(false) {
    mdns_manager_ = std::make_unique<MdnsManager>();
}

DiscoveryManager::~DiscoveryManager() {
    stop();
}

bool DiscoveryManager::start(const std::string& device_name, const std::string& device_id,
                           const std::string& platform, int port, const std::string& fingerprint) {
    if (running_) {
        return false;
    }
    
    // Set debug logging for discovery components
    Logger::instance().set_log_level(LogLevel::DEBUG);
    
    device_name_ = device_name;
    device_id_ = device_id;
    platform_ = platform;
    port_ = port;
    fingerprint_ = fingerprint;
    
    // Start mDNS service publishing
    if (!mdns_manager_->publish_service(device_id, fingerprint, port)) {
        Logger::instance().error("DiscoveryManager", "Failed to start mDNS service publishing");
        return false;
    }
    
    // Start mDNS service discovery
    if (!mdns_manager_->start_discovery(
            [this](const PeerInfo& peer) { this->on_peer_discovered(peer); },
            [this](const std::string& device_id) { this->on_peer_lost(device_id); })) {
        Logger::instance().error("DiscoveryManager", "Failed to start mDNS service discovery");
        mdns_manager_->stop_publishing();
        return false;
    }
    
    running_ = true;
    discovery_thread_ = std::thread(&DiscoveryManager::discovery_thread_func, this);
    
    return true;
}


void DiscoveryManager::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (mdns_manager_) {
        mdns_manager_->stop_discovery();
        mdns_manager_->stop_publishing();
    }
    
    if (discovery_thread_.joinable()) {
        discovery_thread_.join();
    }
    
    std::lock_guard<std::mutex> lock(peers_mutex_);
    discovered_peers_.clear();
}

void DiscoveryManager::set_device_name(const std::string& name) {
    device_name_ = name;
    if (running_ && mdns_manager_) {
        // For MdnsManager, we need to restart publishing with new service info
        mdns_manager_->stop_publishing();
        mdns_manager_->publish_service(device_id_, fingerprint_, port_);
    }
}

std::map<std::string, PeerInfo> DiscoveryManager::get_discovered_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return discovered_peers_;
}

void DiscoveryManager::set_peer_discovered_callback(PeerDiscoveredCallback callback) {
    peer_discovered_callback_ = callback;
}

void DiscoveryManager::set_peer_lost_callback(PeerLostCallback callback) {
    peer_lost_callback_ = callback;
}

void DiscoveryManager::discovery_thread_func() {
    // This thread will handle periodic discovery updates
    // The actual mDNS discovery is handled by the platform-specific implementation
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Periodic cleanup of stale peers could be done here
        // For now, we rely on the platform-specific implementation to handle this
    }
}

void DiscoveryManager::update_service_registration() {
    if (mdns_manager_ && running_) {
        // For MdnsManager, we need to restart publishing with updated service info
        mdns_manager_->stop_publishing();
        mdns_manager_->publish_service(device_id_, fingerprint_, port_);
    }
}

void DiscoveryManager::on_peer_discovered(const PeerInfo& peer) {
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        discovered_peers_[peer.id] = peer;
    }
    
    if (peer_discovered_callback_) {
        peer_discovered_callback_(peer);
    }
    
    Logger::instance().info("DiscoveryManager", "Peer discovered: " + peer.id + " (" + peer.name + ")");
}

void DiscoveryManager::on_peer_lost(const std::string& device_id) {
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        discovered_peers_.erase(device_id);
    }
    
    if (peer_lost_callback_) {
        peer_lost_callback_(device_id);
    }
    
    Logger::instance().info("DiscoveryManager", "Peer lost: " + device_id);
}

} // namespace warpdeck
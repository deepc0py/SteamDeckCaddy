#include "warpdeck.h"
#include "discovery_manager.h"
#include "mdns_manager.h"
#include "api_server.h"
#include "api_client.h"
#include "security_manager.h"
#include "transfer_manager.h"
#include "utils.h"
#include "logger.h"
#include <memory>
#include <string>
#include <cstring>
#include <map>

using namespace warpdeck;

struct WarpDeckHandle {
    std::unique_ptr<DiscoveryManager> discovery_manager;
    std::unique_ptr<APIServer> api_server;
    std::unique_ptr<APIClient> api_client;
    std::unique_ptr<SecurityManager> security_manager;
    std::unique_ptr<TransferManager> transfer_manager;
    
    Callbacks callbacks;
    std::string device_id;
    std::string device_name;
    std::string config_dir;
    int current_port;
    bool started;
    
    WarpDeckHandle() : current_port(0), started(false) {}
};

// Helper function to safely call callbacks
template<typename Callback, typename... Args>
void safe_call_callback(Callback callback, Args... args) {
    if (callback) {
        try {
            callback(args...);
        } catch (...) {
            // Ignore callback exceptions to prevent them from propagating back to C++ core
        }
    }
}

// Helper function to copy string for C API
char* copy_string(const std::string& str) {
    char* result = new char[str.length() + 1];
    std::strcpy(result, str.c_str());
    return result;
}

extern "C" {

WarpDeckHandle* warpdeck_create(const Callbacks* callbacks, const char* config_dir) {
    if (!callbacks || !config_dir) {
        return nullptr;
    }
    
    try {
        auto handle = std::make_unique<WarpDeckHandle>();
        
        // Copy callbacks
        handle->callbacks = *callbacks;
        handle->config_dir = config_dir;
        handle->device_id = utils::generate_uuid();
        
        // Initialize managers
        handle->discovery_manager = std::make_unique<DiscoveryManager>();
        handle->api_server = std::make_unique<APIServer>();
        handle->api_client = std::make_unique<APIClient>();
        handle->security_manager = std::make_unique<SecurityManager>();
        handle->transfer_manager = std::make_unique<TransferManager>();
        
        // Initialize security manager
        if (!handle->security_manager->initialize(config_dir)) {
            return nullptr;
        }
        
        // Generate certificate if needed
        if (!handle->security_manager->generate_certificate_if_needed()) {
            return nullptr;
        }
        
        // Set up discovery manager callbacks
        handle->discovery_manager->set_peer_discovered_callback(
            [handle = handle.get()](const PeerInfo& peer) {
                LOG_CORE_INFO() << "Peer discovered: " << peer.name << " (ID: " << peer.id << ")";
                std::string json = utils::peer_info_to_json(peer);
                safe_call_callback(handle->callbacks.on_peer_discovered, json.c_str());
            });
            
        handle->discovery_manager->set_peer_lost_callback(
            [handle = handle.get()](const std::string& device_id) {
                LOG_CORE_INFO() << "Peer lost: " << device_id;
                safe_call_callback(handle->callbacks.on_peer_lost, device_id.c_str());
            });
        
        // Set up transfer manager callbacks
        handle->transfer_manager->set_progress_callback(
            [handle = handle.get()](const std::string& transfer_id, float progress, uint64_t bytes) {
                safe_call_callback(handle->callbacks.on_transfer_progress_update, 
                                 transfer_id.c_str(), progress, bytes);
            });
            
        handle->transfer_manager->set_completion_callback(
            [handle = handle.get()](const std::string& transfer_id, bool success, const std::string& error) {
                safe_call_callback(handle->callbacks.on_transfer_completed, 
                                 transfer_id.c_str(), success, error.empty() ? nullptr : error.c_str());
            });
            
        handle->transfer_manager->set_incoming_request_callback(
            [handle = handle.get()](const std::string& transfer_id, const std::string& peer_name, 
                                   const std::vector<FileMetadata>& files) {
                // Create JSON for the transfer request
                TransferRequest request;
                request.files = files;
                std::string json = utils::transfer_request_to_json(request);
                safe_call_callback(handle->callbacks.on_incoming_transfer_request, json.c_str());
            });
        
        // Set up API server callbacks
        handle->api_server->set_transfer_request_callback(
            [handle = handle.get()](const std::string& client_fingerprint, 
                                   const TransferRequest& request,
                                   std::function<void(bool, const std::string&)> response_callback) {
                // Check if peer is trusted
                bool is_trusted = false;
                for (const auto& file : request.files) {
                    // For simplicity, we'll determine peer info from the first request
                    // In a real implementation, we'd extract this from the TLS session
                    break;
                }
                
                // Handle the incoming request through transfer manager
                std::string transfer_id = handle->transfer_manager->handle_incoming_request(
                    "unknown_peer", "Unknown Peer", request);
                
                if (!is_trusted) {
                    // Will trigger the incoming request callback to UI
                    response_callback(false, ""); // Will be handled by respond_to_transfer
                } else {
                    response_callback(true, transfer_id);
                }
            });
            
        handle->api_server->set_file_upload_callback(
            [handle = handle.get()](const std::string& transfer_id, int file_index, 
                                   const std::string& data,
                                   std::function<void(bool, const std::string&)> response_callback) {
                std::vector<uint8_t> file_data(data.begin(), data.end());
                bool success = handle->transfer_manager->handle_file_upload(transfer_id, file_index, file_data);
                response_callback(success, success ? "" : "Failed to write file");
            });
        
        return handle.release();
        
    } catch (const std::exception& e) {
        return nullptr;
    }
}

void warpdeck_destroy(WarpDeckHandle* handle) {
    if (handle) {
        if (handle->started) {
            warpdeck_stop(handle);
        }
        delete handle;
    }
}

int warpdeck_start(WarpDeckHandle* handle, const char* device_name, int desired_port) {
    if (!handle || !device_name) {
        return -1;
    }
    
    try {
        handle->device_name = device_name;
        
        // Set up SSL certificates for API server and client
        std::string cert_file = handle->security_manager->get_certificate_file_path();
        std::string key_file = handle->security_manager->get_private_key_file_path();
        
        handle->api_server->set_ssl_certificate(cert_file, key_file);
        handle->api_client->set_client_certificate(cert_file, key_file);
        
        // Start API server
        DeviceInfo device_info;
        device_info.id = handle->device_id;
        device_info.name = device_name;
        device_info.platform = utils::get_platform_name();
        device_info.protocol_version = "1.0";
        
        LOG_CORE_INFO() << "Starting API server on port " << desired_port;
        if (!handle->api_server->start(desired_port, device_info)) {
            LOG_CORE_ERROR() << "API server failed to start on port " << desired_port;
            return -1;
        }
        
        handle->current_port = handle->api_server->get_port();
        LOG_CORE_INFO() << "API server started successfully on port " << handle->current_port;
        
        // Start discovery manager
        LOG_CORE_DEBUG() << "Getting certificate fingerprint for discovery";
        std::string fingerprint = handle->security_manager->get_certificate_fingerprint();
        LOG_CORE_DEBUG() << "Certificate fingerprint: " << fingerprint.substr(0, 16) << "...";
        
        LOG_CORE_INFO() << "Starting discovery manager for device: " << device_name;
        if (!handle->discovery_manager->start(device_name, handle->device_id, 
                                            device_info.platform, handle->current_port, fingerprint)) {
            LOG_CORE_ERROR() << "Discovery manager failed to start";
            handle->api_server->stop();
            return -1;
        }
        LOG_CORE_INFO() << "Discovery manager started successfully";
        
        handle->started = true;
        return handle->current_port;
        
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
        return -1;
    }
}

void warpdeck_stop(WarpDeckHandle* handle) {
    if (!handle || !handle->started) {
        return;
    }
    
    try {
        handle->discovery_manager->stop();
        handle->api_server->stop();
        handle->started = false;
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

void warpdeck_set_device_name(WarpDeckHandle* handle, const char* new_name) {
    if (!handle || !new_name) {
        return;
    }
    
    try {
        handle->device_name = new_name;
        if (handle->started) {
            handle->discovery_manager->set_device_name(new_name);
        }
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

void warpdeck_initiate_transfer(WarpDeckHandle* handle, const char* device_id, const char* files_json) {
    if (!handle || !device_id || !files_json) {
        return;
    }
    
    try {
        // Parse files JSON to get file paths
        // For now, assume files_json is a simple array of file paths
        // In a full implementation, this would parse the FileMetadata JSON
        std::vector<std::string> file_paths = {files_json}; // Simplified
        
        // Get peer info
        auto peers = handle->discovery_manager->get_discovered_peers();
        auto peer_it = peers.find(device_id);
        if (peer_it == peers.end()) {
            safe_call_callback(handle->callbacks.on_error, "Peer not found");
            return;
        }
        
        const PeerInfo& peer = peer_it->second;
        
        // Initiate transfer through transfer manager
        std::string transfer_id = handle->transfer_manager->initiate_transfer(
            device_id, peer.name, file_paths);
            
        if (transfer_id.empty()) {
            safe_call_callback(handle->callbacks.on_error, "Failed to initiate transfer");
        }
        
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

void warpdeck_respond_to_transfer(WarpDeckHandle* handle, const char* transfer_id, bool accept) {
    if (!handle || !transfer_id) {
        return;
    }
    
    try {
        handle->transfer_manager->respond_to_transfer(transfer_id, accept);
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

void warpdeck_cancel_transfer(WarpDeckHandle* handle, const char* transfer_id) {
    if (!handle || !transfer_id) {
        return;
    }
    
    try {
        handle->transfer_manager->cancel_transfer(transfer_id);
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

const char* warpdeck_get_trusted_devices(WarpDeckHandle* handle) {
    if (!handle) {
        return nullptr;
    }
    
    try {
        auto trusted_peers = handle->security_manager->get_trusted_peers();
        std::string json = utils::trusted_peers_to_json(trusted_peers);
        return copy_string(json);
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
        return nullptr;
    }
}

void warpdeck_remove_trusted_device(WarpDeckHandle* handle, const char* device_id) {
    if (!handle || !device_id) {
        return;
    }
    
    try {
        handle->security_manager->remove_trusted_peer(device_id);
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
    }
}

const char* warpdeck_get_discovery_status(WarpDeckHandle* handle) {
    if (!handle || !handle->discovery_manager) {
        return nullptr;
    }
    
    try {
        const MdnsManager* mdns_manager = handle->discovery_manager->get_mdns_manager();
        if (!mdns_manager) {
            return copy_string("{\"error\": \"MdnsManager not available\"}");
        }
        
        std::ostringstream status_json;
        status_json << "{"
                   << "\"publishing\": " << (mdns_manager->is_publishing() ? "true" : "false") << ","
                   << "\"discovering\": " << (mdns_manager->is_discovering() ? "true" : "false") << ","
                   << "\"started\": " << (handle->started ? "true" : "false") << ","
                   << "\"device_id\": \"" << handle->device_id << "\","
                   << "\"device_name\": \"" << handle->device_name << "\","
                   << "\"current_port\": " << handle->current_port
                   << "}";
        
        return copy_string(status_json.str());
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
        return nullptr;
    }
}

const char* warpdeck_get_discovered_peers(WarpDeckHandle* handle) {
    if (!handle || !handle->discovery_manager) {
        return nullptr;
    }
    
    try {
        auto peers = handle->discovery_manager->get_discovered_peers();
        
        std::ostringstream peers_json;
        peers_json << "{"
                  << "\"peer_count\": " << peers.size() << ","
                  << "\"peers\": [";
        
        bool first = true;
        for (const auto& [device_id, peer] : peers) {
            if (!first) peers_json << ",";
            first = false;
            
            peers_json << "{"
                      << "\"id\": \"" << peer.id << "\","
                      << "\"name\": \"" << peer.name << "\","
                      << "\"platform\": \"" << peer.platform << "\","
                      << "\"host_address\": \"" << peer.host_address << "\","
                      << "\"port\": " << peer.port << ","
                      << "\"fingerprint\": \"" << peer.fingerprint.substr(0, 16) << "...\""
                      << "}";
        }
        
        peers_json << "]}";
        
        return copy_string(peers_json.str());
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
        return nullptr;
    }
}

const char* warpdeck_get_mdns_debug_info(WarpDeckHandle* handle) {
    if (!handle || !handle->discovery_manager) {
        return nullptr;
    }
    
    try {
        const MdnsManager* mdns_manager = handle->discovery_manager->get_mdns_manager();
        if (!mdns_manager) {
            return copy_string("MdnsManager not available");
        }
        
        std::string debug_info = mdns_manager->get_debug_info();
        return copy_string(debug_info);
    } catch (const std::exception& e) {
        safe_call_callback(handle->callbacks.on_error, e.what());
        return nullptr;
    }
}

void warpdeck_free_string(const char* str) {
    if (str) {
        delete[] str;
    }
}

} // extern "C"
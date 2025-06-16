#ifndef WARPDECK_H
#define WARPDECK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// Forward declaration for opaque handle
typedef struct WarpDeckHandle WarpDeckHandle;

// Callback function types
typedef void (*on_peer_discovered_callback)(const char* peer_json);
typedef void (*on_peer_lost_callback)(const char* device_id);
typedef void (*on_incoming_transfer_request_callback)(const char* transfer_request_json);
typedef void (*on_transfer_progress_update_callback)(const char* transfer_id, float progress_percent, uint64_t bytes_transferred);
typedef void (*on_transfer_completed_callback)(const char* transfer_id, bool success, const char* error_message);
typedef void (*on_error_callback)(const char* error_message);

// Callbacks struct containing all event callbacks
typedef struct {
    on_peer_discovered_callback on_peer_discovered;
    on_peer_lost_callback on_peer_lost;
    on_incoming_transfer_request_callback on_incoming_transfer_request;
    on_transfer_progress_update_callback on_transfer_progress_update;
    on_transfer_completed_callback on_transfer_completed;
    on_error_callback on_error;
} Callbacks;

// Core library functions
WarpDeckHandle* warpdeck_create(const Callbacks* callbacks, const char* config_dir);
void warpdeck_destroy(WarpDeckHandle* handle);
int warpdeck_start(WarpDeckHandle* handle, const char* device_name, int desired_port);
void warpdeck_stop(WarpDeckHandle* handle);
void warpdeck_set_device_name(WarpDeckHandle* handle, const char* new_name);
void warpdeck_initiate_transfer(WarpDeckHandle* handle, const char* device_id, const char* files_json);
void warpdeck_respond_to_transfer(WarpDeckHandle* handle, const char* transfer_id, bool accept);
void warpdeck_cancel_transfer(WarpDeckHandle* handle, const char* transfer_id);
const char* warpdeck_get_trusted_devices(WarpDeckHandle* handle);
void warpdeck_remove_trusted_device(WarpDeckHandle* handle, const char* device_id);

// Debug and diagnostic functions
const char* warpdeck_get_discovery_status(WarpDeckHandle* handle);
const char* warpdeck_get_discovered_peers(WarpDeckHandle* handle);
const char* warpdeck_get_mdns_debug_info(WarpDeckHandle* handle);

// Utility function to free strings returned by the library
void warpdeck_free_string(const char* str);

#ifdef __cplusplus
}
#endif

#endif // WARPDECK_H
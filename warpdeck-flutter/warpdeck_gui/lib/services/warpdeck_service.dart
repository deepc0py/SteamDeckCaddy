import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:uuid/uuid.dart';

import '../models/peer.dart';
import '../models/transfer.dart';
import 'libwarpdeck_ffi.dart';

class WarpDeckService extends StateNotifier<WarpDeckState> {
  static const _uuid = Uuid();
  
  Pointer<WarpDeckHandle>? _handle;
  Pointer<Callbacks>? _callbacks;
  late String _configDir;
  String _deviceName = '';
  bool _isStarted = false;

  WarpDeckService() : super(const WarpDeckState()) {
    _initializeConfigDir();
  }

  Future<void> _initializeConfigDir() async {
    if (Platform.isMacOS) {
      final homeDir = Platform.environment['HOME']!;
      _configDir = '$homeDir/Library/Application Support/WarpDeck';
    } else if (Platform.isLinux) {
      final homeDir = Platform.environment['HOME']!;
      _configDir = '$homeDir/.config/warpdeck';
    } else {
      final appDir = await getApplicationSupportDirectory();
      _configDir = '${appDir.path}/warpdeck';
    }
    
    // Ensure config directory exists
    await Directory(_configDir).create(recursive: true);
  }

  Future<bool> initialize({String? deviceName}) async {
    try {
      await _initializeConfigDir();
      
      _deviceName = deviceName ?? await _getStoredDeviceName() ?? _getDefaultDeviceName();
      
      // Try to initialize the FFI library first to catch loading errors
      try {
        // This will trigger library loading and function binding
        final _ = WarpDeckFFI.instance;
      } catch (e) {
        state = state.copyWith(
          status: WarpDeckStatus.error,
          errorMessage: 'Failed to load WarpDeck library: $e',
        );
        return false;
      }
      
      // Setup callbacks
      _callbacks = calloc<Callbacks>();
      _callbacks!.ref.onPeerDiscovered = Pointer.fromFunction<OnPeerDiscoveredNative>(_onPeerDiscovered);
      _callbacks!.ref.onPeerLost = Pointer.fromFunction<OnPeerLostNative>(_onPeerLost);
      _callbacks!.ref.onIncomingTransferRequest = Pointer.fromFunction<OnIncomingTransferRequestNative>(_onIncomingTransferRequest);
      _callbacks!.ref.onTransferProgressUpdate = Pointer.fromFunction<OnTransferProgressUpdateNative>(_onTransferProgressUpdate);
      _callbacks!.ref.onTransferCompleted = Pointer.fromFunction<OnTransferCompletedNative>(_onTransferCompleted);
      _callbacks!.ref.onError = Pointer.fromFunction<OnErrorNative>(_onError);

      // Create WarpDeck handle
      final configDirPtr = _configDir.toNativeUtf8();
      _handle = WarpDeckFFI.instance.warpdeckCreate(_callbacks!, configDirPtr);
      calloc.free(configDirPtr);

      if (_handle == nullptr) {
        state = state.copyWith(
          status: WarpDeckStatus.error,
          errorMessage: 'Failed to create WarpDeck instance - libwarpdeck returned null handle',
        );
        return false;
      }

      state = state.copyWith(
        status: WarpDeckStatus.initialized,
        deviceName: _deviceName,
        errorMessage: null, // Clear any previous errors
      );
      
      return true;
    } catch (e) {
      state = state.copyWith(
        status: WarpDeckStatus.error,
        errorMessage: 'Initialization failed: $e',
      );
      return false;
    }
  }

  Future<bool> start({int port = 0}) async {
    if (_handle == nullptr) {
      await initialize();
    }
    
    if (_handle == nullptr) return false;

    try {
      final deviceNamePtr = _deviceName.toNativeUtf8();
      final resultPort = WarpDeckFFI.instance.warpdeckStart(_handle!, deviceNamePtr, port);
      calloc.free(deviceNamePtr);

      if (resultPort < 0) {
        state = state.copyWith(
          status: WarpDeckStatus.error,
          errorMessage: 'Failed to start WarpDeck on port $port',
        );
        return false;
      }

      _isStarted = true;
      state = state.copyWith(
        status: WarpDeckStatus.running,
        currentPort: resultPort,
      );
      
      return true;
    } catch (e) {
      state = state.copyWith(
        status: WarpDeckStatus.error,
        errorMessage: 'Start failed: $e',
      );
      return false;
    }
  }

  Future<void> stop() async {
    if (_handle != nullptr && _isStarted) {
      WarpDeckFFI.instance.warpdeckStop(_handle!);
      _isStarted = false;
      
      state = state.copyWith(
        status: WarpDeckStatus.initialized,
        currentPort: null,
        discoveredPeers: {},
      );
    }
  }

  @override
  Future<void> dispose() async {
    await stop();
    
    if (_handle != nullptr) {
      WarpDeckFFI.instance.warpdeckDestroy(_handle!);
      _handle = nullptr;
    }
    
    super.dispose();
    
    if (_callbacks != nullptr) {
      calloc.free(_callbacks!);
      _callbacks = nullptr;
    }
    
    state = state.copyWith(status: WarpDeckStatus.uninitialized);
  }

  Future<void> sendFiles(String targetPeerId, List<String> filePaths) async {
    if (_handle == nullptr || !_isStarted) return;

    try {
      // Create file list JSON
      final files = <Map<String, dynamic>>[];
      for (final filePath in filePaths) {
        final file = File(filePath);
        if (await file.exists()) {
          final stat = await file.stat();
          files.add({
            'name': file.uri.pathSegments.last,
            'size': stat.size,
            'path': filePath,
          });
        }
      }

      final filesJson = jsonEncode(files);
      final targetIdPtr = targetPeerId.toNativeUtf8();
      final filesJsonPtr = filesJson.toNativeUtf8();

      WarpDeckFFI.instance.warpdeckInitiateTransfer(_handle!, targetIdPtr, filesJsonPtr);

      calloc.free(targetIdPtr);
      calloc.free(filesJsonPtr);

      // Create transfer record
      final transfer = Transfer(
        id: _uuid.v4(),
        peerId: targetPeerId,
        peerName: state.discoveredPeers[targetPeerId]?.name ?? 'Unknown',
        files: files.map((f) => FileInfo.fromJson(f)).toList(),
        direction: TransferDirection.outgoing,
        status: TransferStatus.pending,
        totalBytes: files.fold(0, (sum, f) => sum + (f['size'] as int)),
        createdAt: DateTime.now(),
      );

      state = state.copyWith(
        activeTransfers: {...state.activeTransfers, transfer.id: transfer},
      );
    } catch (e) {
      state = state.copyWith(
        status: WarpDeckStatus.error,
        errorMessage: 'Send files failed: $e',
      );
    }
  }

  Future<void> respondToTransfer(String transferId, bool accepted) async {
    if (_handle == nullptr || !_isStarted) return;

    try {
      final transferIdPtr = transferId.toNativeUtf8();
      WarpDeckFFI.instance.warpdeckRespondToTransfer(_handle!, transferIdPtr, accepted);
      calloc.free(transferIdPtr);

      // Update transfer status
      final transfer = state.activeTransfers[transferId];
      if (transfer != null) {
        final updatedTransfer = transfer.copyWith(
          status: accepted ? TransferStatus.inProgress : TransferStatus.cancelled,
        );
        state = state.copyWith(
          activeTransfers: {...state.activeTransfers, transferId: updatedTransfer},
        );
      }
    } catch (e) {
      state = state.copyWith(
        status: WarpDeckStatus.error,
        errorMessage: 'Respond to transfer failed: $e',
      );
    }
  }

  Future<void> setDeviceName(String name) async {
    _deviceName = name;
    await _saveDeviceName(name);
    
    state = state.copyWith(deviceName: name);
    
    // Restart if running to update broadcast name
    if (_isStarted) {
      await stop();
      await start();
    }
  }

  // Static callback functions
  static void _onPeerDiscovered(Pointer<Utf8> peerJsonPtr) {
    // Ultra-simple implementation to test if the callback itself is the issue
    print('_onPeerDiscovered called - callback is working!');
  }

  static void _onPeerLost(Pointer<Utf8> deviceIdPtr) {
    print('_onPeerLost called');
  }

  static void _onIncomingTransferRequest(Pointer<Utf8> transferRequestJsonPtr) {
    print('_onIncomingTransferRequest called');
  }

  static void _onTransferProgressUpdate(Pointer<Utf8> transferIdPtr, double progress, int bytesTransferred) {
    print('_onTransferProgressUpdate called');
  }

  static void _onTransferCompleted(Pointer<Utf8> transferIdPtr, bool success, Pointer<Utf8> errorMessagePtr) {
    print('_onTransferCompleted called');
  }

  static void _onError(Pointer<Utf8> errorMessagePtr) {
    print('_onError called');
  }

  // Helper methods
  String _getDefaultDeviceName() {
    if (Platform.isMacOS) return 'Mac Flutter';
    if (Platform.isLinux) return 'Linux Flutter';
    return 'WarpDeck Flutter';
  }

  Future<String?> _getStoredDeviceName() async {
    try {
      final configFile = File('$_configDir/config.json');
      if (await configFile.exists()) {
        final content = await configFile.readAsString();
        final config = jsonDecode(content) as Map<String, dynamic>;
        return config['device_name'] as String?;
      }
    } catch (e) {
      // Ignore errors reading config
    }
    return null;
  }

  Future<void> _saveDeviceName(String name) async {
    try {
      final configFile = File('$_configDir/config.json');
      Map<String, dynamic> config = {};
      
      if (await configFile.exists()) {
        final content = await configFile.readAsString();
        config = jsonDecode(content) as Map<String, dynamic>;
      }
      
      config['device_name'] = name;
      await configFile.writeAsString(jsonEncode(config));
    } catch (e) {
      // Ignore errors saving config
    }
  }

  // Debug methods for MdnsManager integration
  Map<String, dynamic>? getDiscoveryStatus() {
    if (_handle == nullptr) return null;
    
    try {
      final statusJson = WarpDeckFFI.instance.getDiscoveryStatus(_handle!);
      if (statusJson == null) return null;
      return jsonDecode(statusJson) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  Map<String, dynamic>? getDiscoveredPeersDebugInfo() {
    if (_handle == nullptr) return null;
    
    try {
      final peersJson = WarpDeckFFI.instance.getDiscoveredPeers(_handle!);
      if (peersJson == null) return null;
      return jsonDecode(peersJson) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  String? getMdnsDebugInfo() {
    if (_handle == nullptr) return null;
    
    try {
      return WarpDeckFFI.instance.getMdnsDebugInfo(_handle!);
    } catch (e) {
      return null;
    }
  }
}

enum WarpDeckStatus {
  uninitialized,
  initialized,
  running,
  error,
}

class WarpDeckState {
  final WarpDeckStatus status;
  final String? deviceName;
  final int? currentPort;
  final Map<String, Peer> discoveredPeers;
  final Map<String, Transfer> activeTransfers;
  final String? errorMessage;

  const WarpDeckState({
    this.status = WarpDeckStatus.uninitialized,
    this.deviceName,
    this.currentPort,
    this.discoveredPeers = const {},
    this.activeTransfers = const {},
    this.errorMessage,
  });

  WarpDeckState copyWith({
    WarpDeckStatus? status,
    String? deviceName,
    int? currentPort,
    Map<String, Peer>? discoveredPeers,
    Map<String, Transfer>? activeTransfers,
    String? errorMessage,
  }) {
    return WarpDeckState(
      status: status ?? this.status,
      deviceName: deviceName ?? this.deviceName,
      currentPort: currentPort ?? this.currentPort,
      discoveredPeers: discoveredPeers ?? this.discoveredPeers,
      activeTransfers: activeTransfers ?? this.activeTransfers,
      errorMessage: errorMessage ?? this.errorMessage,
    );
  }
}

// Riverpod provider
final warpDeckServiceProvider = StateNotifierProvider<WarpDeckService, WarpDeckState>((ref) {
  return WarpDeckService();
});
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'warpdeck_service.dart';

class NetworkDiagnosticService extends ChangeNotifier {
  Map<String, dynamic> _lastDiagnostics = {};
  bool _isRunning = false;
  WarpDeckService? _warpDeckService;
  
  Map<String, dynamic> get lastDiagnostics => Map.unmodifiable(_lastDiagnostics);
  bool get isRunning => _isRunning;
  
  void setWarpDeckService(WarpDeckService service) {
    _warpDeckService = service;
  }

  Future<Map<String, dynamic>> runFullDiagnostics() async {
    if (_isRunning) return _lastDiagnostics;
    
    _isRunning = true;
    notifyListeners();
    
    final diagnostics = <String, dynamic>{
      'timestamp': DateTime.now().toIso8601String(),
      'platform': Platform.operatingSystem,
    };
    
    try {
      // Network interfaces
      diagnostics['network_interfaces'] = await _getNetworkInterfaces();
      
      // mDNS service check (unified MdnsManager)
      diagnostics['mdns_status'] = await _checkMdnsManagerStatus();
      
      // Firewall status (platform-specific)
      diagnostics['firewall_info'] = await _getFirewallInfo();
      
      // Port connectivity tests
      diagnostics['port_tests'] = await _testPortConnectivity();
      
    } catch (e) {
      diagnostics['error'] = e.toString();
    } finally {
      _isRunning = false;
      _lastDiagnostics = diagnostics;
      notifyListeners();
    }
    
    return diagnostics;
  }

  Future<List<Map<String, dynamic>>> _getNetworkInterfaces() async {
    final interfaces = <Map<String, dynamic>>[];
    
    try {
      for (final interface in await NetworkInterface.list()) {
        final interfaceInfo = <String, dynamic>{
          'name': interface.name,
          'addresses': interface.addresses.map((addr) => {
            'address': addr.address,
            'type': addr.type.name,
            'isLoopback': addr.isLoopback,
            'isLinkLocal': addr.isLinkLocal,
            'isMulticast': addr.isMulticast,
          }).toList(),
        };
        interfaces.add(interfaceInfo);
      }
    } catch (e) {
      interfaces.add({'error': 'Failed to get network interfaces: $e'});
    }
    
    return interfaces;
  }

  Future<Map<String, dynamic>> _checkMdnsManagerStatus() async {
    final result = <String, dynamic>{};
    
    try {
      if (_warpDeckService == null) {
        result['error'] = 'WarpDeck service not available';
        return result;
      }
      
      // Get discovery status
      final discoveryStatus = _warpDeckService!.getDiscoveryStatus();
      if (discoveryStatus != null) {
        result['discovery_status'] = discoveryStatus;
      } else {
        result['discovery_error'] = 'Failed to get discovery status';
      }
      
      // Get discovered peers info
      final peersInfo = _warpDeckService!.getDiscoveredPeersDebugInfo();
      if (peersInfo != null) {
        result['discovered_peers'] = peersInfo;
      } else {
        result['peers_error'] = 'Failed to get discovered peers info';
      }
      
      // Get detailed mDNS debug info
      final mdnsDebugInfo = _warpDeckService!.getMdnsDebugInfo();
      if (mdnsDebugInfo != null) {
        result['mdns_debug_info'] = mdnsDebugInfo;
      } else {
        result['mdns_debug_error'] = 'Failed to get mDNS debug info';
      }
      
    } catch (e) {
      result['error'] = 'Failed to check MdnsManager status: $e';
    }
    
    return result;
  }

  Future<Map<String, dynamic>> _getFirewallInfo() async {
    final result = <String, dynamic>{};
    
    try {
      if (Platform.isMacOS) {
        // Check macOS firewall status
        final pfctlResult = await Process.run('pfctl', ['-s', 'info']).timeout(const Duration(seconds: 3));
        result['pfctl_status'] = {
          'exit_code': pfctlResult.exitCode,
          'output': pfctlResult.stdout,
        };
        
        // Check application firewall
        final socketfilterfwResult = await Process.run('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']).timeout(const Duration(seconds: 3));
        result['app_firewall'] = {
          'exit_code': socketfilterfwResult.exitCode,
          'output': socketfilterfwResult.stdout,
        };
      } else if (Platform.isLinux) {
        // Check iptables
        final iptablesResult = await Process.run('iptables', ['-L', '-n']).timeout(const Duration(seconds: 3));
        result['iptables'] = {
          'exit_code': iptablesResult.exitCode,
          'output': iptablesResult.stdout,
        };
        
        // Check ufw status
        final ufwResult = await Process.run('ufw', ['status']).timeout(const Duration(seconds: 3));
        result['ufw'] = {
          'exit_code': ufwResult.exitCode,
          'output': ufwResult.stdout,
        };
      }
    } catch (e) {
      result['error'] = 'Failed to get firewall info: $e';
    }
    
    return result;
  }


  Future<Map<String, dynamic>> _testPortConnectivity() async {
    final result = <String, dynamic>{};
    final testPorts = [54321, 54322, 54323, 54324, 54325];
    
    for (final port in testPorts) {
      try {
        final socket = await ServerSocket.bind('0.0.0.0', port);
        await socket.close();
        result['port_$port'] = {'available': true, 'error': null};
      } catch (e) {
        result['port_$port'] = {'available': false, 'error': e.toString()};
      }
    }
    
    return result;
  }

  String generateDiagnosticReport() {
    if (_lastDiagnostics.isEmpty) {
      return 'No diagnostics available. Run diagnostics first.';
    }
    
    final buffer = StringBuffer();
    buffer.writeln('WarpDeck Network Diagnostics Report');
    buffer.writeln('Generated: ${_lastDiagnostics['timestamp']}');
    buffer.writeln('Platform: ${_lastDiagnostics['platform']}');
    buffer.writeln('=' * 50);
    buffer.writeln();
    
    // Network interfaces
    final interfaces = _lastDiagnostics['network_interfaces'] as List?;
    if (interfaces != null) {
      buffer.writeln('NETWORK INTERFACES:');
      for (final interface in interfaces) {
        buffer.writeln('  ${interface['name']}:');
        final addresses = interface['addresses'] as List?;
        if (addresses != null) {
          for (final addr in addresses) {
            buffer.writeln('    ${addr['address']} (${addr['type']})');
          }
        }
      }
      buffer.writeln();
    }
    
    // mDNS Manager Status
    final mdnsStatus = _lastDiagnostics['mdns_status'] as Map?;
    if (mdnsStatus != null) {
      buffer.writeln('MDNS MANAGER STATUS:');
      
      final discoveryStatus = mdnsStatus['discovery_status'] as Map?;
      if (discoveryStatus != null) {
        buffer.writeln('  Publishing: ${discoveryStatus['publishing']}');
        buffer.writeln('  Discovering: ${discoveryStatus['discovering']}');
        buffer.writeln('  Started: ${discoveryStatus['started']}');
        buffer.writeln('  Device ID: ${discoveryStatus['device_id']}');
        buffer.writeln('  Device Name: ${discoveryStatus['device_name']}');
        buffer.writeln('  Current Port: ${discoveryStatus['current_port']}');
      }
      
      final discoveredPeers = mdnsStatus['discovered_peers'] as Map?;
      if (discoveredPeers != null) {
        buffer.writeln('  Discovered Peers: ${discoveredPeers['peer_count']}');
        final peers = discoveredPeers['peers'] as List?;
        if (peers != null) {
          for (final peer in peers) {
            buffer.writeln('    ${peer['name']} (${peer['id']}) - ${peer['host_address']}:${peer['port']}');
          }
        }
      }
      
      final mdnsDebugInfo = mdnsStatus['mdns_debug_info'] as String?;
      if (mdnsDebugInfo != null) {
        buffer.writeln('  Debug Info:');
        final lines = mdnsDebugInfo.split('\n');
        for (final line in lines) {
          buffer.writeln('    $line');
        }
      }
      
      if (mdnsStatus.containsKey('error')) {
        buffer.writeln('  Error: ${mdnsStatus['error']}');
      }
      
      buffer.writeln();
    }
    
    
    // Port tests
    final portTests = _lastDiagnostics['port_tests'] as Map?;
    if (portTests != null) {
      buffer.writeln('PORT AVAILABILITY TESTS:');
      for (final entry in portTests.entries) {
        final portInfo = entry.value as Map;
        buffer.writeln('  ${entry.key}: ${portInfo['available'] ? 'Available' : 'In use/blocked'} ${portInfo['error'] ?? ''}');
      }
      buffer.writeln();
    }
    
    return buffer.toString();
  }
}
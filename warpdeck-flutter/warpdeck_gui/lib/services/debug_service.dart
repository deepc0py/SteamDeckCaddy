import 'dart:convert';
import 'dart:io';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import 'network_diagnostic_service.dart';

abstract class DebuggableService {
  String get serviceName;
  String get serviceEndpoint;
  
  Future<HealthCheckResult> runHealthCheck();
}

class HealthCheckResult {
  final String serviceName;
  final String endpoint;
  final HealthStatus status;
  final int? statusCode;
  final int? latencyMs;
  final DateTime timestamp;
  final String? errorMessage;

  const HealthCheckResult({
    required this.serviceName,
    required this.endpoint,
    required this.status,
    this.statusCode,
    this.latencyMs,
    required this.timestamp,
    this.errorMessage,
  });

  HealthCheckResult copyWith({
    String? serviceName,
    String? endpoint,
    HealthStatus? status,
    int? statusCode,
    int? latencyMs,
    DateTime? timestamp,
    String? errorMessage,
  }) {
    return HealthCheckResult(
      serviceName: serviceName ?? this.serviceName,
      endpoint: endpoint ?? this.endpoint,
      status: status ?? this.status,
      statusCode: statusCode ?? this.statusCode,
      latencyMs: latencyMs ?? this.latencyMs,
      timestamp: timestamp ?? this.timestamp,
      errorMessage: errorMessage ?? this.errorMessage,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'serviceName': serviceName,
      'endpoint': endpoint,
      'status': status.name,
      'statusCode': statusCode,
      'latencyMs': latencyMs,
      'timestamp': timestamp.toIso8601String(),
      'errorMessage': errorMessage,
    };
  }
}

enum HealthStatus {
  checking,
  healthy,
  unhealthy,
  timeout,
  error,
}

enum ConnectivityType {
  none,
  wifi,
  mobile,
  ethernet,
  unknown,
}

class ConnectivityInfo {
  final ConnectivityType type;
  final String displayName;
  final DateTime lastChecked;

  const ConnectivityInfo({
    required this.type,
    required this.displayName,
    required this.lastChecked,
  });

  Map<String, dynamic> toJson() {
    return {
      'type': type.name,
      'displayName': displayName,
      'lastChecked': lastChecked.toIso8601String(),
    };
  }
}

class WarpDeckHealthService extends DebuggableService {
  final String _baseUrl;
  final int? port;

  WarpDeckHealthService({String? baseUrl, this.port}) : _baseUrl = baseUrl ?? 'http://localhost';

  @override
  String get serviceName => 'WarpDeck Core Service';

  @override
  String get serviceEndpoint => port != null ? '$_baseUrl:$port' : _baseUrl;

  @override
  Future<HealthCheckResult> runHealthCheck() async {
    final stopwatch = Stopwatch()..start();
    final timestamp = DateTime.now();

    try {
      if (port == null) {
        return HealthCheckResult(
          serviceName: serviceName,
          endpoint: serviceEndpoint,
          status: HealthStatus.error,
          timestamp: timestamp,
          errorMessage: 'Service port not available - WarpDeck may not be running',
        );
      }

      final uri = Uri.parse('$serviceEndpoint/health');
      final response = await http.get(uri).timeout(
        const Duration(seconds: 10),
      );

      stopwatch.stop();

      if (response.statusCode == 200) {
        return HealthCheckResult(
          serviceName: serviceName,
          endpoint: serviceEndpoint,
          status: HealthStatus.healthy,
          statusCode: response.statusCode,
          latencyMs: stopwatch.elapsedMilliseconds,
          timestamp: timestamp,
        );
      } else {
        return HealthCheckResult(
          serviceName: serviceName,
          endpoint: serviceEndpoint,
          status: HealthStatus.unhealthy,
          statusCode: response.statusCode,
          latencyMs: stopwatch.elapsedMilliseconds,
          timestamp: timestamp,
          errorMessage: 'HTTP ${response.statusCode}: ${response.reasonPhrase}',
        );
      }
    } catch (e) {
      stopwatch.stop();

      HealthStatus status;
      String errorMessage;

      if (e is SocketException) {
        status = HealthStatus.unhealthy;
        errorMessage = 'Connection refused - service may not be running';
      } else if (e.toString().contains('timeout') || e.toString().contains('TimeoutException')) {
        status = HealthStatus.timeout;
        errorMessage = 'Request timed out after 10 seconds';
      } else {
        status = HealthStatus.error;
        errorMessage = e.toString();
      }

      return HealthCheckResult(
        serviceName: serviceName,
        endpoint: serviceEndpoint,
        status: status,
        latencyMs: stopwatch.elapsedMilliseconds,
        timestamp: timestamp,
        errorMessage: errorMessage,
      );
    }
  }
}

class UpdateHealthService extends DebuggableService {
  static const String _githubApiUrl = 'https://api.github.com/repos/deepc0py/WarpDeck';

  @override
  String get serviceName => 'Update Service (GitHub API)';

  @override
  String get serviceEndpoint => _githubApiUrl;

  @override
  Future<HealthCheckResult> runHealthCheck() async {
    final stopwatch = Stopwatch()..start();
    final timestamp = DateTime.now();

    try {
      final uri = Uri.parse('$_githubApiUrl/releases/latest');
      final response = await http.get(uri).timeout(
        const Duration(seconds: 15),
      );

      stopwatch.stop();

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final tagName = data['tag_name'] as String?;
        
        return HealthCheckResult(
          serviceName: serviceName,
          endpoint: serviceEndpoint,
          status: HealthStatus.healthy,
          statusCode: response.statusCode,
          latencyMs: stopwatch.elapsedMilliseconds,
          timestamp: timestamp,
          errorMessage: tagName != null ? 'Latest version: $tagName' : null,
        );
      } else {
        return HealthCheckResult(
          serviceName: serviceName,
          endpoint: serviceEndpoint,
          status: HealthStatus.unhealthy,
          statusCode: response.statusCode,
          latencyMs: stopwatch.elapsedMilliseconds,
          timestamp: timestamp,
          errorMessage: 'HTTP ${response.statusCode}: ${response.reasonPhrase}',
        );
      }
    } catch (e) {
      stopwatch.stop();

      HealthStatus status;
      String errorMessage;

      if (e.toString().contains('timeout') || e.toString().contains('TimeoutException')) {
        status = HealthStatus.timeout;
        errorMessage = 'Request timed out after 15 seconds';
      } else {
        status = HealthStatus.error;
        errorMessage = e.toString();
      }

      return HealthCheckResult(
        serviceName: serviceName,
        endpoint: serviceEndpoint,
        status: status,
        latencyMs: stopwatch.elapsedMilliseconds,
        timestamp: timestamp,
        errorMessage: errorMessage,
      );
    }
  }
}

class DebugService extends ChangeNotifier {
  final List<DebuggableService> _services = [];
  final Map<String, HealthCheckResult> _lastResults = {};
  ConnectivityInfo? _connectivityInfo;
  bool _isRunningHealthChecks = false;
  NetworkDiagnosticService? _networkDiagnosticService;

  List<DebuggableService> get services => List.unmodifiable(_services);
  Map<String, HealthCheckResult> get lastResults => Map.unmodifiable(_lastResults);
  ConnectivityInfo? get connectivityInfo => _connectivityInfo;
  bool get isRunningHealthChecks => _isRunningHealthChecks;

  void setNetworkDiagnosticService(NetworkDiagnosticService service) {
    _networkDiagnosticService = service;
  }

  void registerService(DebuggableService service) {
    if (!_services.any((s) => s.serviceName == service.serviceName)) {
      _services.add(service);
      notifyListeners();
    }
  }

  void unregisterService(String serviceName) {
    _services.removeWhere((s) => s.serviceName == serviceName);
    _lastResults.remove(serviceName);
    notifyListeners();
  }

  Future<void> runAllHealthChecks() async {
    if (_isRunningHealthChecks) return;

    _isRunningHealthChecks = true;
    notifyListeners();

    try {
      await _updateConnectivityInfo();

      final futures = _services.map((service) async {
        try {
          final result = await service.runHealthCheck();
          _lastResults[service.serviceName] = result;
        } catch (e) {
          _lastResults[service.serviceName] = HealthCheckResult(
            serviceName: service.serviceName,
            endpoint: service.serviceEndpoint,
            status: HealthStatus.error,
            timestamp: DateTime.now(),
            errorMessage: 'Health check failed: $e',
          );
        }
      });

      await Future.wait(futures);
    } finally {
      _isRunningHealthChecks = false;
      notifyListeners();
    }
  }

  Future<void> runHealthCheck(String serviceName) async {
    final service = _services.firstWhere(
      (s) => s.serviceName == serviceName,
      orElse: () => throw ArgumentError('Service not found: $serviceName'),
    );

    try {
      final result = await service.runHealthCheck();
      _lastResults[serviceName] = result;
      notifyListeners();
    } catch (e) {
      _lastResults[serviceName] = HealthCheckResult(
        serviceName: serviceName,
        endpoint: service.serviceEndpoint,
        status: HealthStatus.error,
        timestamp: DateTime.now(),
        errorMessage: 'Health check failed: $e',
      );
      notifyListeners();
    }
  }

  Future<void> _updateConnectivityInfo() async {
    try {
      final result = await Connectivity().checkConnectivity();
      final connectivityType = _mapConnectivityResult(result.first);
      
      _connectivityInfo = ConnectivityInfo(
        type: connectivityType,
        displayName: _getConnectivityDisplayName(connectivityType),
        lastChecked: DateTime.now(),
      );
    } catch (e) {
      if (kDebugMode) {
        print('Failed to check connectivity: $e');
      }
      _connectivityInfo = ConnectivityInfo(
        type: ConnectivityType.unknown,
        displayName: 'Unknown (Error checking connectivity)',
        lastChecked: DateTime.now(),
      );
    }
  }

  ConnectivityType _mapConnectivityResult(ConnectivityResult result) {
    switch (result) {
      case ConnectivityResult.wifi:
        return ConnectivityType.wifi;
      case ConnectivityResult.mobile:
        return ConnectivityType.mobile;
      case ConnectivityResult.ethernet:
        return ConnectivityType.ethernet;
      case ConnectivityResult.none:
        return ConnectivityType.none;
      default:
        return ConnectivityType.unknown;
    }
  }

  String _getConnectivityDisplayName(ConnectivityType type) {
    switch (type) {
      case ConnectivityType.wifi:
        return 'WiFi';
      case ConnectivityType.mobile:
        return 'Mobile Data';
      case ConnectivityType.ethernet:
        return 'Ethernet';
      case ConnectivityType.none:
        return 'No Connection';
      case ConnectivityType.unknown:
        return 'Unknown';
    }
  }

  String generateDiagnosticReport() {
    final buffer = StringBuffer();
    final timestamp = DateTime.now().toIso8601String();
    
    buffer.writeln('WarpDeck Debug Report');
    buffer.writeln('Generated: $timestamp');
    buffer.writeln('=' * 50);
    buffer.writeln();

    // Connectivity Information
    buffer.writeln('CONNECTIVITY STATUS:');
    if (_connectivityInfo != null) {
      buffer.writeln('Type: ${_connectivityInfo!.displayName}');
      buffer.writeln('Last Checked: ${_connectivityInfo!.lastChecked.toIso8601String()}');
    } else {
      buffer.writeln('Status: Not checked');
    }
    buffer.writeln();

    // Service Health Checks
    buffer.writeln('SERVICE HEALTH CHECKS:');
    for (final service in _services) {
      final result = _lastResults[service.serviceName];
      buffer.writeln('${service.serviceName}:');
      buffer.writeln('  Endpoint: ${service.serviceEndpoint}');
      if (result != null) {
        buffer.writeln('  Status: ${result.status.name.toUpperCase()}');
        if (result.statusCode != null) {
          buffer.writeln('  HTTP Status: ${result.statusCode}');
        }
        if (result.latencyMs != null) {
          buffer.writeln('  Latency: ${result.latencyMs}ms');
        }
        buffer.writeln('  Last Check: ${result.timestamp.toIso8601String()}');
        if (result.errorMessage != null) {
          buffer.writeln('  Error: ${result.errorMessage}');
        }
      } else {
        buffer.writeln('  Status: NOT CHECKED');
      }
      buffer.writeln();
    }

    if (_networkDiagnosticService != null && _networkDiagnosticService!.lastDiagnostics.isNotEmpty) {
      buffer.writeln('=' * 50);
      buffer.writeln();
      buffer.write(_networkDiagnosticService!.generateDiagnosticReport());
    }

    return buffer.toString();
  }

  Future<void> clearAppCache() async {
    try {
      // This is a placeholder implementation
      // In a real app, you would clear various caches here
      await Future.delayed(const Duration(milliseconds: 500));
      
      if (kDebugMode) {
        print('App cache cleared (debug mode)');
      }
    } catch (e) {
      if (kDebugMode) {
        print('Failed to clear app cache: $e');
      }
      rethrow;
    }
  }

  Future<void> copyLogsToClipboard() async {
    try {
      final report = generateDiagnosticReport();
      await Clipboard.setData(ClipboardData(text: report));
      
      if (kDebugMode) {
        print('Debug report copied to clipboard');
      }
    } catch (e) {
      if (kDebugMode) {
        print('Failed to copy logs to clipboard: $e');
      }
      rethrow;
    }
  }
}
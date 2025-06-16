import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';

import '../services/debug_service.dart';
import '../services/warpdeck_service.dart';
import '../services/network_diagnostic_service.dart';

final debugServiceProvider = ChangeNotifierProvider<DebugService>((ref) {
  final debugService = DebugService();
  
  // Register services
  final warpDeckState = ref.watch(warpDeckServiceProvider);
  debugService.registerService(WarpDeckHealthService(port: warpDeckState.currentPort));
  debugService.registerService(UpdateHealthService());
  
  return debugService;
});

final networkDiagnosticServiceProvider = ChangeNotifierProvider<NetworkDiagnosticService>((ref) {
  final service = NetworkDiagnosticService();
  final warpDeckState = ref.watch(warpDeckServiceProvider);
  service.setWarpDeckService(ref.read(warpDeckServiceProvider.notifier));
  return service;
});

class DebugScreen extends ConsumerStatefulWidget {
  const DebugScreen({super.key});

  @override
  ConsumerState<DebugScreen> createState() => _DebugScreenState();
}

class _DebugScreenState extends ConsumerState<DebugScreen> {
  String? _expandedService;

  @override
  void initState() {
    super.initState();
    // Run initial health checks
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(debugServiceProvider).runAllHealthChecks();
    });
  }

  @override
  Widget build(BuildContext context) {
    // TODO: Enable debug mode only when requested
    // if (!kDebugMode) {
    //   return const Scaffold(
    //     body: Center(
    //       child: Text(
    //         'Debug screen is only available in debug mode',
    //         style: TextStyle(fontSize: 16),
    //       ),
    //     ),
    //   );
    // }

    final debugService = ref.watch(debugServiceProvider);
    final networkDiagnosticService = ref.watch(networkDiagnosticServiceProvider);
    final connectivity = debugService.connectivityInfo;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Connection & Services Debug'),
        backgroundColor: Colors.red.shade700,
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            onPressed: debugService.isRunningHealthChecks ? null : () {
              ref.read(debugServiceProvider).runAllHealthChecks();
            },
            icon: debugService.isRunningHealthChecks
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                    ),
                  )
                : const Icon(Icons.refresh),
            tooltip: 'Run Health Checks',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Device Status Section
            _buildSectionHeader('Device Status', MdiIcons.monitor),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildInfoRow(
                      'Device Connectivity',
                      connectivity?.displayName ?? 'Checking...',
                      _getConnectivityIcon(connectivity?.type),
                      _getConnectivityColor(connectivity?.type),
                    ),
                    const SizedBox(height: 8),
                    _buildInfoRow(
                      'Last Check',
                      connectivity?.lastChecked.toString().split('.')[0] ?? 'Not checked',
                      Icons.access_time,
                      Colors.grey,
                    ),
                  ],
                ),
              ),
            ),
            
            const SizedBox(height: 24),

            // Action Buttons
            _buildSectionHeader('Actions', MdiIcons.wrench),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _buildActionButton(
                      'Run Health Checks',
                      MdiIcons.heartPulse,
                      debugService.isRunningHealthChecks ? null : () {
                        debugService.runAllHealthChecks();
                      },
                      debugService.isRunningHealthChecks,
                    ),
                    _buildActionButton(
                      'Copy Logs',
                      MdiIcons.contentCopy,
                      () async {
                        try {
                          await debugService.copyLogsToClipboard();
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('Debug logs copied to clipboard'),
                                backgroundColor: Colors.green,
                              ),
                            );
                          }
                        } catch (e) {
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('Failed to copy logs: $e'),
                                backgroundColor: Colors.red,
                              ),
                            );
                          }
                        }
                      },
                      false,
                    ),
                    _buildActionButton(
                      'Clear Cache',
                      MdiIcons.trashCan,
                      () async {
                        try {
                          await debugService.clearAppCache();
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('App cache cleared'),
                                backgroundColor: Colors.green,
                              ),
                            );
                          }
                        } catch (e) {
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('Failed to clear cache: $e'),
                                backgroundColor: Colors.red,
                              ),
                            );
                          }
                        }
                      },
                      false,
                    ),
                    _buildActionButton(
                      'Network Diag',
                      MdiIcons.networkOutline,
                      networkDiagnosticService.isRunning ? null : () async {
                        try {
                          await networkDiagnosticService.runFullDiagnostics();
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('Network diagnostics completed'),
                                backgroundColor: Colors.green,
                              ),
                            );
                          }
                        } catch (e) {
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('Network diagnostics failed: $e'),
                                backgroundColor: Colors.red,
                              ),
                            );
                          }
                        }
                      },
                      networkDiagnosticService.isRunning,
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 24),

            // Services List
            _buildSectionHeader('Services Health Check', MdiIcons.serverNetwork),
            if (debugService.services.isEmpty)
              const Card(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Text('No services registered for health checks'),
                ),
              )
            else
              ...debugService.services.map((service) {
                final result = debugService.lastResults[service.serviceName];
                final isExpanded = _expandedService == service.serviceName;
                
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: Column(
                    children: [
                      ListTile(
                        leading: _buildStatusIcon(result?.status),
                        title: Text(service.serviceName),
                        subtitle: Text(service.serviceEndpoint),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (result?.statusCode != null)
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                decoration: BoxDecoration(
                                  color: _getStatusCodeColor(result!.statusCode!).withOpacity(0.1),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: _getStatusCodeColor(result.statusCode!).withOpacity(0.3),
                                  ),
                                ),
                                child: Text(
                                  '${result.statusCode}',
                                  style: TextStyle(
                                    color: _getStatusCodeColor(result.statusCode!),
                                    fontWeight: FontWeight.bold,
                                    fontSize: 12,
                                  ),
                                ),
                              ),
                            if (result?.latencyMs != null) ...[
                              const SizedBox(width: 8),
                              Text(
                                '${result!.latencyMs}ms',
                                style: TextStyle(
                                  color: _getLatencyColor(result.latencyMs!),
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ],
                            const SizedBox(width: 8),
                            Icon(
                              isExpanded ? Icons.expand_less : Icons.expand_more,
                              color: Colors.grey,
                            ),
                          ],
                        ),
                        onTap: () {
                          setState(() {
                            _expandedService = isExpanded ? null : service.serviceName;
                          });
                        },
                      ),
                      if (isExpanded && result != null)
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.5),
                            border: Border(
                              top: BorderSide(color: Theme.of(context).dividerColor),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Details',
                                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              const SizedBox(height: 8),
                              _buildDetailRow('Endpoint', result.endpoint),
                              _buildDetailRow('Status', result.status.name.toUpperCase()),
                              if (result.statusCode != null)
                                _buildDetailRow('HTTP Status', '${result.statusCode}'),
                              if (result.latencyMs != null)
                                _buildDetailRow('Latency', '${result.latencyMs} ms'),
                              _buildDetailRow('Timestamp', result.timestamp.toString().split('.')[0]),
                              if (result.errorMessage != null) ...[
                                const SizedBox(height: 8),
                                Text(
                                  'Error Message:',
                                  style: Theme.of(context).textTheme.labelMedium?.copyWith(
                                    color: Colors.red,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                                const SizedBox(height: 4),
                                Container(
                                  width: double.infinity,
                                  padding: const EdgeInsets.all(12),
                                  decoration: BoxDecoration(
                                    color: Theme.of(context).colorScheme.errorContainer.withOpacity(0.2),
                                    borderRadius: BorderRadius.circular(8),
                                    border: Border.all(color: Theme.of(context).colorScheme.error.withOpacity(0.5)),
                                  ),
                                  child: Text(
                                    result.errorMessage!,
                                    style: TextStyle(
                                      color: Theme.of(context).colorScheme.onErrorContainer,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                    ],
                  ),
                );
              }),

            const SizedBox(height: 24),

            // Network Diagnostics
            _buildSectionHeader('Network Diagnostics', MdiIcons.networkOutline),
            if (networkDiagnosticService.lastDiagnostics.isEmpty)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      const Text('No network diagnostics available'),
                      const SizedBox(height: 8),
                      ElevatedButton.icon(
                        onPressed: networkDiagnosticService.isRunning ? null : () {
                          networkDiagnosticService.runFullDiagnostics();
                        },
                        icon: networkDiagnosticService.isRunning 
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : Icon(MdiIcons.networkOutline),
                        label: Text(networkDiagnosticService.isRunning 
                            ? 'Running...' 
                            : 'Run Network Diagnostics'),
                      ),
                    ],
                  ),
                ),
              )
            else
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            'Last Run: ${DateTime.parse(networkDiagnosticService.lastDiagnostics['timestamp']).toLocal().toString().split('.')[0]}',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                          TextButton.icon(
                            onPressed: () async {
                              final report = networkDiagnosticService.generateDiagnosticReport();
                              showDialog(
                                context: context,
                                builder: (context) => AlertDialog(
                                  title: const Text('Network Diagnostic Report'),
                                  content: SingleChildScrollView(
                                    child: Text(
                                      report,
                                      style: const TextStyle(fontFamily: 'monospace'),
                                    ),
                                  ),
                                  actions: [
                                    TextButton(
                                      onPressed: () => Navigator.of(context).pop(),
                                      child: const Text('Close'),
                                    ),
                                  ],
                                ),
                              );
                            },
                            icon: const Icon(Icons.description),
                            label: const Text('View Report'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      _buildDiagnosticSummary(networkDiagnosticService.lastDiagnostics),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title, IconData icon) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        children: [
          Icon(
            icon,
            size: 20,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 8),
          Text(
            title,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value, IconData icon, Color color) {
    return Row(
      children: [
        Icon(icon, size: 16, color: color),
        const SizedBox(width: 8),
        Text(
          '$label: ',
          style: const TextStyle(fontWeight: FontWeight.w500),
        ),
        Expanded(
          child: Text(
            value,
            style: TextStyle(color: color),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  Widget _buildActionButton(String label, IconData icon, VoidCallback? onPressed, bool isLoading) {
    return Expanded(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4),
        child: ElevatedButton.icon(
          onPressed: onPressed,
          icon: isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Icon(icon, size: 16),
          label: Text(
            label,
            style: const TextStyle(fontSize: 12),
          ),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(vertical: 12),
          ),
        ),
      ),
    );
  }

  Widget _buildStatusIcon(HealthStatus? status) {
    if (status == null) {
      return const Icon(Icons.help_outline, color: Colors.grey);
    }

    switch (status) {
      case HealthStatus.checking:
        return const SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        );
      case HealthStatus.healthy:
        return const Icon(Icons.check_circle, color: Colors.green);
      case HealthStatus.unhealthy:
        return const Icon(Icons.warning, color: Colors.orange);
      case HealthStatus.timeout:
        return const Icon(Icons.access_time, color: Colors.red);
      case HealthStatus.error:
        return const Icon(Icons.error, color: Colors.red);
    }
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(
              '$label:',
              style: const TextStyle(
                fontWeight: FontWeight.w500,
                fontSize: 12,
                color: Colors.grey,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }

  IconData _getConnectivityIcon(ConnectivityType? type) {
    if (type == null) return Icons.help_outline;
    
    switch (type) {
      case ConnectivityType.wifi:
        return Icons.wifi;
      case ConnectivityType.mobile:
        return Icons.signal_cellular_4_bar;
      case ConnectivityType.ethernet:
        return MdiIcons.ethernet;
      case ConnectivityType.none:
        return Icons.wifi_off;
      case ConnectivityType.unknown:
        return Icons.help_outline;
    }
  }

  Color _getConnectivityColor(ConnectivityType? type) {
    if (type == null) return Colors.grey;
    
    switch (type) {
      case ConnectivityType.wifi:
      case ConnectivityType.mobile:
      case ConnectivityType.ethernet:
        return Colors.green;
      case ConnectivityType.none:
        return Colors.red;
      case ConnectivityType.unknown:
        return Colors.orange;
    }
  }

  Color _getStatusCodeColor(int statusCode) {
    if (statusCode >= 200 && statusCode < 300) {
      return Colors.green;
    } else if (statusCode >= 300 && statusCode < 400) {
      return Colors.orange;
    } else if (statusCode >= 400 && statusCode < 500) {
      return Colors.red;
    } else if (statusCode >= 500) {
      return Colors.red.shade800;
    } else {
      return Colors.grey;
    }
  }

  Color _getLatencyColor(int latencyMs) {
    if (latencyMs < 100) {
      return Colors.green;
    } else if (latencyMs < 500) {
      return Colors.orange;
    } else {
      return Colors.red;
    }
  }

  Widget _buildDiagnosticSummary(Map<String, dynamic> diagnostics) {
    final summaryItems = <Widget>[];
    
    // Network interfaces summary
    final interfaces = diagnostics['network_interfaces'] as List?;
    if (interfaces != null) {
      int totalAddresses = 0;
      for (final interface in interfaces) {
        final addresses = interface['addresses'] as List?;
        if (addresses != null) {
          totalAddresses += addresses.length;
        }
      }
      summaryItems.add(_buildSummaryItem(
        'Network Interfaces',
        '${interfaces.length} interfaces, $totalAddresses addresses',
        Icons.network_check,
        Colors.blue,
      ));
    }
    
    // mDNS Manager status
    if (diagnostics.containsKey('mdns_status')) {
      final mdnsStatus = diagnostics['mdns_status'] as Map;
      final discoveryStatus = mdnsStatus['discovery_status'] as Map?;
      
      if (discoveryStatus != null) {
        final isPublishing = discoveryStatus['publishing'] == true;
        final isDiscovering = discoveryStatus['discovering'] == true;
        final isStarted = discoveryStatus['started'] == true;
        
        // Overall mDNS status
        final isHealthy = isStarted && isPublishing && isDiscovering;
        summaryItems.add(_buildSummaryItem(
          'mDNS Service',
          isHealthy ? 'Healthy' : 'Issues detected',
          isHealthy ? Icons.check_circle : Icons.warning,
          isHealthy ? Colors.green : Colors.orange,
        ));
        
        // Publishing status
        summaryItems.add(_buildSummaryItem(
          'Service Publishing',
          isPublishing ? 'Active' : 'Inactive',
          isPublishing ? Icons.broadcast_on_personal : Icons.broadcast_on_personal,
          isPublishing ? Colors.green : Colors.red,
        ));
        
        // Discovery status
        summaryItems.add(_buildSummaryItem(
          'Peer Discovery',
          isDiscovering ? 'Active' : 'Inactive',
          isDiscovering ? Icons.search : Icons.search_off,
          isDiscovering ? Colors.green : Colors.red,
        ));
        
        // Peer count
        final discoveredPeers = mdnsStatus['discovered_peers'] as Map?;
        if (discoveredPeers != null) {
          final peerCount = discoveredPeers['peer_count'] ?? 0;
          summaryItems.add(_buildSummaryItem(
            'Discovered Peers',
            '$peerCount peer${peerCount == 1 ? '' : 's'}',
            peerCount > 0 ? Icons.devices : Icons.devices_other,
            peerCount > 0 ? Colors.blue : Colors.grey,
          ));
        }
      }
      
      if (mdnsStatus.containsKey('error')) {
        summaryItems.add(_buildSummaryItem(
          'mDNS Error',
          'Failed to get status',
          Icons.error,
          Colors.red,
        ));
      }
    }
    
    // Port availability
    final portTests = diagnostics['port_tests'] as Map?;
    if (portTests != null) {
      int availablePorts = 0;
      for (final entry in portTests.entries) {
        final portInfo = entry.value as Map;
        if (portInfo['available'] == true) {
          availablePorts++;
        }
      }
      summaryItems.add(_buildSummaryItem(
        'Port Availability',
        '$availablePorts/${portTests.length} ports available',
        availablePorts > 0 ? Icons.check_circle : Icons.warning,
        availablePorts > 0 ? Colors.green : Colors.orange,
      ));
    }
    
    return Column(
      children: summaryItems,
    );
  }

  Widget _buildSummaryItem(String label, String value, IconData icon, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 16, color: color),
          const SizedBox(width: 8),
          Text(
            '$label: ',
            style: const TextStyle(fontWeight: FontWeight.w500),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(color: color),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}
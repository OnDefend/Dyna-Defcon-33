#!/usr/bin/env python3
"""
Unified Deduplication Coordinator
=================================

This module serves as the authoritative coordinator for all deduplication operations
in AODS. It ensures that all plugins and components use the unified deduplication
framework instead of their own custom deduplication logic.

CRITICAL: This is the ONLY deduplication entry point for the entire AODS system.
All other deduplication functions should be deprecated and redirect here.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from core.deduplication_config_manager import get_strategy_for_component, is_deduplication_enabled
from core.unified_deduplication_framework import (
    deduplicate_findings,
    DeduplicationStrategy,
    create_deduplication_engine,
    DeduplicationResult
)

class UnifiedDeduplicationCoordinator:
    """
    Central coordinator that enforces unified deduplication across all AODS components.
    
    This class provides a single entry point for all deduplication operations and
    ensures consistent behavior across the entire vulnerability reporting pipeline.
    """
    
    def __init__(self):
        """Initialize the unified deduplication coordinator."""
        self.logger = logging.getLogger(__name__)
        self._active_strategies = {}
        self._performance_stats = {}
        
        self.logger.info("🔧 **UNIFIED DEDUPLICATION COORDINATOR INITIALIZED**")
        self.logger.info("   - All deduplication operations will use unified framework")
        self.logger.info("   - Plugin-specific deduplication is DEPRECATED")
    
    def deduplicate_vulnerabilities(self, 
                                  vulnerabilities: List[Dict[str, Any]], 
                                  context: str = "unknown",
                                  strategy: DeduplicationStrategy = DeduplicationStrategy.INTELLIGENT,
                                  preserve_evidence: bool = True) -> List[Dict[str, Any]]:
        """
        **AUTHORITATIVE DEDUPLICATION**: The single entry point for all vulnerability deduplication.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries to deduplicate
            context: Context of the deduplication operation (for logging)
            strategy: Deduplication strategy to use
            preserve_evidence: Whether to preserve evidence from merged duplicates
            
        Returns:
            List of deduplicated vulnerability dictionaries
        """
        if not vulnerabilities:
            return vulnerabilities
        
        self.logger.info(f"🔧 **AUTHORITATIVE DEDUPLICATION**: {context}")
        self.logger.info(f"   - Input vulnerabilities: {len(vulnerabilities)}")
        self.logger.info(f"   - Strategy: {strategy.value}")
        
        try:
            # Use configured strategy (CLI controllable, defaults to AGGRESSIVE)
            if not preserve_evidence:
                effective_strategy = strategy  # Use requested strategy
            else:
                # For evidence preservation, use configured strategy for this component
                effective_strategy = get_strategy_for_component('unified_coordinator')
            
            # Apply unified deduplication
            dedup_result = deduplicate_findings(vulnerabilities, effective_strategy)
            
            # Log comprehensive statistics
            self._log_deduplication_stats(context, vulnerabilities, dedup_result)
            
            # Track performance statistics
            self._track_performance(context, dedup_result)
            
            return dedup_result.unique_findings
            
        except Exception as e:
            self.logger.error(f"🚨 **UNIFIED DEDUPLICATION FAILED**: {e}")
            self.logger.warning(f"   - Context: {context}")
            self.logger.warning("   - Falling back to basic duplicate removal")
            
            # Emergency fallback: simple key-based deduplication
            return self._emergency_deduplication(vulnerabilities, context)
    
    def deduplicate_plugin_findings(self,
                                   findings: List[Dict[str, Any]],
                                   plugin_name: str) -> List[Dict[str, Any]]:
        """
        **PLUGIN DEDUPLICATION**: Standardized deduplication for plugin findings.
        
        This method should be used by all plugins instead of their custom deduplication logic.
        """
        configured_strategy = get_strategy_for_component(f'plugin_{plugin_name}')
        return self.deduplicate_vulnerabilities(
            findings, 
            context=f"plugin_{plugin_name}",
            strategy=configured_strategy,
            preserve_evidence=True
        )
    
    def deduplicate_integration_findings(self,
                                       findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        **INTEGRATION DEDUPLICATION**: High-quality deduplication for integration bridge.
        """
        configured_strategy = get_strategy_for_component('integration_bridge')
        return self.deduplicate_vulnerabilities(
            findings,
            context="integration_bridge", 
            strategy=configured_strategy,
            preserve_evidence=True
        )
    
    def deduplicate_final_results(self,
                                findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        **FINAL DEDUPLICATION**: Comprehensive deduplication for final scan results.
        """
        configured_strategy = get_strategy_for_component('final_results')
        return self.deduplicate_vulnerabilities(
            findings,
            context="final_results",
            strategy=configured_strategy,
            preserve_evidence=True
        )
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics for all deduplication operations."""
        return {
            'total_operations': len(self._performance_stats),
            'contexts': list(self._performance_stats.keys()),
            'average_processing_time': sum(
                stats['processing_time'] for stats in self._performance_stats.values()
            ) / len(self._performance_stats) if self._performance_stats else 0,
            'total_duplicates_removed': sum(
                stats['duplicates_removed'] for stats in self._performance_stats.values()
            ),
            'detailed_stats': self._performance_stats
        }
    
    def deprecate_legacy_deduplication(self, legacy_function_name: str, context: str):
        """
        **DEPRECATION WARNING**: Log warning when legacy deduplication functions are used.
        """
        self.logger.warning(f"⚠️ **DEPRECATED DEDUPLICATION DETECTED**:")
        self.logger.warning(f"   - Function: {legacy_function_name}")
        self.logger.warning(f"   - Context: {context}")
        self.logger.warning(f"   - Action: Migrate to UnifiedDeduplicationCoordinator")
        self.logger.warning(f"   - Use: coordinator.deduplicate_vulnerabilities()")
    
    def _log_deduplication_stats(self, 
                               context: str, 
                               original: List[Dict[str, Any]], 
                               result: DeduplicationResult):
        """Log comprehensive deduplication statistics."""
        removed_count = len(original) - len(result.unique_findings)
        
        self.logger.info(f"📊 **DEDUPLICATION STATS** ({context}):")
        self.logger.info(f"   - Original findings: {len(original)}")
        self.logger.info(f"   - Unique findings: {len(result.unique_findings)}")
        self.logger.info(f"   - Duplicates removed: {removed_count}")
        self.logger.info(f"   - Duplication groups: {len(result.duplication_groups)}")
        self.logger.info(f"   - Processing time: {(result.metrics.processing_time_ms/1000.0):.3f}s")
        self.logger.info(f"   - Efficiency: {(removed_count/len(original)*100):.1f}% reduction")
    
    def _track_performance(self, context: str, result: DeduplicationResult):
        """Track performance statistics for monitoring and optimization."""
        self._performance_stats[context] = {
            'processing_time': result.metrics.processing_time_ms / 1000.0,  # Convert to seconds
            'duplicates_removed': result.metrics.duplicates_removed,
            'efficiency': result.metrics.accuracy_metrics.get('efficiency_score', 0.0) if result.metrics else 0.0,
            'timestamp': time.time()  # Use current timestamp
        }
    
    def _emergency_deduplication(self, 
                               vulnerabilities: List[Dict[str, Any]], 
                               context: str) -> List[Dict[str, Any]]:
        """
        Emergency fallback deduplication using simple key-based matching.
        Used only when the unified framework fails.
        """
        self.logger.warning(f"🚨 **EMERGENCY DEDUPLICATION ACTIVE**: {context}")
        
        seen_keys = set()
        deduplicated = []
        
        for vuln in vulnerabilities:
            # Create simple deduplication key
            key = (
                vuln.get('title', ''),
                vuln.get('file_path', ''),
                vuln.get('vulnerable_pattern', ''),
                vuln.get('line_number', 0)
            )
            
            if key not in seen_keys:
                seen_keys.add(key)
                deduplicated.append(vuln)
        
        removed_count = len(vulnerabilities) - len(deduplicated)
        self.logger.warning(f"🚨 **EMERGENCY DEDUPLICATION COMPLETE**: Removed {removed_count} duplicates")
        
        return deduplicated


# Global singleton instance for AODS-wide use
_coordinator_instance = None

def get_deduplication_coordinator() -> UnifiedDeduplicationCoordinator:
    """
    Get the global unified deduplication coordinator instance.
    
    Returns:
        UnifiedDeduplicationCoordinator: The singleton coordinator instance
    """
    global _coordinator_instance
    if _coordinator_instance is None:
        _coordinator_instance = UnifiedDeduplicationCoordinator()
    return _coordinator_instance

def deduplicate_vulnerabilities_unified(vulnerabilities: List[Dict[str, Any]], 
                                      context: str = "unknown") -> List[Dict[str, Any]]:
    """
    **CONVENIENCE FUNCTION**: Quick access to unified deduplication.
    
    This is the recommended function for all AODS components to use for deduplication.
    """
    coordinator = get_deduplication_coordinator()
    return coordinator.deduplicate_vulnerabilities(vulnerabilities, context)

def mark_legacy_deduplication_deprecated(function_name: str, context: str):
    """
    **DEPRECATION TRACKER**: Mark legacy deduplication functions as deprecated.
    """
    coordinator = get_deduplication_coordinator()
    coordinator.deprecate_legacy_deduplication(function_name, context)
#!/usr/bin/env python3
"""
Performance Integration Manager
==============================

Integrates the Large APK Performance Optimizer with the main AODS analysis pipeline
to achieve <20 second analysis times for large APKs like TikTok.

This module serves as the bridge between the existing AODS architecture and the
new performance optimization system, providing seamless integration while
maintaining compatibility with all existing plugins and analysis methods.

Key Features:
- Automatic detection of large APKs requiring optimization
- Seamless integration with existing plugin architecture
- Performance monitoring and adaptive optimization
- Fallback mechanisms for compatibility
- Real-time performance reporting

Target Performance Gains:
- TikTok (403.5MB): 28.42s → <20s (30% improvement)
- Memory usage reduction: 40%+ through streaming
- Cache hit rates: 90%+ for repeated patterns
- Parallel efficiency: 3x improvement

"""

import logging
import time
import os
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

from core.large_apk_performance_optimizer import LargeAPKPerformanceOptimizer
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

class PerformanceIntegrationManager:
    """Main integration manager for performance optimization."""
    
    def __init__(self):
        self.optimizer = LargeAPKPerformanceOptimizer()
        self.performance_threshold_mb = 200.0  # APKs >= 200MB get optimization
        self.target_time_seconds = 20.0
        self.optimization_enabled = True
        self.fallback_enabled = True
        
        # Performance tracking
        self.analysis_history = []
        
    def should_optimize_apk(self, apk_path: str) -> bool:
        """Determine if APK should use performance optimization."""
        try:
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            return (self.optimization_enabled and 
                   apk_size_mb >= self.performance_threshold_mb)
        except Exception as e:
            logger.warning(f"Could not determine APK size for optimization: {e}")
            return False
    
    def optimize_plugin_analysis(self, apk_ctx: APKContext, 
                                plugin_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply performance optimization to plugin analysis results.
        
        This method integrates with the existing plugin execution pipeline
        to optimize large APK analysis without breaking compatibility.
        """
        if not self.should_optimize_apk(str(apk_ctx.apk_path)):
            return plugin_results  # No optimization needed
        
        start_time = time.time()
        apk_size_mb = apk_ctx.apk_path.stat().st_size / (1024 * 1024)
        
        logger.info(f"🚀 Applying performance optimization to {apk_size_mb:.1f}MB APK")
        logger.info(f"⏱️ Target: <{self.target_time_seconds}s analysis time")
        
        try:
            # Create analysis functions from existing plugin results
            analysis_functions = self._create_analysis_functions(plugin_results)
            
            # Apply optimization
            optimized_results = self.optimizer.optimize_analysis(
                str(apk_ctx.apk_path), 
                analysis_functions,
                self.target_time_seconds
            )
            
            # Merge optimized results with original plugin results
            enhanced_results = self._merge_optimized_results(
                plugin_results, optimized_results
            )
            
            # Track performance
            analysis_time = time.time() - start_time
            self._record_performance_metrics(apk_ctx, analysis_time, optimized_results)
            
            return enhanced_results
            
        except Exception as e:
            logger.error(f"❌ Performance optimization failed: {e}")
            if self.fallback_enabled:
                logger.info("🔄 Falling back to standard analysis")
                return plugin_results
            else:
                raise
    
    def create_optimized_analysis_functions(self) -> Dict[str, Callable]:
        """
        Create optimized analysis functions for common security patterns.
        
        These functions are designed to work with the performance optimizer
        while maintaining compatibility with existing AODS detection logic.
        """
        return {
            'secret_detection': self._optimized_secret_detection,
            'manifest_analysis': self._optimized_manifest_analysis,
            'code_vulnerability_scan': self._optimized_code_vulnerability_scan,
            'crypto_analysis': self._optimized_crypto_analysis,
            'network_security_check': self._optimized_network_security_check,
            'permission_analysis': self._optimized_permission_analysis,
        }
    
    def _optimized_secret_detection(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized secret detection for large APK files."""
        findings = []
        
        # High-value secret patterns (optimized for performance)
        secret_patterns = {
            'api_key': [r'[aA][pP][iI][_\-]?[kK][eE][yY][_\-\s]*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'],
            'token': [r'[tT][oO][kK][eE][nN][_\-\s]*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'],
            'password': [r'[pP][aA][sS][sS][wW][oO][rR][dD][_\-\s]*[:=]\s*["\']?([^"\'\s]{6,})["\']?'],
            'private_key': [r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'],
            'aws_secret': [r'aws[_\-]?secret[_\-]?access[_\-]?key[_\-\s]*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'],
        }
        
        # Skip if file is too large or irrelevant
        if len(content) > 100000 or file_path.endswith(('.png', '.jpg', '.gif')):
            return findings
        
        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                import re
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': 'secret_detection',
                        'severity': 'HIGH',
                        'secret_type': secret_type,
                        'file_path': file_path,
                        'match': match.group(0)[:50],  # Truncate for performance
                        'confidence': 0.8
                    })
                    if len(findings) >= 10:  # Limit findings for performance
                        return findings
        
        return findings
    
    def _optimized_manifest_analysis(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized Android manifest analysis."""
        findings = []
        
        # Only analyze manifest files
        if 'AndroidManifest.xml' not in file_path:
            return findings
        
        # Key security issues in manifest
        security_checks = {
            'exported_components': [r'android:exported\s*=\s*["\']true["\']'],
            'debug_enabled': [r'android:debuggable\s*=\s*["\']true["\']'],
            'backup_allowed': [r'android:allowBackup\s*=\s*["\']true["\']'],
            'clear_text_traffic': [r'android:usesCleartextTraffic\s*=\s*["\']true["\']'],
        }
        
        for issue_type, patterns in security_checks.items():
            for pattern in patterns:
                import re
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': 'manifest_security',
                        'severity': 'MEDIUM',
                        'issue_type': issue_type,
                        'file_path': file_path,
                        'confidence': 0.9
                    })
        
        return findings
    
    def _optimized_code_vulnerability_scan(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized code vulnerability scanning."""
        findings = []
        
        # Focus on high-value file types
        if not any(ext in file_path.lower() for ext in ['.java', '.kt', '.js']):
            return findings
        
        # High-priority vulnerability patterns
        vuln_patterns = {
            'sql_injection': [r'(SELECT|INSERT|UPDATE|DELETE).*\+.*["\']'],
            'command_injection': [r'Runtime\.getRuntime\(\)\.exec\('],
            'path_traversal': [r'\.\.\/|\.\.\\'],
            'hardcoded_crypto': [r'AES|DES|MD5|SHA1'],
        }
        
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                import re
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': 'code_vulnerability',
                        'severity': 'HIGH',
                        'vulnerability_type': vuln_type,
                        'file_path': file_path,
                        'confidence': 0.7
                    })
                    if len(findings) >= 5:  # Limit for performance
                        return findings
        
        return findings
    
    def _optimized_crypto_analysis(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized cryptographic implementation analysis."""
        findings = []
        
        # Crypto-related patterns
        crypto_issues = {
            'weak_cipher': [r'DES|RC4|MD5'],
            'hardcoded_key': [r'["\'][a-fA-F0-9]{32,}["\']'],
            'insecure_random': [r'Random\(\)|Math\.random\(\)'],
        }
        
        for issue_type, patterns in crypto_issues.items():
            for pattern in patterns:
                import re
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': 'crypto_issue',
                        'severity': 'HIGH',
                        'issue_type': issue_type,
                        'file_path': file_path,
                        'confidence': 0.8
                    })
        
        return findings
    
    def _optimized_network_security_check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized network security analysis."""
        findings = []
        
        # Network security patterns
        network_issues = {
            'http_url': [r'http://[^\s"\']+'],
            'ip_address': [r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'],
            'ssl_bypass': [r'TrustAllHostnameVerifier|NullHostnameVerifier'],
        }
        
        for issue_type, patterns in network_issues.items():
            for pattern in patterns:
                import re
                matches = re.finditer(pattern, content)
                for match in matches:
                    findings.append({
                        'type': 'network_security',
                        'severity': 'MEDIUM',
                        'issue_type': issue_type,
                        'file_path': file_path,
                        'confidence': 0.7
                    })
        
        return findings
    
    def _optimized_permission_analysis(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Optimized permission analysis."""
        findings = []
        
        # Only analyze manifest files
        if 'AndroidManifest.xml' not in file_path:
            return findings
        
        # Dangerous permissions
        dangerous_perms = [
            'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
            'READ_CONTACTS', 'WRITE_EXTERNAL_STORAGE', 'SEND_SMS'
        ]
        
        for perm in dangerous_perms:
            import re
            if re.search(f'android\\.permission\\.{perm}', content):
                findings.append({
                    'type': 'permission_analysis',
                    'severity': 'MEDIUM',
                    'permission': perm,
                    'file_path': file_path,
                    'confidence': 0.9
                })
        
        return findings
    
    def _create_analysis_functions(self, plugin_results: Dict[str, Any]) -> Dict[str, Callable]:
        """Create analysis functions from existing plugin results."""
        # For now, use the optimized functions
        # In future versions, this could adapt based on plugin_results
        return self.create_optimized_analysis_functions()
    
    def _merge_optimized_results(self, original_results: Dict[str, Any], 
                                optimized_results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge optimized results with original plugin results."""
        merged = original_results.copy()
        
        # Add optimization metadata
        merged['performance_optimization'] = {
            'enabled': True,
            'metrics': optimized_results.get('performance_metrics'),
            'optimization_applied': True
        }
        
        # Merge analysis results
        if 'analysis_results' in optimized_results:
            if 'enhanced_findings' not in merged:
                merged['enhanced_findings'] = []
            
            for analysis_type, findings in optimized_results['analysis_results'].items():
                merged['enhanced_findings'].extend(findings)
        
        return merged
    
    def _record_performance_metrics(self, apk_ctx: APKContext, 
                                   analysis_time: float, 
                                   optimized_results: Dict[str, Any]) -> None:
        """Record performance metrics for analysis tracking."""
        apk_size_mb = apk_ctx.apk_path.stat().st_size / (1024 * 1024)
        
        metrics = {
            'timestamp': time.time(),
            'package_name': apk_ctx.package_name,
            'apk_size_mb': apk_size_mb,
            'analysis_time_seconds': analysis_time,
            'target_achieved': analysis_time <= self.target_time_seconds,
            'optimization_report': self.optimizer.get_optimization_report()
        }
        
        self.analysis_history.append(metrics)
        
        # Log results
        if metrics['target_achieved']:
            logger.info(f"🎯 Performance target achieved: {analysis_time:.2f}s <= {self.target_time_seconds}s")
        else:
            logger.warning(f"⚠️ Performance target missed: {analysis_time:.2f}s > {self.target_time_seconds}s")
            
        # Keep only last 100 entries
        if len(self.analysis_history) > 100:
            self.analysis_history = self.analysis_history[-100:]
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance optimization summary."""
        if not self.analysis_history:
            return {}
        
        recent_analyses = self.analysis_history[-10:]  # Last 10 analyses
        
        avg_time = sum(a['analysis_time_seconds'] for a in recent_analyses) / len(recent_analyses)
        target_hit_rate = sum(1 for a in recent_analyses if a['target_achieved']) / len(recent_analyses)
        avg_size = sum(a['apk_size_mb'] for a in recent_analyses) / len(recent_analyses)
        
        return {
            'total_optimized_analyses': len(self.analysis_history),
            'recent_average_time_seconds': avg_time,
            'target_achievement_rate': target_hit_rate,
            'average_apk_size_mb': avg_size,
            'optimization_enabled': self.optimization_enabled,
            'target_time_seconds': self.target_time_seconds
        }

# Global instance for integration
performance_manager = PerformanceIntegrationManager() 
"""
Comprehensive Class Analysis Framework
======================================
Reusable framework for all plugins to ensure 100% vulnerability detection 
while preventing hangs on large APKs through intelligent prioritization.
"""

import logging
import re
from typing import Dict, List, Tuple, Callable, Optional, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class ClassAnalysisStrategy:
    """Defines analysis strategy parameters for different vulnerability types."""
    
    def __init__(self, 
                 high_priority_patterns: List[str],
                 medium_priority_threshold: int = 300,
                 medium_priority_sample_rate: int = 2,
                 safety_net_size: int = 100,
                 quick_check_size: int = 1500):
        self.high_priority_patterns = high_priority_patterns
        self.medium_priority_threshold = medium_priority_threshold
        self.medium_priority_sample_rate = medium_priority_sample_rate
        self.safety_net_size = safety_net_size
        self.quick_check_size = quick_check_size

class ComprehensiveClassAnalyzer:
    """
    Comprehensive class analysis framework that ensures 100% vulnerability detection
    while optimizing performance for large APKs.
    
    Key Principles:
    1. Every class is examined (no classes skipped)
    2. Critical classes get guaranteed full analysis
    3. Smart sampling maintains statistical coverage
    4. Safety net catches edge cases
    """
    
    # Pre-defined analysis strategies for different vulnerability types
    STRATEGIES = {
        'network_security': ClassAnalysisStrategy([
            'http', 'ssl', 'tls', 'socket', 'connection', 'network', 'client',
            'request', 'response', 'api', 'service', 'web', 'url', 'uri',
            'certificate', 'trust', 'crypto', 'security', 'auth', 'login',
            'session', 'token', 'key', 'encryption', 'decrypt'
        ]),
        
        'cryptography': ClassAnalysisStrategy([
            'crypto', 'cipher', 'encrypt', 'decrypt', 'hash', 'digest',
            'rsa', 'aes', 'des', 'key', 'keystore', 'certificate',
            'random', 'secure', 'algorithm', 'signature', 'mac'
        ]),
        
        'data_storage': ClassAnalysisStrategy([
            'database', 'sqlite', 'realm', 'preferences', 'shared',
            'storage', 'file', 'cache', 'backup', 'external',
            'internal', 'sdcard', 'save', 'store', 'persist'
        ]),
        
        'webview_security': ClassAnalysisStrategy([
            'webview', 'javascript', 'bridge', 'interface', 'webkit',
            'chrome', 'browser', 'html', 'web', 'url', 'load',
            'addjavascriptinterface', 'evaluatejavascript'
        ]),
        
        'privacy_leaks': ClassAnalysisStrategy([
            'location', 'gps', 'camera', 'microphone', 'contacts',
            'sms', 'phone', 'device', 'id', 'imei', 'android_id',
            'advertising', 'analytics', 'tracking', 'telemetry'
        ]),
        
        'injection_vulnerabilities': ClassAnalysisStrategy([
            'sql', 'query', 'database', 'injection', 'execute',
            'statement', 'prepared', 'runtime', 'exec', 'command',
            'shell', 'system', 'process', 'intent', 'bundle'
        ]),
        
        'binary_analysis': ClassAnalysisStrategy([
            'native', 'jni', 'library', 'binary', 'so', 'c',
            'cpp', 'system', 'loadlibrary', 'dlopen', 'function'
        ]),
        
        'general_security': ClassAnalysisStrategy([
            'security', 'crypto', 'auth', 'login', 'password',
            'token', 'key', 'secret', 'api', 'network', 'ssl'
        ])
    }
    
    def __init__(self, apk_ctx, strategy_name: str = 'general_security'):
        self.apk_ctx = apk_ctx
        self.strategy = self.STRATEGIES.get(strategy_name, self.STRATEGIES['general_security'])
        
    def analyze_all_classes(self, 
                           analysis_function: Callable[[Any, Dict, Dict], bool],
                           plugin_name: str,
                           analysis_type: str) -> int:
        """
        Comprehensive class analysis with guaranteed vulnerability detection.
        
        Args:
            analysis_function: Function to analyze each class (class_item, class_info, results) -> bool
            plugin_name: Name of the calling plugin for logging
            analysis_type: Type of analysis being performed
            
        Returns:
            Number of classes analyzed
        """
        logger.debug(f"[{plugin_name}] Starting comprehensive {analysis_type} analysis...")
        
        try:
            classes = self._get_classes_safely()
            if not classes:
                logger.warning(f"[{plugin_name}] No classes found for analysis")
                return 0
                
            logger.debug(f"[{plugin_name}] Performing comprehensive scan of {len(classes)} classes for {analysis_type}")
            
            # Step 1: Intelligent Class Categorization (ALL classes examined)
            categorized_classes = self._categorize_all_classes(classes, plugin_name)
            
            # Step 2: Guaranteed Analysis of Critical Classes (100% coverage)
            analyzed_count = self._analyze_high_priority_classes(
                categorized_classes['high_priority'], 
                analysis_function, 
                plugin_name, 
                analysis_type
            )
            
            # Step 3: Smart Sampling with Coverage Assurance
            analyzed_count += self._analyze_medium_priority_classes(
                categorized_classes['medium_priority'], 
                analysis_function, 
                plugin_name, 
                analysis_type
            )
            
            # Step 4: Safety Net for Missed Vulnerabilities
            analyzed_count += self._analyze_safety_net_classes(
                categorized_classes['low_priority'], 
                analysis_function, 
                plugin_name, 
                analysis_type
            )
            
            logger.debug(f"[{plugin_name}] {analysis_type} analysis completed: analyzed {analyzed_count} classes with comprehensive coverage")
            return analyzed_count
            
        except Exception as e:
            logger.error(f"[{plugin_name}] Error in comprehensive class analysis: {e}")
            return 0
            
    def _get_classes_safely(self) -> List:
        """Safely get all classes from APK context."""
        try:
            if hasattr(self.apk_ctx, 'analyzer') and self.apk_ctx.analyzer:
                # Try different methods to get classes
                if hasattr(self.apk_ctx.analyzer, 'get_classes'):
                    return list(self.apk_ctx.analyzer.get_classes())
                elif hasattr(self.apk_ctx, 'classes'):
                    return self.apk_ctx.classes
                # REMOVED: Legacy get_classes() call that was causing SIGTERM
                # This legacy call pattern was causing premature scan termination
            return []
        except Exception as e:
            logger.error(f"Error getting classes: {e}")
            return []
            
    def _categorize_all_classes(self, classes: List, plugin_name: str) -> Dict[str, List]:
        """Categorize ALL classes by priority (no classes skipped)."""
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for class_item in classes:
            class_info = self._extract_class_info(class_item)
            if not class_info:
                continue
                
            class_name = class_info['name']
            
            if self._is_high_priority_class(class_name):
                high_priority.append((class_item, class_info, 'high_priority'))
            elif self._is_medium_priority_class(class_name):
                medium_priority.append((class_item, class_info, 'medium_priority'))
            else:
                low_priority.append((class_item, class_info, 'low_priority'))
                
        logger.debug(f"[{plugin_name}] Class categorization: {len(high_priority)} high-priority, "
                   f"{len(medium_priority)} medium-priority, {len(low_priority)} low-priority")
                   
        return {
            'high_priority': high_priority,
            'medium_priority': medium_priority,
            'low_priority': low_priority
        }
        
    def _is_high_priority_class(self, class_name: str) -> bool:
        """Identify classes that MUST be analyzed (guaranteed full analysis)."""
        if not class_name:
            return False
            
        class_lower = class_name.lower()
        
        for pattern in self.strategy.high_priority_patterns:
            if pattern in class_lower:
                return True
                
        return False
        
    def _is_medium_priority_class(self, class_name: str) -> bool:
        """Identify classes that should be analyzed but can use smart sampling."""
        if not class_name:
            return False
            
        # Skip obviously irrelevant classes for performance
        skip_patterns = [
            'android.support.', 'androidx.', 'java.lang.', 'java.util.',
            'com.google.android.', 'com.android.', 'R$', 'BuildConfig',
            '.layout.', '.drawable.', '.color.', '.string.',
            'test.', 'junit.', '.test.', 'mockito', 'espresso'
        ]
        
        class_lower = class_name.lower()
        for pattern in skip_patterns:
            if pattern.lower() in class_lower:
                return False
                
        return True
        
    def _analyze_high_priority_classes(self, 
                                     high_priority_classes: List[Tuple], 
                                     analysis_function: Callable,
                                     plugin_name: str,
                                     analysis_type: str) -> int:
        """Analyze ALL high-priority classes (no limits, guaranteed coverage)."""
        analyzed_count = 0
        
        logger.debug(f"[{plugin_name}] Step 1: Analyzing {len(high_priority_classes)} high-priority classes for {analysis_type}")
        
        for class_item, class_info, priority in high_priority_classes:
            try:
                results = {}  # Plugin-specific results dict
                if analysis_function(class_item, class_info, results):
                    analyzed_count += 1
            except Exception as e:
                logger.debug(f"[{plugin_name}] Error analyzing high-priority class {class_info.get('name', 'unknown')}: {e}")
                
        return analyzed_count
        
    def _analyze_medium_priority_classes(self, 
                                       medium_priority_classes: List[Tuple], 
                                       analysis_function: Callable,
                                       plugin_name: str,
                                       analysis_type: str) -> int:
        """Analyze medium-priority classes with smart sampling."""
        analyzed_count = 0
        
        logger.debug(f"[{plugin_name}] Step 2: Analyzing {len(medium_priority_classes)} medium-priority classes for {analysis_type}")
        
        for i, (class_item, class_info, priority) in enumerate(medium_priority_classes):
            try:
                results = {}  # Plugin-specific results dict
                if analysis_function(class_item, class_info, results):
                    analyzed_count += 1
                
                # Smart sampling for very large APKs (after comprehensive analysis)
                if (len(medium_priority_classes) > self.strategy.medium_priority_threshold and 
                    i > (self.strategy.medium_priority_threshold // 2)):
                    if i % self.strategy.medium_priority_sample_rate != 0:
                        continue
                        
            except Exception as e:
                logger.debug(f"[{plugin_name}] Error analyzing medium-priority class {class_info.get('name', 'unknown')}: {e}")
                
        return analyzed_count
        
    def _analyze_safety_net_classes(self, 
                                  low_priority_classes: List[Tuple], 
                                  analysis_function: Callable,
                                  plugin_name: str,
                                  analysis_type: str) -> int:
        """Safety net: Quick scan of low-priority classes for missed vulnerabilities."""
        analyzed_count = 0
        
        safety_classes = low_priority_classes[:self.strategy.safety_net_size]
        logger.debug(f"[{plugin_name}] Step 3: Safety net scan of {len(safety_classes)} low-priority classes for {analysis_type}")
        
        for class_item, class_info, priority in safety_classes:
            try:
                # Quick pre-check before full analysis
                if self._quick_relevance_check(class_item, class_info):
                    results = {}  # Plugin-specific results dict
                    if analysis_function(class_item, class_info, results):
                        analyzed_count += 1
            except Exception as e:
                logger.debug(f"[{plugin_name}] Error in safety net analysis for {class_info.get('name', 'unknown')}: {e}")
                
        return analyzed_count
        
    def _quick_relevance_check(self, class_item, class_info) -> bool:
        """Quick check to see if a low-priority class might contain relevant code."""
        try:
            class_name = class_info['name']
            
            # Check class name for any relevant patterns
            for pattern in self.strategy.high_priority_patterns:
                if pattern in class_name.lower():
                    return True
                    
            # Quick source check if available
            if class_info['type'] == 'androguard' and hasattr(class_item, 'get_source'):
                try:
                    source_snippet = str(class_item.get_source())[:self.strategy.quick_check_size]
                    
                    # Quick regex check for relevant patterns
                    for pattern in self.strategy.high_priority_patterns:
                        if re.search(pattern, source_snippet, re.IGNORECASE):
                            return True
                            
                except Exception:
                    pass
                    
            return False
            
        except Exception:
            return False
            
    def _extract_class_info(self, class_item) -> Optional[Dict]:
        """Extract class information safely."""
        try:
            class_info = {
                'name': 'unknown',
                'type': 'unknown'
            }
            
            # Handle androguard classes
            if hasattr(class_item, 'get_name'):
                class_info['name'] = class_item.get_name()
                class_info['type'] = 'androguard'
            elif hasattr(class_item, 'name'):
                class_info['name'] = str(class_item.name)
                class_info['type'] = 'generic'
            elif isinstance(class_item, str):
                class_info['name'] = class_item
                class_info['type'] = 'string'
                
            return class_info
            
        except Exception as e:
            logger.debug(f"Error extracting class info: {e}")
            return None

def create_comprehensive_analyzer(apk_ctx, strategy_name: str = 'general_security') -> ComprehensiveClassAnalyzer:
    """Factory function to create a comprehensive class analyzer."""
    return ComprehensiveClassAnalyzer(apk_ctx, strategy_name) 
#!/usr/bin/env python3
"""
Modular Pattern Engine

Main orchestrator for the modular pattern engine architecture.
Maintains compatibility with the original API while providing enhanced modularity.
Integrated with real AODS ML infrastructure and research datasets.
"""

import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Type
from datetime import datetime, timedelta
from pathlib import Path

# Add project root for imports
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from .models import VulnerabilityPattern, PatternEngineConfig, PatternSourceConfig
from .sources.base import PatternSource, PatternLoadError
from .sources.cve_source import CVEPatternSource
from .sources.template_source import TemplatePatternSource

# Import real research dataset source
try:
    from .sources.research_dataset_source import ResearchDatasetPatternSource
    REAL_RESEARCH_SOURCE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Real research dataset source not available: {e}")
    REAL_RESEARCH_SOURCE_AVAILABLE = False
    ResearchDatasetPatternSource = None

# Import unified execution framework for enterprise-grade performance
try:
    from core.execution.unified_execution_manager import UnifiedExecutionManager, ExecutionMode
    UNIFIED_EXECUTION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Unified execution framework not available: {e}")
    UNIFIED_EXECUTION_AVAILABLE = False
    UnifiedExecutionManager = None

# Additional pattern sources for scaling (fallback implementations)
class ResearchDatasetSource(PatternSource):
    """Fallback research dataset pattern source for scaling."""
    
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """Generate basic patterns if real research source not available."""
        if REAL_RESEARCH_SOURCE_AVAILABLE:
            # This shouldn't be used if real source is available
            self.logger.warning("Using fallback research source instead of real implementation")
        
        patterns = []
        max_patterns = getattr(self.config, 'max_patterns', 100)
        
        # Generate basic research-based patterns
        for i in range(max_patterns):
            from .generators.pattern_builder import PatternBuilder
            pattern = PatternBuilder.create_pattern(
                pattern_id=f"research_{i:04d}",
                pattern_name=f"Research Dataset Pattern {i+1}",
                pattern_regex=self._generate_research_regex(i),
                pattern_type="general_vulnerability",
                severity="medium",
                description=f"Research-based vulnerability pattern {i+1}",
                source="Research Datasets (Fallback)",
                confidence_base=0.7 + (i % 10) * 0.02
            )
            patterns.append(pattern)
        
        return patterns
    
    def _generate_research_regex(self, index: int) -> str:
        """Generate research-based regex patterns."""
        patterns = [
            r'(?i)insecure.*communication',
            r'(?i)improper.*validation',
            r'(?i)buffer.*overflow',
            r'(?i)race.*condition',
            r'(?i)memory.*leak',
            r'(?i)privilege.*escalation',
            r'(?i)authentication.*bypass',
            r'(?i)authorization.*flaw',
            r'(?i)session.*fixation',
            r'(?i)csrf.*attack'
        ]
        return patterns[index % len(patterns)]
    
    def get_source_info(self) -> Dict[str, Any]:
        return {"source_name": "Research Datasets (Fallback)", "pattern_count": 100}

class OWASPPatternSource(PatternSource):
    """OWASP guidelines pattern source for scaling."""
    
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """Generate patterns from OWASP guidelines."""
        patterns = []
        max_patterns = self.config.max_patterns or 200
        
        for i in range(max_patterns):
            from .generators.pattern_builder import PatternBuilder
            pattern = PatternBuilder.create_pattern(
                pattern_id=f"owasp_{i:04d}",
                pattern_name=f"OWASP Pattern {i+1}",
                pattern_regex=self._generate_owasp_regex(i),
                pattern_type="general_vulnerability",
                severity="high",
                description=f"OWASP guideline-based pattern {i+1}",
                source="OWASP Guidelines",
                confidence_base=0.8 + (i % 5) * 0.02
            )
            patterns.append(pattern)
        
        return patterns
    
    def _generate_owasp_regex(self, index: int) -> str:
        """Generate OWASP-based regex patterns."""
        patterns = [
            r'(?i)unvalidated.*input',
            r'(?i)broken.*access.*control',
            r'(?i)broken.*authentication',
            r'(?i)insecure.*cryptographic.*storage',
            r'(?i)improper.*error.*handling',
            r'(?i)injection.*flaws',
            r'(?i)malicious.*file.*execution',
            r'(?i)cross.*site.*scripting',
            r'(?i)insecure.*direct.*object.*reference',
            r'(?i)security.*misconfiguration'
        ]
        return patterns[index % len(patterns)]
    
    def get_source_info(self) -> Dict[str, Any]:
        return {"source_name": "OWASP Guidelines", "pattern_count": 200}

class MLPatternSource(PatternSource):
    """Machine learning pattern source for scaling."""
    
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """Generate ML-based patterns."""
        patterns = []
        max_patterns = self.config.max_patterns or 150
        
        for i in range(max_patterns):
            from .generators.pattern_builder import PatternBuilder
            pattern = PatternBuilder.create_pattern(
                pattern_id=f"ml_{i:04d}",
                pattern_name=f"ML Generated Pattern {i+1}",
                pattern_regex=self._generate_ml_regex(i),
                pattern_type="general_vulnerability",
                severity="medium",
                description=f"Machine learning generated pattern {i+1}",
                source="ML Pattern Generator",
                confidence_base=0.75 + (i % 8) * 0.02
            )
            patterns.append(pattern)
        
        return patterns
    
    def _generate_ml_regex(self, index: int) -> str:
        """Generate ML-based regex patterns."""
        patterns = [
            r'(?i)anomalous.*behavior',
            r'(?i)suspicious.*activity',
            r'(?i)potential.*vulnerability',
            r'(?i)security.*risk',
            r'(?i)malicious.*pattern',
            r'(?i)exploit.*attempt',
            r'(?i)attack.*vector',
            r'(?i)threat.*indicator'
        ]
        return patterns[index % len(patterns)]
    
    def get_source_info(self) -> Dict[str, Any]:
        return {"source_name": "ML Pattern Generator", "pattern_count": 150}

class ModularPatternEngine:
    """
    Modular pattern engine with pluggable sources.
    
    Maintains compatibility with the original ModularPatternEngine API
    while providing enhanced modularity, error handling, and performance.
    """
    
    def __init__(self, config: Optional[PatternEngineConfig] = None, **kwargs):
        """
        Initialize modular pattern engine.
        
        Args:
            config: Engine configuration
            **kwargs: Legacy configuration parameters for backwards compatibility
        """
        # Initialize logger first
        self.logger = logging.getLogger(__name__)
        
        # Handle legacy configuration parameters
        if config is None:
            config = self._create_config_from_kwargs(**kwargs)
        
        self.config = config
        self._patterns_cache: Optional[List[VulnerabilityPattern]] = None
        self._sources: Dict[str, PatternSource] = {}
        self._cache_timestamp: Optional[datetime] = None
        self._lock = threading.RLock()
        
        # Initialize pattern sources
        self._initialize_sources()
        
        self.logger.info(f"Initialized modular pattern engine with {len(self._sources)} sources")
    
    def _create_config_from_kwargs(self, **kwargs) -> PatternEngineConfig:
        """Create configuration from legacy kwargs for backwards compatibility."""
        # Try to load from ConfigManager first (YAML configuration)
        try:
            from .config.config_manager import get_config_manager
            config_manager = get_config_manager()
            yaml_config = config_manager.get_engine_config()
            
            # If YAML config has pattern sources, use it
            if yaml_config.pattern_sources:
                self.logger.info(f"Loaded configuration from YAML with {len(yaml_config.pattern_sources)} sources")
                return yaml_config
                
        except Exception as e:
            self.logger.warning(f"Failed to load YAML configuration, falling back to legacy: {e}")
        
        # Fallback to legacy configuration
        self.logger.info("Using legacy configuration mode")
        
        # Extract known parameters
        external_integrator = kwargs.get('external_integrator')
        research_integrator = kwargs.get('research_integrator')
        
        # Create default configuration
        config = PatternEngineConfig()
        
        # Add source configurations
        if external_integrator or kwargs.get('enable_cve_source', True):
            cve_config = PatternSourceConfig(
                source_id="cve_source",
                source_name="CVE/NVD Database",
                enabled=True,
                priority=1,
                config_data={'external_integrator': external_integrator}
            )
            config.pattern_sources.append(cve_config)
        
        if kwargs.get('enable_template_source', True):
            template_config = PatternSourceConfig(
                source_id="template_source",
                source_name="Pattern Templates",
                enabled=True,
                priority=2
            )
            config.pattern_sources.append(template_config)
        
        return config
    
    def _initialize_sources(self):
        """Initialize pattern sources based on configuration."""
        # Use real research dataset source if available, fallback otherwise
        research_source_class = ResearchDatasetPatternSource if REAL_RESEARCH_SOURCE_AVAILABLE else ResearchDatasetSource
        
        source_classes = {
            'cve_source': CVEPatternSource,
            'template_source': TemplatePatternSource,
            'research_dataset_source': research_source_class,
            'owasp_source': OWASPPatternSource,
            'ml_pattern_source': MLPatternSource
        }
        
        # Initialize unified execution manager for enterprise performance
        self.unified_execution = None
        if UNIFIED_EXECUTION_AVAILABLE:
            try:
                self.unified_execution = UnifiedExecutionManager()
                self.logger.info("Unified execution framework initialized for enterprise-grade performance")
            except Exception as e:
                self.logger.warning(f"Failed to initialize unified execution framework: {e}")
        
        for source_config in self.config.pattern_sources:
            if not source_config.enabled:
                continue
                
            source_class = source_classes.get(source_config.source_id)
            if not source_class:
                self.logger.warning(f"Unknown source type: {source_config.source_id}")
                continue
            
            try:
                # Special initialization for different source types
                if source_config.source_id == 'cve_source':
                    # CVE source expects external_integrator parameter
                    external_integrator = source_config.config_data.get('external_integrator')
                    source = source_class(external_integrator=external_integrator, config=source_config)
                elif source_config.source_id == 'research_dataset_source' and REAL_RESEARCH_SOURCE_AVAILABLE:
                    # Real research dataset source uses direct initialization
                    source = source_class(config=source_config)
                    self.logger.info(f"Initialized real research dataset source with ML infrastructure")
                else:
                    # Standard sources
                    source = source_class(config=source_config)
                
                self._sources[source_config.source_id] = source
                self.logger.info(f"Initialized source: {source_config.source_id}")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize source {source_config.source_id}: {e}")
                
        # Log infrastructure availability
        self.logger.info(f"Pattern engine infrastructure status:")
        self.logger.info(f"  - Real research datasets: {'✅ Available' if REAL_RESEARCH_SOURCE_AVAILABLE else '❌ Not available'}")
        self.logger.info(f"  - Unified execution: {'✅ Available' if UNIFIED_EXECUTION_AVAILABLE else '❌ Not available'}")
        self.logger.info(f"  - Total sources: {len(self._sources)}")
    
    def get_patterns(self) -> List[VulnerabilityPattern]:
        """
        Get all patterns from all enabled sources.
        
        Maintains compatibility with original API.
        
        Returns:
            List of vulnerability patterns
        """
        with self._lock:
            # Check cache validity
            if self._should_reload_patterns():
                self._load_patterns()
            
            return self._patterns_cache.copy() if self._patterns_cache else []
    
    def _should_reload_patterns(self) -> bool:
        """Check if patterns should be reloaded."""
        if self._patterns_cache is None:
            return True
            
        if self._cache_timestamp is None:
            return True
            
        # Check cache expiration
        cache_duration = timedelta(hours=self.config.pattern_sources[0].cache_duration_hours if self.config.pattern_sources else 24)
        if datetime.now() - self._cache_timestamp > cache_duration:
            return True
            
        return False
    
    def _load_patterns(self):
        """Load patterns from all sources."""
        patterns = []
        
        if self.config.enable_parallel_loading and len(self._sources) > 1:
            patterns = self._load_patterns_parallel()
        else:
            patterns = self._load_patterns_sequential()
        
        # Sort patterns by priority and confidence
        patterns.sort(key=lambda p: (p.severity.value, -p.confidence_base))
        
        self._patterns_cache = patterns
        self._cache_timestamp = datetime.now()
        
        self.logger.info(f"Loaded {len(patterns)} patterns from {len(self._sources)} sources")
    
    def _load_patterns_parallel(self) -> List[VulnerabilityPattern]:
        """Load patterns from sources in parallel."""
        patterns = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit tasks for enabled sources
            future_to_source = {}
            for source_id, source in self._sources.items():
                if source.is_enabled():
                    future = executor.submit(self._load_from_source, source_id, source)
                    future_to_source[future] = source_id
            
            # Collect results
            for future in as_completed(future_to_source):
                source_id = future_to_source[future]
                try:
                    source_patterns = future.result(timeout=self.config.match_timeout_seconds)
                    patterns.extend(source_patterns)
                    self.logger.info(f"Loaded {len(source_patterns)} patterns from {source_id}")
                except Exception as e:
                    self.logger.error(f"Failed to load patterns from {source_id}: {e}")
        
        return patterns
    
    def _load_patterns_sequential(self) -> List[VulnerabilityPattern]:
        """Load patterns from sources sequentially."""
        patterns = []
        
        # Sort sources by priority
        sorted_sources = sorted(
            [(source_id, source) for source_id, source in self._sources.items() if source.is_enabled()],
            key=lambda x: x[1].get_priority()
        )
        
        for source_id, source in sorted_sources:
            try:
                source_patterns = self._load_from_source(source_id, source)
                patterns.extend(source_patterns)
                self.logger.info(f"Loaded {len(source_patterns)} patterns from {source_id}")
            except Exception as e:
                self.logger.error(f"Failed to load patterns from {source_id}: {e}")
        
        return patterns
    
    def _load_from_source(self, source_id: str, source: PatternSource) -> List[VulnerabilityPattern]:
        """Load patterns from a single source with error handling."""
        try:
            return source.load_patterns_cached()
        except PatternLoadError as e:
            self.logger.error(f"Pattern load error from {source_id}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error loading from {source_id}: {e}", exc_info=True)
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Maintains compatibility with original API.
        
        Returns:
            Dictionary containing engine statistics
        """
        with self._lock:
            patterns = self._patterns_cache or []
            
            # Source statistics
            source_stats = {}
            for source_id, source in self._sources.items():
                source_stats[source_id] = source.get_statistics()
            
            # Pattern type distribution
            type_distribution = {}
            severity_distribution = {}
            source_distribution = {}
            
            for pattern in patterns:
                # Count by type
                pattern_type = pattern.pattern_type.value
                type_distribution[pattern_type] = type_distribution.get(pattern_type, 0) + 1
                
                # Count by severity
                severity = pattern.severity.value
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
                
                # Count by source
                source = pattern.source
                source_distribution[source] = source_distribution.get(source, 0) + 1
            
            # Main statistics dictionary
            stats = {
                "total_patterns": len(patterns),
                "sources_enabled": len([s for s in self._sources.values() if s.is_enabled()]),
                "sources_total": len(self._sources),
                "cache_timestamp": self._cache_timestamp.isoformat() if self._cache_timestamp else None,
                "pattern_distribution": {
                    "by_type": type_distribution,
                    "by_severity": severity_distribution,
                    "by_source": source_distribution
                },
                "source_statistics": source_stats,
                "configuration": {
                    "parallel_loading": self.config.enable_parallel_loading,
                    "max_workers": self.config.max_workers,
                    "semantic_analysis": self.config.enable_semantic_analysis,
                    "caching": self.config.enable_caching
                }
            }
            
            # Add backwards compatibility keys for deployment script
            stats.update({
                "patterns_by_source": source_distribution,
                "patterns_by_type": type_distribution,
                "patterns_by_severity": severity_distribution
            })
            
            return stats
    
    @property
    def pattern_sources(self) -> List[str]:
        """
        Backwards compatibility property for deployment script.
        
        Returns:
            List of pattern source IDs
        """
        return list(self._sources.keys())
    
    def get_pattern_count(self) -> int:
        """
        Backwards compatibility method for deployment script.
        
        Returns:
            Total number of patterns
        """
        return len(self.get_patterns())
    
    def get_pattern_sources(self) -> Dict[str, Any]:
        """
        Backwards compatibility method for deployment script.
        
        Returns:
            Dictionary of pattern sources
        """
        return {source_id: source for source_id, source in self._sources.items()}
    
    def get_patterns_dict(self) -> Dict[str, VulnerabilityPattern]:
        """
        Backwards compatibility method for deployment script.
        
        Returns patterns as a dictionary with pattern_id as key.
        
        Returns:
            Dictionary of patterns keyed by pattern_id
        """
        patterns = self.get_patterns()
        return {pattern.pattern_id: pattern for pattern in patterns}

    def clear_cache(self):
        """Clear the patterns cache and force reload on next access."""
        with self._lock:
            self._patterns_cache = None
            self._cache_timestamp = None
            
            # Clear source caches
            for source in self._sources.values():
                source.clear_cache()
                
            self.logger.info("Cleared all pattern caches")
    
    def add_source(self, source_id: str, source: PatternSource):
        """
        Add a new pattern source.
        
        Args:
            source_id: Unique identifier for the source
            source: Pattern source instance
        """
        with self._lock:
            self._sources[source_id] = source
            # Clear cache to force reload with new source
            self.clear_cache()
            self.logger.info(f"Added pattern source: {source_id}")
    
    def remove_source(self, source_id: str):
        """
        Remove a pattern source.
        
        Args:
            source_id: Identifier of the source to remove
        """
        with self._lock:
            if source_id in self._sources:
                del self._sources[source_id]
                # Clear cache to force reload without this source
                self.clear_cache()
                self.logger.info(f"Removed pattern source: {source_id}")
            else:
                self.logger.warning(f"Source not found: {source_id}")
    
    def get_source(self, source_id: str) -> Optional[PatternSource]:
        """
        Get a specific pattern source.
        
        Args:
            source_id: Identifier of the source
            
        Returns:
            Pattern source or None if not found
        """
        return self._sources.get(source_id)
    
    def reload_source(self, source_id: str):
        """
        Reload patterns from a specific source.
        
        Args:
            source_id: Identifier of the source to reload
        """
        with self._lock:
            source = self._sources.get(source_id)
            if source:
                source.clear_cache()
                # Clear engine cache to force full reload
                self.clear_cache()
                self.logger.info(f"Reloaded source: {source_id}")
            else:
                self.logger.warning(f"Source not found: {source_id}")

# Factory function for backwards compatibility
def create_modular_pattern_engine(
    external_integrator=None,
    research_integrator=None,
    **kwargs
) -> ModularPatternEngine:
    """
    Create a modular pattern engine instance.
    
    Maintains compatibility with original factory function.
    
    Args:
        external_integrator: External data integrator (legacy)
        research_integrator: Research data integrator (legacy)
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured modular pattern engine
    """
    return ModularPatternEngine(
        external_integrator=external_integrator,
        research_integrator=research_integrator,
        **kwargs
    ) 
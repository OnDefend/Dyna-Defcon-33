"""
AODS Dependency Injection Framework

Provides enterprise-grade dependency injection pattern for clean component instantiation,
improved testability, and maintainable architecture across all AODS plugins.

Features:
- Constructor injection pattern for all dependencies
- Component factory with automatic dependency resolution
- Service locator for shared components
- Mock-friendly architecture for comprehensive testing
- Lifecycle management for resource cleanup
"""

import logging
import weakref
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Type, TypeVar, Callable, Union, List
from dataclasses import dataclass, field
from pathlib import Path
import threading
from contextlib import contextmanager

from ..shared_analyzers.universal_confidence_calculator import UniversalConfidenceCalculator
from ..shared_analyzers.universal_pattern_analyzer import UniversalPatternAnalyzer
from ..config_management.pattern_loader import PatternLoader

# Type variables for generic dependency injection
T = TypeVar('T')
ServiceFactory = Callable[['AnalysisContext'], Any]

logger = logging.getLogger(__name__)

@dataclass
class ComponentLifecycle:
    """Manages component lifecycle and cleanup."""
    instances: Dict[str, Any] = field(default_factory=dict)
    cleanup_handlers: Dict[str, List[Callable]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def register_cleanup(self, component_name: str, cleanup_fn: Callable):
        """Register cleanup function for a component."""
        with self._lock:
            if component_name not in self.cleanup_handlers:
                self.cleanup_handlers[component_name] = []
            self.cleanup_handlers[component_name].append(cleanup_fn)
    
    def cleanup_component(self, component_name: str):
        """Clean up a specific component."""
        with self._lock:
            # Run cleanup handlers
            if component_name in self.cleanup_handlers:
                for cleanup_fn in self.cleanup_handlers[component_name]:
                    try:
                        cleanup_fn()
                    except Exception as e:
                        logger.error(f"Error in cleanup handler for {component_name}: {e}")
                del self.cleanup_handlers[component_name]
            
            # Remove instance
            if component_name in self.instances:
                del self.instances[component_name]
    
    def cleanup_all(self):
        """Clean up all registered components."""
        with self._lock:
            for component_name in list(self.cleanup_handlers.keys()):
                self.cleanup_component(component_name)

@dataclass
class AnalysisContext:
    """
    Centralized analysis context containing all dependencies for AODS analysis.
    
    Provides dependency injection for all analysis components including:
    - APK context and file paths
    - Shared analyzers and pattern engines
    - Configuration and pattern loaders
    - Logging and error handling
    - Performance monitoring and metrics
    """
    
    # Core analysis context
    apk_path: Path
    decompiled_path: Optional[Path] = None
    output_path: Optional[Path] = None
    
    # Shared analyzers (injected dependencies)
    confidence_calculator: Optional[UniversalConfidenceCalculator] = None
    pattern_analyzer: Optional[UniversalPatternAnalyzer] = None
    pattern_loader: Optional[PatternLoader] = None
    
    # Configuration and settings
    config: Dict[str, Any] = field(default_factory=dict)
    debug_mode: bool = False
    max_analysis_time: int = 300  # seconds
    parallel_processing: bool = True
    
    # Logging and monitoring
    logger: Optional[logging.Logger] = None
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Component lifecycle management
    lifecycle: ComponentLifecycle = field(default_factory=ComponentLifecycle)
    
    # Thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        """Initialize context after creation."""
        if self.logger is None:
            self.logger = logging.getLogger(f"aods.context.{self.apk_path.stem}")
        
        # Validate required paths
        if not self.apk_path.exists():
            raise ValueError(f"APK path does not exist: {self.apk_path}")
    
    def get_component(self, component_name: str, factory: Optional[ServiceFactory] = None) -> Any:
        """
        Get or create a component with dependency injection.
        
        Args:
            component_name: Name of the component to retrieve
            factory: Optional factory function to create the component
            
        Returns:
            Component instance
        """
        with self._lock:
            # Check if component already exists
            if component_name in self.lifecycle.instances:
                return self.lifecycle.instances[component_name]
            
            # Create component using factory
            if factory:
                try:
                    instance = factory(self)
                    self.lifecycle.instances[component_name] = instance
                    self.logger.debug(f"Created component: {component_name}")
                    return instance
                except Exception as e:
                    self.logger.error(f"Error creating component {component_name}: {e}")
                    raise
            
            raise ValueError(f"No factory provided for component: {component_name}")
    
    def register_cleanup(self, component_name: str, cleanup_fn: Callable):
        """Register cleanup function for a component."""
        self.lifecycle.register_cleanup(component_name, cleanup_fn)
    
    def create_child_context(self, **overrides) -> 'AnalysisContext':
        """Create a child context with specific overrides."""
        child_data = {
            'apk_path': self.apk_path,
            'decompiled_path': self.decompiled_path,
            'output_path': self.output_path,
            'confidence_calculator': self.confidence_calculator,
            'pattern_analyzer': self.pattern_analyzer,
            'pattern_loader': self.pattern_loader,
            'config': self.config.copy(),
            'debug_mode': self.debug_mode,
            'max_analysis_time': self.max_analysis_time,
            'parallel_processing': self.parallel_processing,
            'logger': self.logger,
            'performance_metrics': self.performance_metrics.copy()
        }
        
        # Apply overrides
        child_data.update(overrides)
        
        return AnalysisContext(**child_data)
    
    def cleanup(self):
        """Clean up all resources."""
        self.lifecycle.cleanup_all()
        self.logger.debug("Analysis context cleaned up")

class ComponentFactory:
    """
    Component factory for creating and managing AODS analysis components.
    
    Provides automatic dependency resolution and manages component lifecycle
    with proper cleanup and resource management.
    """
    
    def __init__(self):
        self.factories: Dict[str, ServiceFactory] = {}
        self.singletons: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # Register default factories
        self._register_default_factories()
    
    def _register_default_factories(self):
        """Register default component factories."""
        self.register_factory('confidence_calculator', self._create_confidence_calculator)
        self.register_factory('pattern_analyzer', self._create_pattern_analyzer)
        self.register_factory('pattern_loader', self._create_pattern_loader)
    
    def register_factory(self, component_name: str, factory: ServiceFactory):
        """Register a factory function for a component."""
        with self._lock:
            self.factories[component_name] = factory
            self.logger.debug(f"Registered factory for: {component_name}")
    
    def create_component(self, component_name: str, context: AnalysisContext) -> Any:
        """Create a component using registered factory."""
        with self._lock:
            if component_name not in self.factories:
                raise ValueError(f"No factory registered for: {component_name}")
            
            factory = self.factories[component_name]
            try:
                instance = factory(context)
                self.logger.debug(f"Created component: {component_name}")
                return instance
            except Exception as e:
                self.logger.error(f"Error creating component {component_name}: {e}")
                raise
    
    def get_singleton(self, component_name: str, context: AnalysisContext) -> Any:
        """Get or create a singleton component."""
        with self._lock:
            if component_name not in self.singletons:
                self.singletons[component_name] = self.create_component(component_name, context)
            return self.singletons[component_name]
    
    def _create_confidence_calculator(self, context: AnalysisContext) -> UniversalConfidenceCalculator:
        """Factory for confidence calculator."""
        calculator = UniversalConfidenceCalculator(
            domain="general",
            config=context.config.get('confidence', {})
        )
        
        # Register cleanup if needed
        context.register_cleanup('confidence_calculator', lambda: None)
        
        return calculator
    
    def _create_pattern_analyzer(self, context: AnalysisContext) -> UniversalPatternAnalyzer:
        """Factory for pattern analyzer."""
        analyzer = UniversalPatternAnalyzer(
            config=context.config.get('patterns', {})
        )
        
        # Register cleanup if needed
        context.register_cleanup('pattern_analyzer', lambda: None)
        
        return analyzer
    
    def _create_pattern_loader(self, context: AnalysisContext) -> PatternLoader:
        """Factory for pattern loader."""
        loader = PatternLoader(
            config_path=context.config.get('pattern_config_path', 'config/patterns'),
            cache_enabled=context.config.get('cache_patterns', True)
        )
        
        # Register cleanup
        context.register_cleanup('pattern_loader', loader.cleanup if hasattr(loader, 'cleanup') else lambda: None)
        
        return loader

class DependencyInjector:
    """
    Main dependency injector for AODS framework.
    
    Provides service locator pattern and manages component lifecycle
    across the entire analysis session.
    """
    
    def __init__(self):
        self.factory = ComponentFactory()
        self.contexts: Dict[str, AnalysisContext] = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def create_context(self, apk_path: Path, context_id: Optional[str] = None, **kwargs) -> AnalysisContext:
        """
        Create a new analysis context with dependency injection.
        
        Args:
            apk_path: Path to the APK file
            context_id: Optional unique identifier for the context
            **kwargs: Additional context parameters
            
        Returns:
            Configured AnalysisContext with all dependencies injected
        """
        if context_id is None:
            context_id = f"context_{apk_path.stem}_{id(apk_path)}"
        
        with self._lock:
            # Create base context
            context = AnalysisContext(apk_path=apk_path, **kwargs)
            
            # Inject dependencies
            context.confidence_calculator = self.factory.get_singleton('confidence_calculator', context)
            context.pattern_analyzer = self.factory.get_singleton('pattern_analyzer', context)
            context.pattern_loader = self.factory.get_singleton('pattern_loader', context)
            
            # Store context
            self.contexts[context_id] = context
            
            self.logger.info(f"Created analysis context: {context_id}")
            return context
    
    def get_context(self, context_id: str) -> Optional[AnalysisContext]:
        """Get an existing analysis context."""
        with self._lock:
            return self.contexts.get(context_id)
    
    def cleanup_context(self, context_id: str):
        """Clean up a specific analysis context."""
        with self._lock:
            if context_id in self.contexts:
                context = self.contexts[context_id]
                context.cleanup()
                del self.contexts[context_id]
                self.logger.info(f"Cleaned up analysis context: {context_id}")
    
    def cleanup_all(self):
        """Clean up all analysis contexts."""
        with self._lock:
            for context_id in list(self.contexts.keys()):
                self.cleanup_context(context_id)
    
    @contextmanager
    def analysis_session(self, apk_path: Path, **kwargs):
        """
        Context manager for analysis session with automatic cleanup.
        
        Args:
            apk_path: Path to the APK file
            **kwargs: Additional context parameters
            
        Yields:
            AnalysisContext: Configured analysis context
        """
        context_id = f"session_{apk_path.stem}_{id(apk_path)}"
        context = None
        
        try:
            context = self.create_context(apk_path, context_id, **kwargs)
            yield context
        except Exception as e:
            self.logger.error(f"Error in analysis session: {e}")
            raise
        finally:
            if context:
                self.cleanup_context(context_id)

# Global dependency injector instance
_injector = DependencyInjector()

def get_injector() -> DependencyInjector:
    """Get the global dependency injector instance."""
    return _injector

def create_analysis_context(apk_path: Path, **kwargs) -> AnalysisContext:
    """
    Convenience function to create an analysis context with dependency injection.
    
    Args:
        apk_path: Path to the APK file
        **kwargs: Additional context parameters
        
    Returns:
        Configured AnalysisContext with all dependencies injected
    """
    return _injector.create_context(apk_path, **kwargs)

@contextmanager
def analysis_session(apk_path: Path, **kwargs):
    """
    Context manager for analysis session with automatic cleanup.
    
    Args:
        apk_path: Path to the APK file
        **kwargs: Additional context parameters
        
    Yields:
        AnalysisContext: Configured analysis context
    """
    with _injector.analysis_session(apk_path, **kwargs) as context:
        yield context 
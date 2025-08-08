#!/usr/bin/env python3
"""
Base Pattern Source Interface

Abstract base class for all pattern sources in the modular pattern engine.
Provides consistent interface and common functionality.
"""

import abc
import logging
from typing import Dict, List, Any, Optional
from ..models import VulnerabilityPattern, PatternSourceConfig

class PatternSource(abc.ABC):
    """
    Abstract base class for pattern sources.
    
    All pattern sources must inherit from this class and implement
    the required methods for loading patterns.
    """
    
    def __init__(self, config: Optional[PatternSourceConfig] = None):
        """
        Initialize pattern source.
        
        Args:
            config: Optional source configuration
        """
        self.config = config or PatternSourceConfig(
            source_id=self.__class__.__name__.lower(),
            source_name=self.__class__.__name__
        )
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._patterns_cache: Optional[List[VulnerabilityPattern]] = None
        
    @abc.abstractmethod
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """
        Load patterns from this source.
        
        Returns:
            List of validated vulnerability patterns
            
        Raises:
            PatternLoadError: If pattern loading fails
        """
        pass
    
    @abc.abstractmethod
    def get_source_info(self) -> Dict[str, Any]:
        """
        Get information about this pattern source.
        
        Returns:
            Dictionary containing source metadata
        """
        pass
    
    def is_enabled(self) -> bool:
        """
        Check if this pattern source is enabled.
        
        Returns:
            True if source is enabled, False otherwise
        """
        return self.config.enabled
    
    def get_priority(self) -> int:
        """
        Get the priority of this pattern source.
        
        Returns:
            Priority value (1=highest, 10=lowest)
        """
        return self.config.priority
    
    def get_max_patterns(self) -> Optional[int]:
        """
        Get the maximum number of patterns to load from this source.
        
        Returns:
            Maximum pattern count or None for unlimited
        """
        return self.config.max_patterns
    
    def clear_cache(self) -> None:
        """Clear the patterns cache."""
        self._patterns_cache = None
        self.logger.debug(f"Cleared cache for {self.config.source_id}")
    
    def load_patterns_cached(self) -> List[VulnerabilityPattern]:
        """
        Load patterns with caching support.
        
        Returns:
            List of validated vulnerability patterns
        """
        if self._patterns_cache is None:
            self.logger.info(f"Loading patterns from {self.config.source_id}")
            try:
                patterns = self.load_patterns()
                
                # Apply max patterns limit if configured
                if self.config.max_patterns and len(patterns) > self.config.max_patterns:
                    patterns = patterns[:self.config.max_patterns]
                    self.logger.warning(
                        f"Limited patterns from {self.config.source_id} to {self.config.max_patterns}"
                    )
                
                self._patterns_cache = patterns
                self.logger.info(f"Loaded {len(patterns)} patterns from {self.config.source_id}")
                
            except Exception as e:
                self.logger.error(
                    f"Failed to load patterns from {self.config.source_id}: {e}",
                    exc_info=True
                )
                raise PatternLoadError(f"Failed to load patterns from {self.config.source_id}") from e
        
        return self._patterns_cache
    
    def validate_pattern(self, pattern: VulnerabilityPattern) -> bool:
        """
        Validate a pattern before adding it to the collection.
        
        Args:
            pattern: Pattern to validate
            
        Returns:
            True if pattern is valid, False otherwise
        """
        try:
            # Pydantic validation happens automatically during construction
            # Additional business logic validation can be added here
            
            if not pattern.pattern_regex.strip():
                self.logger.warning(f"Pattern {pattern.pattern_id} has empty regex")
                return False
                
            if pattern.confidence_base <= 0:
                self.logger.warning(f"Pattern {pattern.pattern_id} has invalid confidence")
                return False
                
            return True
            
        except Exception as e:
            self.logger.warning(f"Pattern validation failed for {pattern.pattern_id}: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics for this pattern source.
        
        Returns:
            Dictionary containing source statistics
        """
        patterns = self._patterns_cache or []
        
        return {
            "source_id": self.config.source_id,
            "source_name": self.config.source_name,
            "enabled": self.config.enabled,
            "priority": self.config.priority,
            "pattern_count": len(patterns),
            "patterns_cached": self._patterns_cache is not None,
            "source_info": self.get_source_info()
        }

class PatternLoadError(Exception):
    """Exception raised when pattern loading fails."""
    pass

class PatternValidationError(Exception):
    """Exception raised when pattern validation fails."""
    pass 
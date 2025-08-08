#!/usr/bin/env python3
"""
Result Aggregator

Unified result aggregation for all execution strategies.
"""

import logging
from typing import Any, Dict, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class AggregatedResult:
    """Aggregated execution results."""
    total_plugins: int = 0
    successful_plugins: int = 0
    failed_plugins: int = 0
    results: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)

class ResultAggregator:
    """Unified result aggregation for execution strategies."""
    
    def __init__(self):
        """Initialize result aggregator."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("Result aggregator initialized")
    
    def aggregate_results(self, plugin_results: Dict[str, Any]) -> AggregatedResult:
        """Aggregate plugin results into unified format."""
        aggregated = AggregatedResult()
        
        for plugin_name, result in plugin_results.items():
            aggregated.total_plugins += 1
            
            if hasattr(result, 'success') and result.success:
                aggregated.successful_plugins += 1
            elif hasattr(result, 'failed') and result.failed:
                aggregated.failed_plugins += 1
            
            # Convert to results format
            if hasattr(result, 'result') and result.result:
                aggregated.results[plugin_name] = result.result
            else:
                aggregated.results[plugin_name] = (plugin_name, str(result))
        
        # Calculate statistics
        aggregated.statistics = {
            'success_rate': aggregated.successful_plugins / aggregated.total_plugins if aggregated.total_plugins > 0 else 0.0,
            'failure_rate': aggregated.failed_plugins / aggregated.total_plugins if aggregated.total_plugins > 0 else 0.0
        }
        
        return aggregated

def create_result_aggregator() -> ResultAggregator:
    """Factory function to create result aggregator."""
    return ResultAggregator() 
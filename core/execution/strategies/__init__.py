#!/usr/bin/env python3
"""
Execution Strategies Module

Different execution strategies for unified framework without code duplication.
"""

from .base_strategy import ExecutionStrategy
from .parallel_strategy import ParallelExecutionStrategy
from .sequential_strategy import SequentialExecutionStrategy
from .process_strategy import ProcessSeparationStrategy
from .adaptive_strategy import AdaptiveExecutionStrategy

__all__ = [
    'ExecutionStrategy',
    'ParallelExecutionStrategy',
    'SequentialExecutionStrategy',
    'ProcessSeparationStrategy',
    'AdaptiveExecutionStrategy'
] 
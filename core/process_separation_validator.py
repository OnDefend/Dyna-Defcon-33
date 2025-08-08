#!/usr/bin/env python3
"""
Process Separation Validator
Ensures static and dynamic analysis run in truly separate processes
"""

import multiprocessing as mp
import os
import time
from typing import Dict, Any, Optional

class ProcessSeparationValidator:
    """Validates that processes are properly separated."""
    
    def __init__(self):
        self.process_registry = {}
    
    def register_process(self, process_type: str, process_id: int) -> None:
        """Register a process for monitoring."""
        self.process_registry[process_type] = {
            'pid': process_id,
            'start_time': time.time(),
            'parent_pid': os.getppid()
        }
    
    def validate_separation(self) -> Dict[str, Any]:
        """Validate that processes are properly separated."""
        if len(self.process_registry) < 2:
            return {
                'separated': False,
                'reason': 'Insufficient processes registered',
                'process_count': len(self.process_registry)
            }
        
        pids = [info['pid'] for info in self.process_registry.values()]
        
        # Check if all PIDs are different
        if len(set(pids)) != len(pids):
            return {
                'separated': False,
                'reason': 'Duplicate PIDs detected',
                'pids': pids
            }
        
        return {
            'separated': True,
            'reason': f'{len(self.process_registry)} processes running separately',
            'processes': list(self.process_registry.keys()),
            'pids': pids
        }

# Global validator instance
process_validator = ProcessSeparationValidator()

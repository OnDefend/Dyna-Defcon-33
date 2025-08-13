"""
Runtime Hooks Package

This package provides the core runtime instrumentation functionality for 
true dynamic analysis using Frida JavaScript hooks.

Components:
- RuntimeHookEngine: Core engine for executing and managing runtime hooks
- JavaScript hook scripts: Crypto, network, and storage monitoring scripts

Author: AODS Team
Date: January 2025
"""

from .hook_engine import RuntimeHookEngine, RuntimeHookResult, HookStatus

__all__ = [
    'RuntimeHookEngine',
    'RuntimeHookResult', 
    'HookStatus'
]

__version__ = '1.0.0'
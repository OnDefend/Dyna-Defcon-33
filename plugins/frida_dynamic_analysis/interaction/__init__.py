#!/usr/bin/env python3
"""
AODS App Interaction Framework

Automated app interaction engine for systematic feature exercise
and vulnerability scenario triggering during runtime analysis.

Author: AODS Team
Date: January 2025
"""

from .app_automator import AppAutomationFramework
from .ui_patterns import UIInteractionPatterns

__all__ = [
    'AppAutomationFramework',
    'UIInteractionPatterns'
]
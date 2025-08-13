#!/usr/bin/env python3
"""
AODS Objection Integration - Complementary Interactive Testing

Provides strategic integration of objection toolkit with AODS automated analysis
for enhanced reconnaissance, verification, training, and development support.

Author: AODS Team
Date: January 2025
"""

from typing import Dict, Any
import logging
from core.apk_ctx import APKContext
from .reconnaissance_module import ObjectionReconnaissanceModule
from .verification_assistant import ObjectionVerificationAssistant  
from .training_module import ObjectionTrainingModule
from .dev_testing_module import ObjectionDevelopmentTesting

logger = logging.getLogger(__name__)

class ObjectionIntegrationPlugin:
    """Main plugin class for Objection integration with AODS."""
    
    def __init__(self):
        """Initialize the Objection integration plugin."""
        self.reconnaissance = ObjectionReconnaissanceModule()
        self.verification = ObjectionVerificationAssistant()
        self.training = ObjectionTrainingModule()
        self.dev_testing = ObjectionDevelopmentTesting()
        self.logger = logger
    
    def analyze(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform Objection integration analysis.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing Objection integration results
        """
        try:
            self.logger.info("Starting Objection integration analysis")
            
            results = {
                "plugin_name": "objection_integration",
                "version": "1.0.0",
                "reconnaissance_ready": True,
                "verification_ready": True,
                "training_ready": True,
                "dev_testing_ready": True,
                "objection_available": self._check_objection_availability(),
                "integration_status": "functional",
                "vulnerabilities": []
            }
            
            # Note: This plugin provides integration framework
            # Actual objection execution is handled in scan workflow
            self.logger.info("✅ Objection integration framework ready")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Objection integration analysis failed: {e}")
            return {
                "plugin_name": "objection_integration",
                "error": str(e),
                "integration_status": "failed",
                "vulnerabilities": []
            }
    
    def _check_objection_availability(self) -> bool:
        """Check if objection binary is available."""
        try:
            import subprocess
            result = subprocess.run(['objection', '--version'], 
                                 capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

# Plugin metadata for AODS integration
PLUGIN_INFO = {
    "name": "objection_integration",
    "version": "1.0.0",
    "description": "Objection integration framework for interactive testing",
    "author": "AODS Team",
    "category": "INTEGRATION",
    "tags": ["objection", "interactive", "verification", "training"],
    "requires_dynamic": False,
    "supports_dynamic": True,
    "priority": "LOW"  # Framework plugin, doesn't contribute findings directly
}

def run(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    AODS-compatible run function for Objection integration.
    
    This is the main entry point that AODS calls for this plugin.
    
    Args:
        apk_ctx: The APK context for analysis
        
    Returns:
        Dictionary containing Objection integration status
    """
    plugin = ObjectionIntegrationPlugin()
    return plugin.analyze(apk_ctx)

def create_plugin():
    """Factory function to create plugin instance."""
    return ObjectionIntegrationPlugin()

__all__ = [
    'ObjectionReconnaissanceModule',
    'ObjectionVerificationAssistant', 
    'ObjectionTrainingModule',
    'ObjectionDevelopmentTesting',
    'ObjectionIntegrationPlugin',
    'run',
    'create_plugin'
]
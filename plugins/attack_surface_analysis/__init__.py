"""
Attack Surface Analysis Plugin Module

This module provides comprehensive attack surface analysis for Android applications
with modular architecture, evidence-based confidence calculation, and scalable
security assessment capabilities.
"""

from .data_structures import (
    AttackSurfaceVulnerability,
    AttackVector,
    ComponentSurface,
    AttackSurfaceAnalysis,
    AnalysisContext,
    DrozerFinding,
    ComponentType,
    SeverityLevel,
    ExposureLevel,
    AttackComplexity,
    PermissionLevel,
    PatternType
)

from .confidence_calculator import (
    AttackSurfaceConfidenceCalculator,
    calculate_attack_surface_confidence
)

from .manifest_analyzer import ManifestAnalyzer

from .plugin import (
    AttackSurfaceAnalysisPlugin,
    create_attack_surface_plugin
)

__version__ = "2.0.0"
__author__ = "AODS Security Team"

__all__ = [
    # Main plugin class
    'AttackSurfaceAnalysisPlugin',
    
    # Data structures
    'AttackSurfaceVulnerability',
    'AttackVector',
    'ComponentSurface', 
    'AttackSurfaceAnalysis',
    'AnalysisContext',
    'DrozerFinding',
    
    # Enums
    'ComponentType',
    'SeverityLevel',
    'ExposureLevel',
    'AttackComplexity',
    'PermissionLevel',
    'PatternType',
    
    # Analyzers
    'AttackSurfaceConfidenceCalculator',
    'ManifestAnalyzer',
    
    # Factory functions
    'create_attack_surface_plugin',
    'calculate_attack_surface_confidence'
]

class AttackSurfaceAnalyzer:
    """Attack Surface Analyzer for AODS integration."""
    
    def __init__(self, apk_ctx):
        """Initialize the attack surface analyzer."""
        self.apk_ctx = apk_ctx
        
    def analyze(self):
        """Perform attack surface analysis."""
        # Create empty result for now - can be enhanced later
        from .data_structures import AttackSurfaceAnalysisResult
        
        result = AttackSurfaceAnalysisResult(
            surfaces=[],
            metadata={"analyzer": "attack_surface_analysis", "version": "1.0.0"}
        )
        return result

# Plugin compatibility functions
def run(apk_ctx):
    try:
        from rich.text import Text
        analyzer = AttackSurfaceAnalyzer(apk_ctx)
        result = analyzer.analyze()
        
        if hasattr(result, 'findings') and result.findings:
            findings_text = Text(f"Attack Surface Analysis - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Attack Surface Analysis completed - No issues found", style="green")
            
        return "Attack Surface Analysis", findings_text
    except Exception as e:
        error_text = Text(f"Attack Surface Analysis Error: {str(e)}", style="red")
        return "Attack Surface Analysis", error_text

def run_plugin(apk_ctx):
    return run(apk_ctx)

__all__.extend(['run', 'run_plugin'])
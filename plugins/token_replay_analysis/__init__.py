"""
Token Replay Analysis Plugin Module

This module provides comprehensive token security analysis for Android applications
with modular architecture, professional confidence calculation, and enterprise-grade
token vulnerability detection capabilities.
"""

from .data_structures import (
    TokenInfo,
    JWTAnalysis,
    SessionAnalysis,
    TokenReplayVulnerability,
    TokenExpiryIssue,
    WeakTokenIssue,
    TokenSecurityAnalysisResult,
    TokenAnalysisContext,
    TokenType,
    TokenStrength,
    TokenVulnerabilityType,
    SessionSecurityLevel,
    JWTVulnerabilityType,
    TokenPatterns,
    MAVSAuthControls,
    CWEAuthCategories,
    TokenWeaknessPatterns
)

from .confidence_calculator import (
    TokenSecurityConfidenceCalculator,
    calculate_token_security_confidence
)

__version__ = "2.0.0"
__author__ = "AODS Security Team"

__all__ = [
    # Data structures
    'TokenInfo',
    'JWTAnalysis',
    'SessionAnalysis',
    'TokenReplayVulnerability',
    'TokenExpiryIssue',
    'WeakTokenIssue',
    'TokenSecurityAnalysisResult',
    'TokenAnalysisContext',
    
    # Enums
    'TokenType',
    'TokenStrength',
    'TokenVulnerabilityType',
    'SessionSecurityLevel',
    'JWTVulnerabilityType',
    'TokenPatterns',
    'MAVSAuthControls',
    'CWEAuthCategories',
    'TokenWeaknessPatterns',
    
    # Analyzers
    'TokenSecurityConfidenceCalculator',
    
    # Utility functions
    'calculate_token_security_confidence'
] 

# Plugin compatibility functions
def run(apk_ctx):
    """Main plugin entry point for compatibility with plugin manager."""
    try:
        from rich.text import Text
        analyzer = TokenReplayAnalyzer(apk_ctx)
        result = analyzer.analyze()
        
        if hasattr(result, 'findings') and result.findings:
            findings_text = Text()
            findings_text.append(f"Token Replay Analysis - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Token Replay Analysis completed - No issues found", style="green")
            
        return "Token Replay Analysis", findings_text
    except Exception as e:
        error_text = Text(f"Token Replay Analysis Error: {str(e)}", style="red")
        return "Token Replay Analysis", error_text

def run_plugin(apk_ctx):
    return run(apk_ctx)

__all__.extend(['run', 'run_plugin']) 
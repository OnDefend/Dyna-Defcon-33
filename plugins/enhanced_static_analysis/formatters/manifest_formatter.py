"""
Manifest Analysis Formatter

This module handles the formatting of AndroidManifest.xml analysis results.
"""

import logging
from typing import Dict, List, Any

from rich.text import Text

logger = logging.getLogger(__name__)

class ManifestAnalysisFormatter:
    """
    Formatter for AndroidManifest.xml analysis results.
    
    Provides rich formatting for manifest analysis in reports.
    """
    
    def __init__(self):
        """Initialize the manifest analysis formatter."""
        self.risk_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
    
    def format_manifest_analysis(self, manifest_data: Dict[str, Any]) -> Text:
        """
        Format manifest analysis results for display.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Text: Formatted manifest analysis
        """
        if not manifest_data or "error" in manifest_data:
            return Text("❌ AndroidManifest.xml analysis failed\n", style="red")
        
        logger.info("Formatting AndroidManifest.xml analysis results")
        
        manifest_text = Text()
        manifest_text.append("📱 AndroidManifest.xml Analysis\n", style="bold cyan")
        
        # Security features
        security_features = manifest_data.get("security_features", {})
        if security_features:
            manifest_text.append(self._format_security_features(security_features))
        
        # Permission analysis
        permission_analysis = manifest_data.get("permission_analysis", {})
        if permission_analysis:
            manifest_text.append(self._format_permission_analysis(permission_analysis))
        
        # Component analysis
        component_analysis = manifest_data.get("component_analysis", {})
        if component_analysis:
            manifest_text.append(self._format_component_analysis(component_analysis))
        
        # Risk assessment
        risk_assessment = manifest_data.get("risk_assessment", {})
        if risk_assessment:
            manifest_text.append(self._format_risk_assessment(risk_assessment))
        
        manifest_text.append("\n")
        return manifest_text
    
    def _format_security_features(self, security_features: Dict[str, Any]) -> Text:
        """
        Format security features section.
        
        Args:
            security_features: Security features data
            
        Returns:
            Text: Formatted security features
        """
        section = Text()
        section.append("\nSecurity Configuration:\n", style="cyan")
        
        # Get security config from nested structure
        security_config = security_features.get("security_config", security_features)
        
        # Debuggable flag
        debuggable = security_config.get("debuggable", False)
        if debuggable:
            section.append("  ❌ App is debuggable (security risk)\n", style="red")
        else:
            section.append("  ✅ App is not debuggable\n", style="green")
        
        # Backup settings
        allow_backup = security_config.get("allow_backup", True)
        if allow_backup:
            section.append("  ⚠️ Backup is allowed (potential data exposure)\n", style="yellow")
        else:
            section.append("  ✅ Backup is disabled\n", style="green")
        
        # Cleartext traffic
        cleartext_traffic = security_config.get("uses_cleartext_traffic")
        if cleartext_traffic is True:
            section.append("  ❌ Cleartext traffic is explicitly allowed\n", style="red")
        elif cleartext_traffic is False:
            section.append("  ✅ Cleartext traffic is disabled\n", style="green")
        else:
            section.append("  ⚠️ Cleartext traffic setting not specified\n", style="yellow")
        
        # Target SDK
        target_sdk = security_config.get("target_sdk")
        if target_sdk:
            if target_sdk >= 30:
                section.append(f"  ✅ Target SDK: {target_sdk} (modern)\n", style="green")
            elif target_sdk >= 23:
                section.append(f"  ⚠️ Target SDK: {target_sdk} (acceptable)\n", style="yellow")
            else:
                section.append(f"  ❌ Target SDK: {target_sdk} (outdated)\n", style="red")
        
        # Test only flag
        test_only = security_config.get("test_only", False)
        if test_only:
            section.append("  ⚠️ App is marked as test-only\n", style="yellow")
        
        return section
    
    def _format_permission_analysis(self, permission_analysis: Dict[str, Any]) -> Text:
        """
        Format permission analysis section.
        
        Args:
            permission_analysis: Permission analysis data
            
        Returns:
            Text: Formatted permission analysis
        """
        section = Text()
        
        total_permissions = permission_analysis.get("total_permissions", 0)
        dangerous_permissions = permission_analysis.get("dangerous_permissions", [])
        
        section.append(f"\nPermission Analysis (Total: {total_permissions}):\n", style="cyan")
        
        # Dangerous permissions
        if dangerous_permissions:
            section.append(f"  ⚠️ Dangerous Permissions ({len(dangerous_permissions)}):\n", style="yellow")
            
            for i, perm in enumerate(dangerous_permissions[:5], 1):
                perm_name = perm.get("name", "Unknown")
                risk_level = perm.get("risk_level", "UNKNOWN")
                
                # Shorten permission name for display
                display_name = perm_name.replace("android.permission.", "")
                
                risk_color = self.risk_colors.get(risk_level, "yellow")
                section.append(f"    {i}. {display_name} ({risk_level})\n", style=risk_color)
            
            if len(dangerous_permissions) > 5:
                remaining = len(dangerous_permissions) - 5
                section.append(f"    ... and {remaining} more dangerous permissions\n", style="dim yellow")
        
        # Overprivileged assessment
        overprivileged = permission_analysis.get("overprivileged_assessment", {})
        if overprivileged:
            status = overprivileged.get("status", "UNKNOWN")
            reason = overprivileged.get("reason", "")
            
            if status == "HIGH_RISK":
                section.append(f"  🚨 Overprivileged: {reason}\n", style="red")
            elif status == "MEDIUM_RISK":
                section.append(f"  ⚠️ Potentially overprivileged: {reason}\n", style="yellow")
            else:
                section.append(f"  ✅ Permission usage appears reasonable\n", style="green")
        
        return section
    
    def _format_component_analysis(self, component_analysis: Dict[str, Any]) -> Text:
        """
        Format component analysis section.
        
        Args:
            component_analysis: Component analysis data
            
        Returns:
            Text: Formatted component analysis
        """
        section = Text()
        
        exported_components = component_analysis.get("exported_components", [])
        
        if exported_components:
            section.append(f"\nExported Components ({len(exported_components)}):\n", style="cyan")
            
            # Group by component type
            by_type = {}
            for comp in exported_components:
                comp_type = comp.get("type", "unknown")
                if comp_type not in by_type:
                    by_type[comp_type] = []
                by_type[comp_type].append(comp)
            
            for comp_type, components in by_type.items():
                section.append(f"  {comp_type.title()}s ({len(components)}):\n", style="yellow")
                
                for i, comp in enumerate(components[:3], 1):
                    comp_name = comp.get("name", "Unknown")
                    risk_level = comp.get("risk_level", "UNKNOWN")
                    has_intent_filter = comp.get("has_intent_filter", False)
                    
                    # Shorten component name for display
                    display_name = comp_name.split(".")[-1] if "." in comp_name else comp_name
                    
                    risk_color = self.risk_colors.get(risk_level, "yellow")
                    intent_indicator = " (intent filters)" if has_intent_filter else ""
                    
                    section.append(
                        f"    {i}. {display_name}{intent_indicator} ({risk_level})\n",
                        style=risk_color
                    )
                
                if len(components) > 3:
                    remaining = len(components) - 3
                    section.append(f"    ... and {remaining} more {comp_type}s\n", style="dim yellow")
        
        # Vulnerable components
        vulnerable_components = component_analysis.get("vulnerable_components", [])
        if vulnerable_components:
            section.append(f"\n🚨 Vulnerable Components ({len(vulnerable_components)}):\n", style="red")
            
            for i, vuln in enumerate(vulnerable_components[:3], 1):
                component = vuln.get("component", {})
                vulnerability = vuln.get("vulnerability", "Unknown vulnerability")
                risk_level = vuln.get("risk_level", "UNKNOWN")
                
                comp_name = component.get("name", "Unknown")
                comp_type = component.get("type", "unknown")
                
                display_name = comp_name.split(".")[-1] if "." in comp_name else comp_name
                
                section.append(
                    f"    {i}. {comp_type.title()}: {display_name}\n",
                    style="red"
                )
                section.append(f"       Issue: {vulnerability}\n", style="dim red")
        
        return section
    
    def _format_risk_assessment(self, risk_assessment) -> Text:
        """
        Format risk assessment section.
        
        Args:
            risk_assessment: Risk assessment data (dict or RiskAssessment object)
            
        Returns:
            Text: Formatted risk assessment
        """
        section = Text()
        
        # Handle both RiskAssessment objects and dictionaries
        if hasattr(risk_assessment, 'overall_risk'):
            # RiskAssessment dataclass object
            risk_level = risk_assessment.overall_risk.value if hasattr(risk_assessment.overall_risk, 'value') else str(risk_assessment.overall_risk)
            risk_score = risk_assessment.risk_score
            critical_issues = risk_assessment.critical_issues
            high_issues = risk_assessment.high_issues
            medium_issues = risk_assessment.medium_issues
            low_issues = risk_assessment.low_issues
            total_issues = risk_assessment.total_issues
        else:
            # Dictionary format
            risk_level = risk_assessment.get("risk_level", "UNKNOWN")
            risk_score = risk_assessment.get("risk_score", 0.0)
            critical_issues = risk_assessment.get("critical_issues", 0)
            high_issues = risk_assessment.get("high_issues", 0)
            medium_issues = risk_assessment.get("medium_issues", 0)
            low_issues = risk_assessment.get("low_issues", 0)
            total_issues = risk_assessment.get("total_issues", 0)
        
        section.append("\nManifest Risk Assessment:\n", style="cyan")
        
        # Overall risk
        risk_color = self.risk_colors.get(risk_level, "dim")
        section.append(f"  Overall Risk: {risk_level} ({risk_score:.2f})\n", style=f"bold {risk_color}")
        
        # Issue breakdown
        if total_issues > 0:
            section.append(f"  Issues Found: {total_issues}\n", style="dim")
            
            if critical_issues > 0:
                section.append(f"    🚨 Critical: {critical_issues}\n", style="red")
            if high_issues > 0:
                section.append(f"    ⚠️ High: {high_issues}\n", style="yellow") 
            if medium_issues > 0:
                section.append(f"    📋 Medium: {medium_issues}\n", style="cyan")
            if low_issues > 0:
                section.append(f"    ℹ️ Low: {low_issues}\n", style="dim")
        else:
            section.append("  No specific risk issues identified\n", style="green")
        
        return section
    
    def format_manifest_summary(self, manifest_data: Dict[str, Any]) -> Text:
        """
        Format a summary of manifest analysis.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Text: Formatted summary
        """
        summary = Text()
        
        if not manifest_data or "error" in manifest_data:
            summary.append("❌ AndroidManifest.xml analysis failed\n", style="red")
            return summary
        
        risk_assessment = manifest_data.get("risk_assessment", {})
        permission_analysis = manifest_data.get("permission_analysis", {})
        component_analysis = manifest_data.get("component_analysis", {})
        
        # Overall risk
        # Handle both RiskAssessment objects and dictionaries
        if hasattr(risk_assessment, 'overall_risk'):
            # RiskAssessment dataclass object
            risk_level = risk_assessment.overall_risk.value if hasattr(risk_assessment.overall_risk, 'value') else str(risk_assessment.overall_risk)
        else:
            # Dictionary format
            risk_level = risk_assessment.get("risk_level", "UNKNOWN")
            
        risk_color = self.risk_colors.get(risk_level, "dim")
        summary.append(f"📱 Manifest Risk: {risk_level}\n", style=f"bold {risk_color}")
        
        # Key statistics
        dangerous_perms = len(permission_analysis.get("dangerous_permissions", []))
        exported_comps = len(component_analysis.get("exported_components", []))
        
        if dangerous_perms > 0:
            summary.append(f"  🔑 Dangerous Permissions: {dangerous_perms}\n", style="yellow")
        if exported_comps > 0:
            summary.append(f"  📤 Exported Components: {exported_comps}\n", style="yellow")
        
        return summary
    
    def format_security_recommendations(self, manifest_data: Dict[str, Any]) -> Text:
        """
        Format security recommendations for manifest.
        
        Args:
            manifest_data: Manifest analysis data
            
        Returns:
            Text: Formatted recommendations
        """
        if not manifest_data or "error" in manifest_data:
            return Text()
        
        recommendations = manifest_data.get("recommendations", [])
        
        if not recommendations:
            return Text()
        
        rec_text = Text()
        rec_text.append("💡 Manifest Security Recommendations:\n", style="bold yellow")
        
        for i, rec in enumerate(recommendations[:5], 1):
            rec_text.append(f"  {i}. {rec}\n", style="yellow")
        
        return rec_text 
"""
Secret Analysis Formatter

This module handles the formatting of secret analysis results for reports.
"""

import logging
from typing import List, Any

from rich.text import Text

logger = logging.getLogger(__name__)

class SecretAnalysisFormatter:
    """
    Formatter for secret analysis results.
    
    Provides rich formatting for secret detection results in reports.
    """
    
    def __init__(self):
        """Initialize the secret analysis formatter."""
        self.confidence_colors = {
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        
        self.risk_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
    
    def format_secret_analysis(self, secrets: List[Any]) -> Text:
        """
        Format secret analysis results for display.
        
        Args:
            secrets: List of detected secrets
            
        Returns:
            Text: Formatted secret analysis
        """
        if not secrets:
            return Text("✅ No high-confidence secrets detected\n", style="green")
        
        logger.info(f"Formatting {len(secrets)} secret analysis results")
        
        secrets_text = Text()
        secrets_text.append("🔍 Secret Analysis Results\n", style="bold magenta")
        
        # Categorize secrets by confidence
        high_confidence = [s for s in secrets if getattr(s, 'confidence', 0) >= 0.7]
        medium_confidence = [s for s in secrets if 0.4 <= getattr(s, 'confidence', 0) < 0.7]
        low_confidence = [s for s in secrets if getattr(s, 'confidence', 0) < 0.4]
        
        # Format high confidence secrets
        if high_confidence:
            secrets_text.append(self._format_high_confidence_secrets(high_confidence))
        
        # Format medium confidence secrets
        if medium_confidence:
            secrets_text.append(self._format_medium_confidence_secrets(medium_confidence))
        
        # Format low confidence secrets (if any)
        if low_confidence:
            secrets_text.append(self._format_low_confidence_secrets(low_confidence))
        
        secrets_text.append("\n")
        return secrets_text
    
    def _format_high_confidence_secrets(self, secrets: List[Any]) -> Text:
        """
        Format high confidence secrets.
        
        Args:
            secrets: List of high confidence secrets
            
        Returns:
            Text: Formatted high confidence secrets
        """
        section = Text()
        
        section.append(
            f"\n🔑 High Confidence Secrets ({len(secrets)})\n",
            style="bold bright_red",
        )
        
        # Show top 5 high confidence secrets
        for i, secret in enumerate(secrets[:5], 1):
            section.append(self._format_individual_secret(secret, i, "bright_red"))
        
        # Show count of remaining secrets
        if len(secrets) > 5:
            remaining = len(secrets) - 5
            section.append(
                f"     ... and {remaining} more high confidence secrets\n\n",
                style="dim bright_red",
            )
        
        return section
    
    def _format_medium_confidence_secrets(self, secrets: List[Any]) -> Text:
        """
        Format medium confidence secrets.
        
        Args:
            secrets: List of medium confidence secrets
            
        Returns:
            Text: Formatted medium confidence secrets
        """
        section = Text()
        
        section.append(
            f"\n🔐 Medium Confidence Secrets ({len(secrets)})\n",
            style="bold yellow",
        )
        
        # Show top 3 medium confidence secrets
        for i, secret in enumerate(secrets[:3], 1):
            section.append(self._format_individual_secret(secret, i, "yellow"))
        
        # Show count of remaining secrets
        if len(secrets) > 3:
            remaining = len(secrets) - 3
            section.append(
                f"     ... and {remaining} more medium confidence secrets\n\n",
                style="dim yellow",
            )
        
        return section
    
    def _format_low_confidence_secrets(self, secrets: List[Any]) -> Text:
        """
        Format low confidence secrets.
        
        Args:
            secrets: List of low confidence secrets
            
        Returns:
            Text: Formatted low confidence secrets
        """
        section = Text()
        
        section.append(
            f"\n🔍 Low Confidence Secrets ({len(secrets)})\n",
            style="bold blue",
        )
        
        # Show only count for low confidence secrets
        section.append(
            f"     {len(secrets)} potential secrets with low confidence\n",
            style="dim blue",
        )
        
        return section
    
    def _format_individual_secret(self, secret: Any, index: int, color: str) -> Text:
        """
        Format an individual secret.
        
        Args:
            secret: Individual secret
            index: Secret index
            color: Color for this confidence level
            
        Returns:
            Text: Formatted secret
        """
        secret_text = Text()
        
        # Pattern type and masked value
        pattern_type = getattr(secret, 'pattern_type', 'UNKNOWN')
        value = getattr(secret, 'value', '')
        
        # Mask the value for security
        masked_value = self._mask_secret_value(value)
        
        secret_text.append(
            f"  {index}. {pattern_type.upper()}: {masked_value}\n",
            style=color,
        )
        
        # Confidence and entropy
        confidence = getattr(secret, 'confidence', 0.0)
        entropy = getattr(secret, 'entropy', 0.0)
        secret_text.append(f"     Confidence: {confidence:.1%}\n", style="dim")
        secret_text.append(f"     Entropy: {entropy:.2f}\n", style="dim")
        
        # File path
        file_path = getattr(secret, 'file_path', 'Unknown')
        secret_text.append(f"     File: {file_path}\n", style="dim")
        
        # Risk level
        risk_level = getattr(secret, 'risk_level', 'UNKNOWN')
        secret_text.append(f"     Risk Level: {risk_level}\n", style="dim")
        
        # Risk score (if available)
        if hasattr(secret, 'risk_score'):
            risk_score = secret.risk_score
            secret_text.append(f"     Risk Score: {risk_score:.2f}\n", style="dim")
        
        # Category (if available)
        if hasattr(secret, 'category'):
            category = secret.category
            secret_text.append(f"     Category: {category}\n", style="dim")
        
        # Severity (if available)
        if hasattr(secret, 'severity'):
            severity = secret.severity
            severity_color = self.risk_colors.get(severity, "dim")
            secret_text.append(f"     Severity: {severity}\n", style=severity_color)
        
        # Location risk (if available)
        if hasattr(secret, 'location_risk'):
            location_risk = secret.location_risk
            secret_text.append(f"     Location Risk: {location_risk}\n", style="dim")
        
        # Exposure risk (if available)
        if hasattr(secret, 'exposure_risk'):
            exposure_risk = secret.exposure_risk
            exposure_color = self.risk_colors.get(exposure_risk, "dim")
            secret_text.append(f"     Exposure Risk: {exposure_risk}\n", style=exposure_color)
        
        # Remediation suggestions (if available)
        if hasattr(secret, 'remediation') and secret.remediation:
            remediation = secret.remediation
            if remediation:
                secret_text.append(f"     💡 {remediation[0]}\n", style="cyan")
        
        secret_text.append("\n")
        return secret_text
    
    def _mask_secret_value(self, value: str) -> str:
        """
        Mask secret value for display.
        
        Args:
            value: Secret value
            
        Returns:
            str: Masked value
        """
        if not value:
            return "***"
        
        # Show first few characters, mask the rest
        if len(value) <= 4:
            return "*" * len(value)
        elif len(value) <= 10:
            return value[:2] + "*" * (len(value) - 2)
        else:
            return value[:4] + "*" * 6 + value[-2:]
    
    def format_secrets_summary(self, secrets: List[Any]) -> Text:
        """
        Format a summary of secret analysis.
        
        Args:
            secrets: List of detected secrets
            
        Returns:
            Text: Formatted summary
        """
        summary = Text()
        
        if not secrets:
            summary.append("✅ No secrets detected\n", style="green")
            return summary
        
        # Categorize by confidence
        high_confidence = [s for s in secrets if getattr(s, 'confidence', 0) >= 0.7]
        medium_confidence = [s for s in secrets if 0.4 <= getattr(s, 'confidence', 0) < 0.7]
        low_confidence = [s for s in secrets if getattr(s, 'confidence', 0) < 0.4]
        
        summary.append(f"🔍 Secret Analysis: {len(secrets)} total\n", style="bold magenta")
        
        if high_confidence:
            summary.append(f"  🔑 High Confidence: {len(high_confidence)}\n", style="bright_red")
        if medium_confidence:
            summary.append(f"  🔐 Medium Confidence: {len(medium_confidence)}\n", style="yellow")
        if low_confidence:
            summary.append(f"  🔍 Low Confidence: {len(low_confidence)}\n", style="blue")
        
        return summary
    
    def format_secrets_by_category(self, secrets: List[Any]) -> Text:
        """
        Format secrets breakdown by category.
        
        Args:
            secrets: List of detected secrets
            
        Returns:
            Text: Formatted category breakdown
        """
        if not secrets:
            return Text()
        
        # Group by category
        categories = {}
        for secret in secrets:
            category = getattr(secret, 'category', 'UNKNOWN')
            if category not in categories:
                categories[category] = []
            categories[category].append(secret)
        
        breakdown = Text()
        breakdown.append("📊 Secrets by Category\n", style="bold cyan")
        
        # Sort categories by count
        sorted_categories = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)
        
        for category, category_secrets in sorted_categories:
            count = len(category_secrets)
            # Count high confidence secrets in this category
            high_conf_count = len([s for s in category_secrets if getattr(s, 'confidence', 0) >= 0.7])
            
            if high_conf_count > 0:
                breakdown.append(f"  • {category}: {count} total ({high_conf_count} high confidence)\n", style="red")
            else:
                breakdown.append(f"  • {category}: {count} total\n", style="cyan")
        
        return breakdown
    
    def format_top_secrets(self, secrets: List[Any], limit: int = 3) -> Text:
        """
        Format top secrets by confidence.
        
        Args:
            secrets: List of detected secrets
            limit: Maximum number of secrets to show
            
        Returns:
            Text: Formatted top secrets
        """
        if not secrets:
            return Text()
        
        # Sort by confidence and risk score
        sorted_secrets = sorted(
            secrets,
            key=lambda s: (
                getattr(s, 'confidence', 0.0),
                getattr(s, 'risk_score', 0.0)
            ),
            reverse=True
        )
        
        top_secrets = Text()
        top_secrets.append(f"🔥 Top {min(limit, len(secrets))} Secrets\n", style="bold red")
        
        for i, secret in enumerate(sorted_secrets[:limit], 1):
            pattern_type = getattr(secret, 'pattern_type', 'UNKNOWN')
            confidence = getattr(secret, 'confidence', 0.0)
            risk_level = getattr(secret, 'risk_level', 'UNKNOWN')
            
            color = "bright_red" if confidence >= 0.7 else "yellow" if confidence >= 0.4 else "blue"
            
            top_secrets.append(
                f"  {i}. {pattern_type.upper()} ({confidence:.1%}, {risk_level})\n",
                style=color
            )
        
        return top_secrets
    
    def format_remediation_summary(self, secrets: List[Any]) -> Text:
        """
        Format remediation summary for secrets.
        
        Args:
            secrets: List of detected secrets
            
        Returns:
            Text: Formatted remediation summary
        """
        if not secrets:
            return Text()
        
        # Filter high confidence secrets that need immediate attention
        high_risk_secrets = [
            s for s in secrets 
            if getattr(s, 'confidence', 0) >= 0.7 or getattr(s, 'risk_score', 0) >= 0.8
        ]
        
        if not high_risk_secrets:
            return Text()
        
        remediation = Text()
        remediation.append("🚨 Immediate Action Required\n", style="bold red")
        
        # Common remediation actions
        remediation.append("  1. Remove hardcoded secrets from source code\n", style="red")
        remediation.append("  2. Use environment variables or secure vaults\n", style="red")
        remediation.append("  3. Implement proper secret rotation policies\n", style="red")
        remediation.append("  4. Audit all detected secret locations\n", style="red")
        
        if len(high_risk_secrets) > 5:
            remediation.append(f"  ⚠️ {len(high_risk_secrets)} high-risk secrets require immediate attention\n", style="yellow")
        
        return remediation 
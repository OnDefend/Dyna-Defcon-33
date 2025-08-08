"""
Secret Analysis Engine

This module handles processing and analysis of secret detection results.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SecretAnalysisEngine:
    """
    Engine for processing secret analysis results.
    
    Provides enhanced processing, filtering, and analysis of detected secrets.
    """
    
    def __init__(self):
        """Initialize the secret analysis engine."""
        self.risk_thresholds = {
            "high": 0.7,
            "medium": 0.4,
            "low": 0.0
        }
        
        self.secret_categories = {
            "api_key": ["api", "key", "token", "secret"],
            "password": ["password", "pass", "pwd"],
            "private_key": ["private", "key", "rsa", "pem"],
            "database": ["db", "database", "connection", "url"],
            "oauth": ["oauth", "client_id", "client_secret"],
            "encryption": ["encrypt", "cipher", "aes", "des"]
        }
    
    def process_secret_analysis(self, secret_data: List[Any]) -> List[Any]:
        """
        Process secret analysis results with enhanced categorization and risk assessment.
        
        Args:
            secret_data: Raw secret analysis results
            
        Returns:
            List[Any]: Processed secret analysis results
        """
        if not secret_data:
            return []
        
        logger.info(f"Processing {len(secret_data)} secret analysis results")
        
        processed_secrets = []
        
        for secret in secret_data:
            # Enhance secret with additional metadata
            enhanced_secret = self._enhance_secret(secret)
            
            # Apply risk categorization
            enhanced_secret = self._categorize_secret_risk(enhanced_secret)
            
            # Add contextual information
            enhanced_secret = self._add_contextual_info(enhanced_secret)
            
            processed_secrets.append(enhanced_secret)
        
        # Sort by confidence and risk level
        processed_secrets.sort(key=lambda x: (x.confidence, x.risk_score), reverse=True)
        
        logger.info(f"Processed {len(processed_secrets)} secrets successfully")
        return processed_secrets
    
    def _enhance_secret(self, secret: Any) -> Any:
        """
        Enhance secret with additional metadata and analysis.
        
        Args:
            secret: Raw secret object
            
        Returns:
            Any: Enhanced secret object
        """
        # Add risk score based on confidence and entropy
        risk_score = self._calculate_secret_risk_score(secret)
        secret.risk_score = risk_score
        
        # Categorize secret type
        secret.category = self._determine_secret_category(secret)
        
        # Add severity assessment
        secret.severity = self._determine_secret_severity(secret)
        
        # Add remediation suggestions
        secret.remediation = self._generate_remediation_suggestions(secret)
        
        return secret
    
    def _categorize_secret_risk(self, secret: Any) -> Any:
        """
        Categorize secret based on risk level.
        
        Args:
            secret: Secret object to categorize
            
        Returns:
            Any: Secret with risk categorization
        """
        if secret.confidence >= self.risk_thresholds["high"]:
            secret.risk_category = "HIGH"
            secret.priority = "URGENT"
        elif secret.confidence >= self.risk_thresholds["medium"]:
            secret.risk_category = "MEDIUM"
            secret.priority = "HIGH"
        else:
            secret.risk_category = "LOW"
            secret.priority = "MEDIUM"
        
        return secret
    
    def _add_contextual_info(self, secret: Any) -> Any:
        """
        Add contextual information to secret analysis.
        
        Args:
            secret: Secret object to enhance
            
        Returns:
            Any: Secret with contextual information
        """
        # Add file context
        if hasattr(secret, 'file_path') and secret.file_path:
            secret.file_type = self._determine_file_type(secret.file_path)
            secret.location_risk = self._assess_location_risk(secret.file_path)
        
        # Add pattern context
        if hasattr(secret, 'pattern_type'):
            secret.pattern_description = self._get_pattern_description(secret.pattern_type)
        
        # Add exposure risk
        secret.exposure_risk = self._assess_exposure_risk(secret)
        
        return secret
    
    def _calculate_secret_risk_score(self, secret: Any) -> float:
        """
        Calculate comprehensive risk score for a secret.
        
        Args:
            secret: Secret object
            
        Returns:
            float: Risk score between 0.0 and 1.0
        """
        base_score = getattr(secret, 'confidence', 0.0)
        entropy_factor = min(1.0, getattr(secret, 'entropy', 0.0) / 8.0)  # Normalize entropy
        
        # File location factor
        file_path = getattr(secret, 'file_path', '')
        location_factor = 1.0
        if 'test' in file_path.lower() or 'debug' in file_path.lower():
            location_factor = 0.7
        elif 'config' in file_path.lower() or 'properties' in file_path.lower():
            location_factor = 1.2
        
        # Pattern type factor
        pattern_type = getattr(secret, 'pattern_type', '')
        pattern_factor = 1.0
        if 'api' in pattern_type.lower() or 'token' in pattern_type.lower():
            pattern_factor = 1.3
        elif 'private' in pattern_type.lower() or 'key' in pattern_type.lower():
            pattern_factor = 1.5
        
        # Calculate final score
        final_score = base_score * entropy_factor * location_factor * pattern_factor
        return min(1.0, final_score)
    
    def _determine_secret_category(self, secret: Any) -> str:
        """
        Determine the category of a secret based on its pattern type.
        
        Args:
            secret: Secret object
            
        Returns:
            str: Secret category
        """
        pattern_type = getattr(secret, 'pattern_type', '').lower()
        
        for category, keywords in self.secret_categories.items():
            if any(keyword in pattern_type for keyword in keywords):
                return category.upper()
        
        return "UNKNOWN"
    
    def _determine_secret_severity(self, secret: Any) -> str:
        """
        Determine the severity level of a secret.
        
        Args:
            secret: Secret object
            
        Returns:
            str: Severity level
        """
        confidence = getattr(secret, 'confidence', 0.0)
        category = getattr(secret, 'category', 'UNKNOWN')
        
        # High-impact categories
        if category in ['PRIVATE_KEY', 'API_KEY', 'PASSWORD', 'OAUTH']:
            if confidence >= 0.8:
                return "CRITICAL"
            elif confidence >= 0.6:
                return "HIGH"
            else:
                return "MEDIUM"
        
        # Medium-impact categories
        elif category in ['DATABASE', 'ENCRYPTION']:
            if confidence >= 0.9:
                return "HIGH"
            elif confidence >= 0.7:
                return "MEDIUM"
            else:
                return "LOW"
        
        # Default based on confidence
        if confidence >= 0.9:
            return "HIGH"
        elif confidence >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_remediation_suggestions(self, secret: Any) -> List[str]:
        """
        Generate remediation suggestions for a secret.
        
        Args:
            secret: Secret object
            
        Returns:
            List[str]: Remediation suggestions
        """
        suggestions = []
        category = getattr(secret, 'category', 'UNKNOWN')
        
        if category == 'API_KEY':
            suggestions.extend([
                "Remove hardcoded API keys from source code",
                "Use environment variables or secure configuration management",
                "Implement proper API key rotation policies",
                "Use encrypted storage for API credentials"
            ])
        elif category == 'PASSWORD':
            suggestions.extend([
                "Remove hardcoded passwords from source code",
                "Use secure password hashing algorithms",
                "Implement proper authentication mechanisms",
                "Use encrypted credential storage"
            ])
        elif category == 'PRIVATE_KEY':
            suggestions.extend([
                "Remove private keys from source code",
                "Use secure key management systems",
                "Implement proper key rotation policies",
                "Use hardware security modules for key storage"
            ])
        elif category == 'DATABASE':
            suggestions.extend([
                "Remove hardcoded database credentials",
                "Use connection pooling with secure authentication",
                "Implement database access controls",
                "Use encrypted database connections"
            ])
        else:
            suggestions.extend([
                "Remove hardcoded secrets from source code",
                "Use secure configuration management",
                "Implement proper secret rotation policies",
                "Use encrypted storage for sensitive data"
            ])
        
        return suggestions
    
    def _determine_file_type(self, file_path: str) -> str:
        """Determine file type based on file path."""
        if file_path.endswith('.java'):
            return 'JAVA'
        elif file_path.endswith('.kt'):
            return 'KOTLIN'
        elif file_path.endswith('.xml'):
            return 'XML'
        elif file_path.endswith('.properties'):
            return 'PROPERTIES'
        elif file_path.endswith('.json'):
            return 'JSON'
        else:
            return 'UNKNOWN'
    
    def _assess_location_risk(self, file_path: str) -> str:
        """Assess risk based on file location."""
        if any(keyword in file_path.lower() for keyword in ['config', 'properties', 'settings']):
            return 'HIGH'
        elif any(keyword in file_path.lower() for keyword in ['test', 'debug', 'sample']):
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def _get_pattern_description(self, pattern_type: str) -> str:
        """Get description for pattern type."""
        descriptions = {
            'api_key': 'API Key or Token',
            'password': 'Password or Credential',
            'private_key': 'Private Key or Certificate',
            'database': 'Database Connection String',
            'oauth': 'OAuth Token or Secret',
            'encryption': 'Encryption Key or Cipher'
        }
        return descriptions.get(pattern_type.lower(), 'Unknown Pattern')
    
    def _assess_exposure_risk(self, secret: Any) -> str:
        """Assess exposure risk level."""
        confidence = getattr(secret, 'confidence', 0.0)
        entropy = getattr(secret, 'entropy', 0.0)
        
        if confidence >= 0.8 and entropy >= 6.0:
            return 'CRITICAL'
        elif confidence >= 0.6 and entropy >= 4.0:
            return 'HIGH'
        elif confidence >= 0.4 and entropy >= 2.0:
            return 'MEDIUM'
        else:
            return 'LOW' 
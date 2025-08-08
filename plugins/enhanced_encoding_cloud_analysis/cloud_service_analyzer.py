"""
Cloud Service Security Analyzer Module

This module handles comprehensive cloud service security analysis including 
Firebase, AWS S3, Google Cloud, Azure, and other cloud service integrations
with focus on security vulnerabilities and misconfigurations.
"""

import re
import json
import logging
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from .data_structures import (
    CloudServiceFinding, CloudServiceEndpoint, EncodingContext,
    CloudServiceType, SeverityLevel, FileType, AnalysisPattern
)

logger = logging.getLogger(__name__)

class CloudServicePatternLibrary:
    """Library of cloud service detection patterns and security checks."""
    
    def __init__(self):
        """Initialize cloud service pattern library."""
        self._init_firebase_patterns()
        self._init_aws_patterns()
        self._init_google_cloud_patterns()
        self._init_azure_patterns()
        self._init_generic_patterns()
        self._init_security_patterns()
    
    def _init_firebase_patterns(self):
        """Initialize Firebase detection patterns."""
        self.firebase_patterns = [
            # Firebase configuration patterns
            re.compile(r'firebase["\s]*[=:]["\s]*([^"\';\s]+)', re.IGNORECASE),
            re.compile(r'firebaseConfig["\s]*[=:]["\s]*{([^}]+)}', re.IGNORECASE),
            re.compile(r'apiKey["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'authDomain["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'databaseURL["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'projectId["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'storageBucket["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'messagingSenderId["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            
            # Firebase URLs
            re.compile(r'https?://([a-zA-Z0-9-]+)\.firebaseio\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9-]+)\.firebaseapp\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9-]+)\.web\.app', re.IGNORECASE),
            
            # Firebase Android SDK patterns
            re.compile(r'FirebaseDatabase\.getInstance\(\)', re.IGNORECASE),
            re.compile(r'FirebaseAuth\.getInstance\(\)', re.IGNORECASE),
            re.compile(r'FirebaseStorage\.getInstance\(\)', re.IGNORECASE),
        ]
        
        # Firebase security rule patterns
        self.firebase_security_patterns = [
            re.compile(r'\.read["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'\.write["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'rules_version["\s]*[=:]["\s]*["\']1["\']', re.IGNORECASE),
            re.compile(r'allow read, write["\s]*[=:]["\s]*if true', re.IGNORECASE),
        ]
    
    def _init_aws_patterns(self):
        """Initialize AWS detection patterns."""
        self.aws_patterns = [
            # AWS access keys and credentials
            re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            re.compile(r'aws_access_key_id["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'aws_secret_access_key["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'aws_session_token["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            
            # S3 bucket patterns
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.s3\.amazonaws\.com', re.IGNORECASE),
            re.compile(r'https?://s3\.amazonaws\.com/([a-zA-Z0-9.-]+)', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com', re.IGNORECASE),
            re.compile(r's3://([a-zA-Z0-9.-]+)', re.IGNORECASE),
            
            # AWS SDK patterns
            re.compile(r'AmazonS3Client\(\)', re.IGNORECASE),
            re.compile(r'BasicAWSCredentials\(', re.IGNORECASE),
            re.compile(r'AWSStaticCredentialsProvider\(', re.IGNORECASE),
            
            # AWS service endpoints
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.lambda\.([a-z0-9-]+)\.amazonaws\.com', re.IGNORECASE),
        ]
    
    def _init_google_cloud_patterns(self):
        """Initialize Google Cloud Platform patterns."""
        self.google_cloud_patterns = [
            # Google Cloud Storage
            re.compile(r'https?://storage\.googleapis\.com/([a-zA-Z0-9.-]+)', re.IGNORECASE),
            re.compile(r'gs://([a-zA-Z0-9.-]+)', re.IGNORECASE),
            
            # Google Cloud service accounts
            re.compile(r'[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com', re.IGNORECASE),
            re.compile(r'type["\s]*[=:]["\s]*["\']service_account["\']', re.IGNORECASE),
            re.compile(r'private_key_id["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'private_key["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            
            # Google Cloud API endpoints
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.googleapis\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.googleapi\.com', re.IGNORECASE),
        ]
    
    def _init_azure_patterns(self):
        """Initialize Microsoft Azure patterns."""
        self.azure_patterns = [
            # Azure storage accounts
            re.compile(r'https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9]+)\.table\.core\.windows\.net', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9]+)\.queue\.core\.windows\.net', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9]+)\.file\.core\.windows\.net', re.IGNORECASE),
            
            # Azure credentials
            re.compile(r'DefaultEndpointsProtocol[=:][^;]+;AccountName[=:]([^;]+);AccountKey[=:]([^;]+)', re.IGNORECASE),
            re.compile(r'azure_storage_account["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'azure_storage_key["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            
            # Azure API endpoints
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.azurewebsites\.net', re.IGNORECASE),
            re.compile(r'https?://management\.azure\.com', re.IGNORECASE),
        ]
    
    def _init_generic_patterns(self):
        """Initialize generic cloud service patterns."""
        self.generic_patterns = [
            # Generic API endpoints
            re.compile(r'https?://api\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
            re.compile(r'api[_-]?key["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'api[_-]?secret["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'access[_-]?token["\s]*[=:]["\s]*["\']([^"\']+)["\']', re.IGNORECASE),
            
            # Database connection strings
            re.compile(r'mongodb://([^@]+@)?([^/]+)/([^?]+)', re.IGNORECASE),
            re.compile(r'mysql://([^@]+@)?([^/]+)/([^?]+)', re.IGNORECASE),
            re.compile(r'postgresql://([^@]+@)?([^/]+)/([^?]+)', re.IGNORECASE),
            
            # Cloud storage services
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.dropbox\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.box\.com', re.IGNORECASE),
            re.compile(r'https?://([a-zA-Z0-9.-]+)\.sharepoint\.com', re.IGNORECASE),
        ]
    
    def _init_security_patterns(self):
        """Initialize security vulnerability patterns."""
        self.security_patterns = [
            # Insecure configurations
            re.compile(r'ssl[_-]?verify["\s]*[=:]["\s]*false', re.IGNORECASE),
            re.compile(r'verify[_-]?ssl["\s]*[=:]["\s]*false', re.IGNORECASE),
            re.compile(r'ignore[_-]?ssl["\s]*[=:]["\s]*true', re.IGNORECASE),
            
            # Public access configurations
            re.compile(r'public[_-]?read["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'public[_-]?write["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'AllowAnonymous', re.IGNORECASE),
            
            # Debug and development configurations
            re.compile(r'debug["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'development["\s]*[=:]["\s]*true', re.IGNORECASE),
            re.compile(r'test[_-]?mode["\s]*[=:]["\s]*true', re.IGNORECASE),
        ]

class CloudServiceAnalyzer:
    """Analyzer for cloud service security vulnerabilities and misconfigurations."""
    
    def __init__(self):
        """Initialize the cloud service analyzer."""
        self.pattern_library = CloudServicePatternLibrary()
        self.detected_services: Set[Tuple[str, str]] = set()  # Cache for deduplication
        
        # Analysis configuration
        self.confidence_threshold = 0.7
        self.max_url_length = 500
    
    def analyze_cloud_services(self, content: str, location: str, 
                              file_type: FileType = FileType.OTHER) -> List[CloudServiceFinding]:
        """
        Analyze content for cloud service patterns and vulnerabilities.
        
        Args:
            content: Text content to analyze
            location: Location identifier for the content
            file_type: Type of file being analyzed
            
        Returns:
            List of cloud service findings
        """
        findings = []
        
        if not content or not content.strip():
            return findings
        
        try:
            # Analyze different cloud service types
            findings.extend(self._analyze_firebase_services(content, location, file_type))
            findings.extend(self._analyze_aws_services(content, location, file_type))
            findings.extend(self._analyze_google_cloud_services(content, location, file_type))
            findings.extend(self._analyze_azure_services(content, location, file_type))
            findings.extend(self._analyze_generic_services(content, location, file_type))
            
            # Analyze security configurations
            findings.extend(self._analyze_security_configurations(content, location, file_type))
            
        except Exception as e:
            logger.error(f"Error analyzing cloud services at {location}: {e}")
        
        return findings
    
    def _analyze_firebase_services(self, content: str, location: str, 
                                  file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze Firebase service configurations and security."""
        findings = []
        
        # Firebase configuration analysis
        for pattern in self.pattern_library.firebase_patterns:
            for match in pattern.finditer(content):
                firebase_config = match.group(0)
                
                cache_key = (firebase_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                finding = self._create_cloud_service_finding(
                    service_type=CloudServiceType.FIREBASE,
                    config_content=firebase_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Analyze Firebase configuration for security issues
                security_issues = self._analyze_firebase_configuration(firebase_config, content)
                finding.configuration_issues.extend(security_issues)
                
                # Check for Firebase security rules
                if any(pattern.search(content) for pattern in self.pattern_library.firebase_security_patterns):
                    finding.configuration_issues.append("Permissive Firebase security rules detected")
                    finding.severity = SeverityLevel.HIGH
                
                # Check for exposed API keys
                if 'apikey' in firebase_config.lower() or 'api_key' in firebase_config.lower():
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.HIGH
                    finding.configuration_issues.append("Firebase API key may be exposed")
                
                finding.confidence = self._calculate_firebase_confidence(firebase_config, content, file_type)
                finding.analysis_patterns = [AnalysisPattern.FIREBASE_INTEGRATION]
                
                findings.append(finding)
        
        return findings
    
    def _analyze_aws_services(self, content: str, location: str, 
                             file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze AWS service configurations and security."""
        findings = []
        
        for pattern in self.pattern_library.aws_patterns:
            for match in pattern.finditer(content):
                aws_config = match.group(0)
                
                cache_key = (aws_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                finding = self._create_cloud_service_finding(
                    service_type=CloudServiceType.AWS_S3,
                    config_content=aws_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Check for AWS credentials
                if 'AKIA' in aws_config or 'aws_access_key' in aws_config.lower():
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.CRITICAL
                    finding.configuration_issues.append("AWS credentials may be hardcoded")
                    finding.analysis_patterns.append(AnalysisPattern.AWS_CREDENTIALS)
                
                # Check for S3 bucket configurations
                if 's3' in aws_config.lower():
                    s3_issues = self._analyze_s3_configuration(aws_config, content)
                    finding.configuration_issues.extend(s3_issues)
                
                finding.confidence = self._calculate_aws_confidence(aws_config, content, file_type)
                finding.analysis_patterns = [AnalysisPattern.CLOUD_ENDPOINTS]
                
                findings.append(finding)
        
        return findings
    
    def _analyze_google_cloud_services(self, content: str, location: str, 
                                      file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze Google Cloud Platform services."""
        findings = []
        
        for pattern in self.pattern_library.google_cloud_patterns:
            for match in pattern.finditer(content):
                gcp_config = match.group(0)
                
                cache_key = (gcp_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                finding = self._create_cloud_service_finding(
                    service_type=CloudServiceType.GOOGLE_CLOUD,
                    config_content=gcp_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Check for service account credentials
                if 'service_account' in gcp_config.lower() or 'private_key' in gcp_config.lower():
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.HIGH
                    finding.configuration_issues.append("Google Cloud service account credentials may be exposed")
                
                # Check for Cloud Storage configurations
                if 'storage.googleapis.com' in gcp_config or 'gs://' in gcp_config:
                    storage_issues = self._analyze_gcp_storage_configuration(gcp_config, content)
                    finding.configuration_issues.extend(storage_issues)
                
                finding.confidence = self._calculate_gcp_confidence(gcp_config, content, file_type)
                
                findings.append(finding)
        
        return findings
    
    def _analyze_azure_services(self, content: str, location: str, 
                               file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze Microsoft Azure services."""
        findings = []
        
        for pattern in self.pattern_library.azure_patterns:
            for match in pattern.finditer(content):
                azure_config = match.group(0)
                
                cache_key = (azure_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                finding = self._create_cloud_service_finding(
                    service_type=CloudServiceType.AZURE,
                    config_content=azure_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Check for Azure storage credentials
                if 'AccountKey' in azure_config or 'azure_storage_key' in azure_config.lower():
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.HIGH
                    finding.configuration_issues.append("Azure storage credentials may be exposed")
                
                # Check for Azure storage configurations
                if 'blob.core.windows.net' in azure_config or 'DefaultEndpointsProtocol' in azure_config:
                    storage_issues = self._analyze_azure_storage_configuration(azure_config, content)
                    finding.configuration_issues.extend(storage_issues)
                
                finding.confidence = self._calculate_azure_confidence(azure_config, content, file_type)
                
                findings.append(finding)
        
        return findings
    
    def _analyze_generic_services(self, content: str, location: str, 
                                 file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze generic cloud services and APIs."""
        findings = []
        
        for pattern in self.pattern_library.generic_patterns:
            for match in pattern.finditer(content):
                service_config = match.group(0)
                
                cache_key = (service_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                # Determine service type
                service_type = self._determine_generic_service_type(service_config)
                
                finding = self._create_cloud_service_finding(
                    service_type=service_type,
                    config_content=service_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Check for API credentials
                if any(keyword in service_config.lower() for keyword in ['api_key', 'api_secret', 'access_token']):
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.MEDIUM
                    finding.configuration_issues.append("API credentials may be hardcoded")
                
                # Check for database connection strings
                if any(keyword in service_config.lower() for keyword in ['mongodb://', 'mysql://', 'postgresql://']):
                    finding.credential_exposure = True
                    finding.severity = SeverityLevel.HIGH
                    finding.configuration_issues.append("Database connection string with credentials detected")
                
                finding.confidence = self._calculate_generic_confidence(service_config, content, file_type)
                
                findings.append(finding)
        
        return findings
    
    def _analyze_security_configurations(self, content: str, location: str, 
                                        file_type: FileType) -> List[CloudServiceFinding]:
        """Analyze security-related configurations."""
        findings = []
        
        for pattern in self.pattern_library.security_patterns:
            for match in pattern.finditer(content):
                security_config = match.group(0)
                
                cache_key = (security_config, location)
                if cache_key in self.detected_services:
                    continue
                
                self.detected_services.add(cache_key)
                
                finding = self._create_cloud_service_finding(
                    service_type=CloudServiceType.GENERIC_API,
                    config_content=security_config,
                    location=location,
                    file_type=file_type,
                    match_position=match.start(),
                    context_text=content[max(0, match.start()-100):match.end()+100]
                )
                
                # Analyze specific security issues
                if 'ssl_verify' in security_config.lower() and 'false' in security_config.lower():
                    finding.configuration_issues.append("SSL certificate verification disabled")
                    finding.severity = SeverityLevel.HIGH
                
                if 'public' in security_config.lower() and 'true' in security_config.lower():
                    finding.public_access_risk = True
                    finding.severity = SeverityLevel.MEDIUM
                    finding.configuration_issues.append("Public access configuration detected")
                
                if 'debug' in security_config.lower() and 'true' in security_config.lower():
                    finding.configuration_issues.append("Debug mode enabled in configuration")
                    finding.severity = SeverityLevel.LOW
                
                finding.confidence = 0.8
                
                findings.append(finding)
        
        return findings
    
    def _create_cloud_service_finding(self, service_type: CloudServiceType, config_content: str,
                                     location: str, file_type: FileType, match_position: int,
                                     context_text: str) -> CloudServiceFinding:
        """Create a cloud service finding with context."""
        finding_id = f"cloud_{service_type.value}_{hash(config_content) % 10000:04d}"
        
        context = EncodingContext(
            file_path=location,
            file_type=file_type,
            line_number=context_text[:match_position].count('\n') + 1,
            surrounding_text=context_text
        )
        
        # Try to parse endpoint if it's a URL
        endpoint = None
        if config_content.startswith(('http://', 'https://')):
            endpoint = self._parse_service_endpoint(config_content, service_type)
        
        finding = CloudServiceFinding(
            finding_id=finding_id,
            service_type=service_type,
            service_endpoint=endpoint,
            location=location,
            context=context,
            description=f"Detected {service_type.value} service configuration",
            severity=SeverityLevel.MEDIUM  # Default, will be adjusted based on analysis
        )
        
        # Add security implications and recommendations
        finding.security_impact = self._assess_cloud_security_impact(finding, config_content)
        finding.recommendations = self._generate_cloud_recommendations(finding)
        finding.cwe = self._get_cloud_service_cwe(service_type)
        finding.masvs_control = self._get_cloud_service_masvs_control(service_type)
        
        return finding
    
    def _parse_service_endpoint(self, url: str, service_type: CloudServiceType) -> Optional[CloudServiceEndpoint]:
        """Parse service endpoint from URL."""
        try:
            parsed = urlparse(url)
            
            endpoint = CloudServiceEndpoint(
                service_type=service_type,
                endpoint_url=url,
                service_config={
                    'domain': parsed.netloc,
                    'path': parsed.path,
                    'scheme': parsed.scheme
                }
            )
            
            # Add service-specific configuration
            if service_type == CloudServiceType.FIREBASE:
                if 'firebaseio.com' in parsed.netloc:
                    endpoint.service_config['firebase_project'] = parsed.netloc.split('.')[0]
                    endpoint.encryption_status = 'HTTPS' if parsed.scheme == 'https' else 'HTTP'
            
            elif service_type == CloudServiceType.AWS_S3:
                if 's3.amazonaws.com' in parsed.netloc:
                    path_parts = parsed.path.strip('/').split('/')
                    if path_parts:
                        endpoint.service_config['bucket_name'] = path_parts[0]
            
            return endpoint
            
        except Exception as e:
            logger.debug(f"Error parsing service endpoint {url}: {e}")
            return None
    
    def _analyze_firebase_configuration(self, config: str, full_content: str) -> List[str]:
        """Analyze Firebase configuration for security issues."""
        issues = []
        
        # Check for development/test configurations
        if any(keyword in config.lower() for keyword in ['test', 'dev', 'debug', 'local']):
            issues.append("Development or test Firebase configuration detected")
        
        # Check for security rule violations in content
        if '.read: true' in full_content or '.write: true' in full_content:
            issues.append("Permissive Firebase security rules allowing public access")
        
        # Check for authentication domain issues
        if 'authDomain' in config and 'localhost' in config:
            issues.append("Firebase authentication domain set to localhost")
        
        return issues
    
    def _analyze_s3_configuration(self, config: str, full_content: str) -> List[str]:
        """Analyze S3 configuration for security issues."""
        issues = []
        
        # Check for public bucket configurations
        if any(keyword in full_content.lower() for keyword in ['public-read', 'public-read-write']):
            issues.append("S3 bucket may have public access permissions")
        
        # Check for CORS misconfigurations
        if 'AllowedOrigin' in full_content and '*' in full_content:
            issues.append("S3 CORS configuration allows all origins")
        
        return issues
    
    def _analyze_gcp_storage_configuration(self, config: str, full_content: str) -> List[str]:
        """Analyze Google Cloud Storage configuration."""
        issues = []
        
        # Check for public access
        if 'allUsers' in full_content or 'allAuthenticatedUsers' in full_content:
            issues.append("Google Cloud Storage bucket may allow public access")
        
        return issues
    
    def _analyze_azure_storage_configuration(self, config: str, full_content: str) -> List[str]:
        """Analyze Azure Storage configuration."""
        issues = []
        
        # Check for HTTP usage
        if 'DefaultEndpointsProtocol=http' in config:
            issues.append("Azure storage connection uses HTTP instead of HTTPS")
        
        return issues
    
    def _determine_generic_service_type(self, config: str) -> CloudServiceType:
        """Determine the type of generic cloud service."""
        config_lower = config.lower()
        
        if 'dropbox' in config_lower:
            return CloudServiceType.DROPBOX
        elif 'box.com' in config_lower:
            return CloudServiceType.BOX
        elif 'sharepoint' in config_lower or 'onedrive' in config_lower:
            return CloudServiceType.ONEDRIVE
        elif any(db in config_lower for db in ['mongodb', 'mysql', 'postgresql']):
            return CloudServiceType.SQLITE_CLOUD
        else:
            return CloudServiceType.GENERIC_API
    
    def _calculate_firebase_confidence(self, config: str, content: str, file_type: FileType) -> float:
        """Calculate confidence score for Firebase detection."""
        confidence = 0.8  # High base confidence
        
        # Firebase-specific indicators
        if any(keyword in config.lower() for keyword in ['firebase', 'firebaseio', 'firebaseapp']):
            confidence += 0.1
        
        # Configuration completeness
        if all(keyword in content.lower() for keyword in ['apikey', 'authdomain', 'projectid']):
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _calculate_aws_confidence(self, config: str, content: str, file_type: FileType) -> float:
        """Calculate confidence score for AWS detection."""
        confidence = 0.7  # Base confidence
        
        # AWS-specific indicators
        if 'AKIA' in config or 'amazonaws.com' in config.lower():
            confidence += 0.2
        
        # SDK usage
        if any(keyword in content for keyword in ['AmazonS3Client', 'BasicAWSCredentials']):
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _calculate_gcp_confidence(self, config: str, content: str, file_type: FileType) -> float:
        """Calculate confidence score for Google Cloud detection."""
        confidence = 0.7  # Base confidence
        
        if 'googleapis.com' in config.lower() or 'gserviceaccount.com' in config.lower():
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def _calculate_azure_confidence(self, config: str, content: str, file_type: FileType) -> float:
        """Calculate confidence score for Azure detection."""
        confidence = 0.7  # Base confidence
        
        if 'core.windows.net' in config.lower() or 'azure' in config.lower():
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def _calculate_generic_confidence(self, config: str, content: str, file_type: FileType) -> float:
        """Calculate confidence score for generic service detection."""
        confidence = 0.6  # Lower base confidence
        
        # URL pattern confidence
        if config.startswith(('http://', 'https://')):
            confidence += 0.1
        
        # API credential patterns
        if any(keyword in config.lower() for keyword in ['api_key', 'token', 'secret']):
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _assess_cloud_security_impact(self, finding: CloudServiceFinding, config: str) -> str:
        """Assess security impact of cloud service finding."""
        if finding.credential_exposure:
            return "Exposed cloud service credentials can lead to unauthorized access and data breaches"
        
        if finding.public_access_risk:
            return "Public access configuration may expose sensitive data or services"
        
        if finding.service_type in [CloudServiceType.FIREBASE, CloudServiceType.AWS_S3]:
            return "Cloud service configuration may expose sensitive data or functionality"
        
        return "Cloud service integration should be reviewed for security best practices"
    
    def _generate_cloud_recommendations(self, finding: CloudServiceFinding) -> List[str]:
        """Generate security recommendations for cloud service finding."""
        recommendations = [
            "Review cloud service configuration for security best practices",
            "Ensure proper authentication and authorization mechanisms",
            "Use environment variables or secure vaults for credentials"
        ]
        
        if finding.credential_exposure:
            recommendations.extend([
                "Remove hardcoded credentials from source code",
                "Rotate exposed credentials immediately",
                "Implement proper credential management"
            ])
        
        if finding.public_access_risk:
            recommendations.extend([
                "Review and restrict public access permissions",
                "Implement proper access controls and policies"
            ])
        
        if finding.service_type == CloudServiceType.FIREBASE:
            recommendations.extend([
                "Configure Firebase security rules properly",
                "Use Firebase Authentication for user management",
                "Enable Firebase App Check for additional security"
            ])
        
        return recommendations
    
    def _get_cloud_service_cwe(self, service_type: CloudServiceType) -> Optional[str]:
        """Get CWE mapping for cloud service type."""
        cwe_mapping = {
            CloudServiceType.FIREBASE: "CWE-200",
            CloudServiceType.AWS_S3: "CWE-200",
            CloudServiceType.GOOGLE_CLOUD: "CWE-200",
            CloudServiceType.AZURE: "CWE-200",
            CloudServiceType.GENERIC_API: "CWE-200"
        }
        return cwe_mapping.get(service_type, "CWE-200")
    
    def _get_cloud_service_masvs_control(self, service_type: CloudServiceType) -> Optional[str]:
        """Get MASVS control mapping for cloud service type."""
        return "MSTG-NETWORK-01"  # Network Communication Requirements
    
    def get_analysis_statistics(self) -> Dict[str, int]:
        """Get statistics about cloud service analysis."""
        return {
            'total_services_detected': len(self.detected_services),
            'unique_services': len(set(service[0] for service in self.detected_services)),
            'unique_locations': len(set(service[1] for service in self.detected_services))
        } 
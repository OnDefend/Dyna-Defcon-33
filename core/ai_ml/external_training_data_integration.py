#!/usr/bin/env python3
"""
External Training Data Integration System

Comprehensive system for integrating third-party training data sources to enhance
AI/ML model training with diverse, high-quality datasets from external sources.

Supported Data Sources:
- CVE/NVD vulnerability databases
- OWASP testing datasets
- Academic research datasets
- Commercial threat intelligence feeds
- Open source vulnerability repositories
- Security conference datasets
- Bug bounty program data
- Penetration testing results

Features:
- Multi-format data ingestion (JSON, CSV, XML, API)
- Data validation and quality assurance
- Automated data preprocessing and normalization
- Privacy and security compliance
- License compliance checking
- Data versioning and provenance tracking
- Incremental updates and synchronization
- Custom data source plugins

"""

import logging
import json
import csv
import xml.etree.ElementTree as ET
import hashlib
import asyncio
import aiohttp
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import urlparse
import zipfile
import tarfile
import gzip
import re
import time

# Data processing imports
try:
    import pandas as pd
    import numpy as np
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.utils import resample
    DATA_PROCESSING_AVAILABLE = True
except ImportError:
    DATA_PROCESSING_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class DataSource:
    """External data source configuration."""
    source_id: str
    name: str
    source_type: str  # 'api', 'file', 'database', 'git_repo'
    url: Optional[str] = None
    file_path: Optional[str] = None
    format: str = 'json'  # 'json', 'csv', 'xml', 'custom'
    update_frequency: str = 'daily'  # 'hourly', 'daily', 'weekly', 'monthly'
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    authentication: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 1  # 1=highest, 5=lowest
    license: str = ""
    description: str = ""
    data_schema: Dict[str, Any] = field(default_factory=dict)
    last_updated: Optional[datetime] = None
    record_count: int = 0


@dataclass
class DataRecord:
    """Standardized data record format."""
    record_id: str
    source_id: str
    vulnerability_type: str
    severity: str
    content: str
    context: Dict[str, Any]
    label: int  # 0=safe, 1=vulnerable
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_training_sample(self) -> Dict[str, Any]:
        """Convert to ML training sample format."""
        return {
            'text': self.content,
            'label': self.label,
            'severity': self.severity,
            'vulnerability_type': self.vulnerability_type,
            'confidence': self.confidence,
            'context': self.context,
            'metadata': {
                **self.metadata,
                'source_id': self.source_id,
                'record_id': self.record_id,
                'created_at': self.created_at.isoformat()
            }
        }


@dataclass
class ValidationResult:
    """Data validation result."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    quality_score: float = 0.0
    processed_records: int = 0
    duplicate_records: int = 0
    invalid_records: int = 0


class ExternalDataIntegrator:
    """
    Main external training data integration system.
    """
    
    def __init__(self, config_file: str = "config/external_data_sources.json"):
        """
        Initialize external data integrator.
        
        Args:
            config_file: Path to data sources configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config_file = Path(config_file)
        self.data_dir = Path("data/external_training")
        self.cache_dir = Path("cache/external_data")
        
        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.data_sources: Dict[str, DataSource] = {}
        self.data_processors: Dict[str, Callable] = {}
        self.validation_rules: List[Callable] = []
        self.collected_data: List[DataRecord] = []
        
        # Statistics
        self.stats = {
            "total_sources": 0,
            "active_sources": 0,
            "total_records": 0,
            "successful_updates": 0,
            "failed_updates": 0,
            "last_update": None
        }
        
        # Initialize default configurations
        self._initialize_default_sources()
        self._initialize_data_processors()
        self._initialize_validation_rules()
        
        # Load configuration
        self._load_configuration()
        
        self.logger.info(f"External Data Integrator initialized with {len(self.data_sources)} sources")
    
    def _initialize_default_sources(self):
        """Initialize default external data sources."""
        default_sources = {
            "nvd_cve": DataSource(
                source_id="nvd_cve",
                name="National Vulnerability Database",
                source_type="api",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                format="json",
                update_frequency="daily",
                license="Public Domain",
                description="NIST National Vulnerability Database CVE entries",
                data_schema={
                    "vulnerability_field": "cve.description.description_data[0].value",
                    "severity_field": "impact.baseMetricV3.cvssV3.baseSeverity",
                    "score_field": "impact.baseMetricV3.cvssV3.baseScore"
                }
            ),
            
            "owasp_mastg": DataSource(
                source_id="owasp_mastg",
                name="OWASP Mobile Application Security Testing Guide",
                source_type="git_repo",
                url="https://github.com/OWASP/owasp-mastg",
                format="custom",
                update_frequency="weekly",
                license="Creative Commons",
                description="OWASP MASTG test cases and vulnerability patterns"
            ),
            
            "android_security_bulletins": DataSource(
                source_id="android_security_bulletins",
                name="Android Security Bulletins",
                source_type="api",
                url="https://source.android.com/security/bulletin",
                format="json",
                update_frequency="monthly",
                license="Apache 2.0",
                description="Official Android security bulletins and patches"
            ),
            
            "exploit_db": DataSource(
                source_id="exploit_db",
                name="Exploit Database",
                source_type="api",
                url="https://www.exploit-db.com/api/v1/search",
                format="json",
                update_frequency="daily",
                license="GPL",
                description="Exploit Database vulnerability and exploit information"
            ),
            
            "mitre_cwe": DataSource(
                source_id="mitre_cwe",
                name="MITRE Common Weakness Enumeration",
                source_type="api",
                url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                format="xml",
                update_frequency="monthly",
                license="MITRE",
                description="MITRE CWE database of software weaknesses"
            ),
            
            "github_security_advisories": DataSource(
                source_id="github_security_advisories",
                name="GitHub Security Advisories",
                source_type="api",
                url="https://api.github.com/advisories",
                format="json",
                update_frequency="daily",
                license="GitHub Terms",
                description="GitHub security advisories database",
                headers={"Accept": "application/vnd.github.v3+json"}
            ),
            
            "local_files": DataSource(
                source_id="local_files",
                name="Local Training Files",
                source_type="file",
                file_path="data/external_training/manual",
                format="json",
                update_frequency="manual",
                license="Internal",
                description="Manually curated training data files"
            )
        }
        
        self.data_sources.update(default_sources)
        self.stats["total_sources"] = len(default_sources)
    
    def _initialize_data_processors(self):
        """Initialize data processors for different formats."""
        self.data_processors = {
            'json': self._process_json_data,
            'csv': self._process_csv_data,
            'xml': self._process_xml_data,
            'custom': self._process_custom_data
        }
    
    def _initialize_validation_rules(self):
        """Initialize data validation rules."""
        self.validation_rules = [
            self._validate_required_fields,
            self._validate_data_types,
            self._validate_severity_values,
            self._validate_content_quality,
            self._validate_label_consistency,
            self._check_for_duplicates
        ]
    
    def _load_configuration(self):
        """Load external data sources configuration."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Update existing sources with configuration
                for source_id, source_config in config.get("sources", {}).items():
                    if source_id in self.data_sources:
                        # Update existing source
                        source = self.data_sources[source_id]
                        for key, value in source_config.items():
                            if hasattr(source, key) and key not in ['sources']:  # Skip nested 'sources' arrays
                                setattr(source, key, value)
                    else:
                        # Add new source - filter valid DataSource parameters
                        valid_params = {}
                        for key, value in source_config.items():
                            # Skip nested structures that aren't DataSource fields
                            if key not in ['sources', 'filters', 'data_extraction', 'providers', 'validation']:
                                valid_params[key] = value
                        
                        # Set required fields if missing
                        if 'name' not in valid_params:
                            valid_params['name'] = source_id.replace('_', ' ').title()
                        if 'source_type' not in valid_params:
                            valid_params['source_type'] = 'file'  # Default type
                        if 'format' not in valid_params:
                            valid_params['format'] = 'json'  # Default format
                        
                        try:
                            self.data_sources[source_id] = DataSource(
                                source_id=source_id,
                                **valid_params
                            )
                        except Exception as e:
                            self.logger.warning(f"Failed to create DataSource for {source_id}: {e}")
                            continue
                
                self.logger.info(f"Loaded configuration for {len(config.get('sources', {}))} sources")
                
            except Exception as e:
                self.logger.error(f"Failed to load configuration: {e}")
        else:
            self.logger.info("No configuration file found, using default sources only")
    
    def add_data_source(self, source: DataSource) -> bool:
        """
        Add a new external data source.
        
        Args:
            source: DataSource configuration
            
        Returns:
            Success status
        """
        try:
            # Validate source configuration
            if not source.source_id or not source.name:
                raise ValueError("Source ID and name are required")
            
            if source.source_type not in ['api', 'file', 'database', 'git_repo']:
                raise ValueError(f"Invalid source type: {source.source_type}")
            
            if source.format not in self.data_processors:
                raise ValueError(f"Unsupported format: {source.format}")
            
            # Add to sources
            self.data_sources[source.source_id] = source
            self.stats["total_sources"] = len(self.data_sources)
            
            self.logger.info(f"Added data source: {source.source_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add data source: {e}")
            return False
    
    def update_all_sources(self, force: bool = False) -> Dict[str, Any]:
        """
        Update all enabled data sources.
        
        Args:
            force: Force update regardless of schedule
            
        Returns:
            Update results summary
        """
        results = {
            "updated_sources": [],
            "failed_sources": [],
            "total_records": 0,
            "new_records": 0,
            "start_time": datetime.now(),
            "end_time": None
        }
        
        for source_id, source in self.data_sources.items():
            if not source.enabled:
                continue
            
            try:
                # Check if update is needed
                if not force and not self._should_update_source(source):
                    continue
                
                self.logger.info(f"Updating data source: {source_id}")
                
                # Fetch data
                raw_data = self._fetch_data(source)
                if not raw_data:
                    continue
                
                # Process data
                processed_data = self._process_data(source, raw_data)
                if not processed_data:
                    continue
                
                # Validate data
                validation_result = self._validate_data(processed_data)
                if not validation_result.is_valid:
                    self.logger.warning(f"Data validation failed for {source_id}: {validation_result.errors}")
                    results["failed_sources"].append(source_id)
                    continue
                
                # Convert to data records
                data_records = self._convert_to_data_records(source, processed_data)
                
                # Update statistics
                source.last_updated = datetime.now()
                source.record_count = len(data_records)
                results["updated_sources"].append(source_id)
                results["total_records"] += len(data_records)
                results["new_records"] += len(data_records)
                
                # Store data
                self._store_data_records(source_id, data_records)
                self.collected_data.extend(data_records)
                
                self.stats["successful_updates"] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to update source {source_id}: {e}")
                results["failed_sources"].append(source_id)
                self.stats["failed_updates"] += 1
        
        results["end_time"] = datetime.now()
        self.stats["last_update"] = results["end_time"]
        
        self.logger.info(f"Update completed: {len(results['updated_sources'])} successful, "
                        f"{len(results['failed_sources'])} failed")
        
        return results
    
    def _should_update_source(self, source: DataSource) -> bool:
        """Check if a source should be updated based on schedule."""
        if not source.last_updated:
            return True
        
        frequency_mapping = {
            'hourly': timedelta(hours=1),
            'daily': timedelta(days=1),
            'weekly': timedelta(weeks=1),
            'monthly': timedelta(days=30),
            'manual': timedelta(days=365)  # Never auto-update
        }
        
        interval = frequency_mapping.get(source.update_frequency, timedelta(days=1))
        return datetime.now() - source.last_updated > interval
    
    def _fetch_data(self, source: DataSource) -> Optional[Any]:
        """Fetch data from external source."""
        try:
            if source.source_type == 'api':
                return self._fetch_api_data(source)
            elif source.source_type == 'file':
                return self._fetch_file_data(source)
            elif source.source_type == 'database':
                return self._fetch_database_data(source)
            elif source.source_type == 'git_repo':
                return self._fetch_git_repo_data(source)
            else:
                raise ValueError(f"Unsupported source type: {source.source_type}")
        
        except Exception as e:
            self.logger.error(f"Failed to fetch data from {source.source_id}: {e}")
            return None
    
    def _fetch_api_data(self, source: DataSource) -> Optional[Any]:
        """Fetch data from API endpoint."""
        headers = {**source.headers}
        if source.api_key:
            headers['Authorization'] = f"Bearer {source.api_key}"
        
        params = {}
        
        # Add date filters for incremental updates
        if source.last_updated and source.source_id == 'nvd_cve':
            params['lastModStartDate'] = source.last_updated.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['lastModEndDate'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        
        response = requests.get(source.url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        if source.format == 'json':
            return response.json()
        else:
            return response.text
    
    def _fetch_file_data(self, source: DataSource) -> Optional[Any]:
        """Fetch data from local files."""
        if not source.file_path:
            return None
        
        file_path = Path(source.file_path)
        if not file_path.exists():
            return None
        
        all_data = []
        
        if file_path.is_file():
            files = [file_path]
        else:
            # Process all files in directory
            pattern = f"*.{source.format}"
            files = list(file_path.glob(pattern))
        
        for file in files:
            try:
                if source.format == 'json':
                    with open(file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_data.extend(data)
                        else:
                            all_data.append(data)
                elif source.format == 'csv':
                    with open(file, 'r') as f:
                        reader = csv.DictReader(f)
                        all_data.extend(list(reader))
                
            except Exception as e:
                self.logger.warning(f"Failed to read file {file}: {e}")
        
        return all_data
    
    def _fetch_database_data(self, source: DataSource) -> Optional[Any]:
        """Fetch data from database (placeholder for future implementation)."""
        # This would be implemented based on specific database requirements
        self.logger.warning(f"Database source not yet implemented: {source.source_id}")
        return None
    
    def _fetch_git_repo_data(self, source: DataSource) -> Optional[Any]:
        """Fetch data from Git repository (placeholder for future implementation)."""
        # This would clone/pull the repository and extract relevant data
        self.logger.warning(f"Git repository source not yet implemented: {source.source_id}")
        return None
    
    def _process_data(self, source: DataSource, raw_data: Any) -> Optional[List[Dict[str, Any]]]:
        """Process raw data using appropriate processor."""
        processor = self.data_processors.get(source.format)
        if not processor:
            self.logger.error(f"No processor found for format: {source.format}")
            return None
        
        return processor(source, raw_data)
    
    def _process_json_data(self, source: DataSource, raw_data: Any) -> List[Dict[str, Any]]:
        """Process JSON data."""
        processed_data = []
        
        if source.source_id == 'nvd_cve':
            # Process NVD CVE data
            vulnerabilities = raw_data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                
                # Extract description
                descriptions = cve.get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                
                # Extract severity
                metrics = vuln.get('cve', {}).get('metrics', {})
                severity = 'MEDIUM'
                cvss_score = 5.0
                
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    severity = cvss_data.get('baseSeverity', 'MEDIUM')
                    cvss_score = cvss_data.get('baseScore', 5.0)
                
                processed_data.append({
                    'id': cve.get('id', ''),
                    'description': description,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'published_date': cve.get('published', ''),
                    'last_modified': cve.get('lastModified', ''),
                    'vulnerability_type': self._extract_vulnerability_type(description),
                    'label': 1,  # CVE entries are vulnerabilities
                    'confidence': 0.9
                })
        
        elif source.source_id == 'github_security_advisories':
            # Process GitHub security advisories
            if isinstance(raw_data, list):
                for advisory in raw_data:
                    processed_data.append({
                        'id': advisory.get('ghsa_id', ''),
                        'description': advisory.get('description', ''),
                        'severity': advisory.get('severity', 'MEDIUM').upper(),
                        'published_date': advisory.get('published_at', ''),
                        'vulnerability_type': self._extract_vulnerability_type(advisory.get('description', '')),
                        'label': 1,
                        'confidence': 0.85
                    })
        
        else:
            # Generic JSON processing
            if isinstance(raw_data, list):
                processed_data = raw_data
            elif isinstance(raw_data, dict):
                processed_data = [raw_data]
        
        return processed_data
    
    def _process_csv_data(self, source: DataSource, raw_data: Any) -> List[Dict[str, Any]]:
        """Process CSV data."""
        if isinstance(raw_data, str):
            # Parse CSV string
            import io
            reader = csv.DictReader(io.StringIO(raw_data))
            return list(reader)
        elif isinstance(raw_data, list):
            return raw_data
        else:
            return []
    
    def _process_xml_data(self, source: DataSource, raw_data: Any) -> List[Dict[str, Any]]:
        """Process XML data."""
        processed_data = []
        
        try:
            if isinstance(raw_data, str):
                root = ET.fromstring(raw_data)
            else:
                root = raw_data
            
            if source.source_id == 'mitre_cwe':
                # Process MITRE CWE data
                for weakness in root.findall('.//Weakness'):
                    weakness_id = weakness.get('ID', '')
                    name = weakness.get('Name', '')
                    description_elem = weakness.find('.//Description')
                    description = description_elem.text if description_elem is not None else ''
                    
                    processed_data.append({
                        'id': f"CWE-{weakness_id}",
                        'name': name,
                        'description': description,
                        'vulnerability_type': self._map_cwe_to_vuln_type(weakness_id),
                        'severity': 'MEDIUM',  # Default severity for CWE
                        'label': 1,
                        'confidence': 0.8
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to process XML data: {e}")
        
        return processed_data
    
    def _process_custom_data(self, source: DataSource, raw_data: Any) -> List[Dict[str, Any]]:
        """Process custom format data."""
        # This would be implemented based on specific requirements
        # For now, assume it's already in the correct format
        if isinstance(raw_data, list):
            return raw_data
        elif isinstance(raw_data, dict):
            return [raw_data]
        else:
            return []
    
    def _extract_vulnerability_type(self, description: str) -> str:
        """Extract vulnerability type from description."""
        description_lower = description.lower()
        
        if any(term in description_lower for term in ['sql injection', 'sqli']):
            return 'SQL_INJECTION'
        elif any(term in description_lower for term in ['cross-site scripting', 'xss']):
            return 'XSS'
        elif any(term in description_lower for term in ['remote code execution', 'rce']):
            return 'RCE'
        elif any(term in description_lower for term in ['authentication', 'auth']):
            return 'AUTHENTICATION'
        elif any(term in description_lower for term in ['authorization', 'privilege']):
            return 'AUTHORIZATION'
        elif any(term in description_lower for term in ['encryption', 'crypto']):
            return 'CRYPTOGRAPHY'
        elif any(term in description_lower for term in ['buffer overflow', 'overflow']):
            return 'BUFFER_OVERFLOW'
        elif any(term in description_lower for term in ['denial of service', 'dos']):
            return 'DOS'
        else:
            return 'OTHER'
    
    def _map_cwe_to_vuln_type(self, cwe_id: str) -> str:
        """Map CWE ID to vulnerability type."""
        cwe_mapping = {
            '79': 'XSS',
            '89': 'SQL_INJECTION',
            '94': 'CODE_INJECTION',
            '119': 'BUFFER_OVERFLOW',
            '200': 'INFORMATION_DISCLOSURE',
            '287': 'AUTHENTICATION',
            '295': 'CERTIFICATE_VALIDATION',
            '311': 'CRYPTOGRAPHY',
            '352': 'CSRF',
            '434': 'FILE_UPLOAD',
            '502': 'DESERIALIZATION'
        }
        
        return cwe_mapping.get(cwe_id, 'OTHER')
    
    def _validate_data(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate processed data quality."""
        result = ValidationResult(is_valid=True)
        
        if not data:
            result.is_valid = False
            result.errors.append("No data to validate")
            return result
        
        # Run validation rules
        for rule in self.validation_rules:
            try:
                rule_result = rule(data)
                if not rule_result.is_valid:
                    result.is_valid = False
                    result.errors.extend(rule_result.errors)
                result.warnings.extend(rule_result.warnings)
            except Exception as e:
                result.warnings.append(f"Validation rule failed: {e}")
        
        # Calculate quality score
        total_records = len(data)
        valid_records = total_records - result.invalid_records
        result.quality_score = valid_records / total_records if total_records > 0 else 0.0
        result.processed_records = total_records
        
        return result
    
    def _validate_required_fields(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate required fields are present."""
        result = ValidationResult(is_valid=True)
        required_fields = ['description', 'label']
        
        for i, record in enumerate(data):
            missing_fields = [field for field in required_fields if field not in record or not record[field]]
            if missing_fields:
                result.errors.append(f"Record {i}: Missing required fields: {missing_fields}")
                result.invalid_records += 1
        
        if result.invalid_records > 0:
            result.is_valid = False
        
        return result
    
    def _validate_data_types(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate data types are correct."""
        result = ValidationResult(is_valid=True)
        
        for i, record in enumerate(data):
            # Validate label is integer
            if 'label' in record:
                try:
                    int(record['label'])
                except (ValueError, TypeError):
                    result.errors.append(f"Record {i}: Invalid label type")
                    result.invalid_records += 1
            
            # Validate confidence is float
            if 'confidence' in record:
                try:
                    float(record['confidence'])
                except (ValueError, TypeError):
                    result.warnings.append(f"Record {i}: Invalid confidence type")
        
        return result
    
    def _validate_severity_values(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate severity values are valid."""
        result = ValidationResult(is_valid=True)
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        
        for i, record in enumerate(data):
            if 'severity' in record:
                severity = str(record['severity']).upper()
                if severity not in valid_severities:
                    result.warnings.append(f"Record {i}: Invalid severity value: {severity}")
        
        return result
    
    def _validate_content_quality(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate content quality."""
        result = ValidationResult(is_valid=True)
        
        for i, record in enumerate(data):
            description = record.get('description', '')
            
            # Check minimum length
            if len(description) < 10:
                result.warnings.append(f"Record {i}: Description too short")
            
            # Check for meaningful content
            if not re.search(r'[a-zA-Z]', description):
                result.warnings.append(f"Record {i}: Description lacks meaningful content")
        
        return result
    
    def _validate_label_consistency(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Validate label consistency with content."""
        result = ValidationResult(is_valid=True)
        
        for i, record in enumerate(data):
            label = record.get('label', 0)
            description = record.get('description', '').lower()
            
            # Check for obvious mismatches
            vulnerability_indicators = ['vulnerability', 'exploit', 'attack', 'malicious', 'security']
            safe_indicators = ['secure', 'safe', 'protected', 'no issues', 'passed']
            
            has_vuln_indicators = any(indicator in description for indicator in vulnerability_indicators)
            has_safe_indicators = any(indicator in description for indicator in safe_indicators)
            
            if label == 1 and has_safe_indicators and not has_vuln_indicators:
                result.warnings.append(f"Record {i}: Positive label but safe content")
            elif label == 0 and has_vuln_indicators and not has_safe_indicators:
                result.warnings.append(f"Record {i}: Negative label but vulnerability content")
        
        return result
    
    def _check_for_duplicates(self, data: List[Dict[str, Any]]) -> ValidationResult:
        """Check for duplicate records."""
        result = ValidationResult(is_valid=True)
        seen_hashes = set()
        
        for i, record in enumerate(data):
            # Create hash of key fields
            key_fields = [
                record.get('description', ''),
                str(record.get('label', '')),
                record.get('vulnerability_type', '')
            ]
            record_hash = hashlib.md5(''.join(key_fields).encode()).hexdigest()
            
            if record_hash in seen_hashes:
                result.duplicate_records += 1
                result.warnings.append(f"Record {i}: Potential duplicate found")
            else:
                seen_hashes.add(record_hash)
        
        return result
    
    def _convert_to_data_records(self, source: DataSource, data: List[Dict[str, Any]]) -> List[DataRecord]:
        """Convert processed data to standardized DataRecord format."""
        data_records = []
        
        for i, item in enumerate(data):
            try:
                record = DataRecord(
                    record_id=f"{source.source_id}_{i}_{datetime.now().strftime('%Y%m%d')}",
                    source_id=source.source_id,
                    vulnerability_type=item.get('vulnerability_type', 'OTHER'),
                    severity=item.get('severity', 'MEDIUM'),
                    content=item.get('description', ''),
                    context={
                        'source_type': source.source_type,
                        'format': source.format,
                        'cvss_score': item.get('cvss_score'),
                        'published_date': item.get('published_date'),
                        'cve_id': item.get('id')
                    },
                    label=int(item.get('label', 0)),
                    confidence=float(item.get('confidence', 0.5)),
                    metadata={
                        'original_data': item,
                        'source_priority': source.priority
                    }
                )
                data_records.append(record)
                
            except Exception as e:
                self.logger.warning(f"Failed to convert record {i} from {source.source_id}: {e}")
        
        return data_records
    
    def _store_data_records(self, source_id: str, records: List[DataRecord]):
        """Store data records to file system."""
        try:
            output_file = self.data_dir / f"{source_id}_{datetime.now().strftime('%Y%m%d')}.json"
            
            # Convert to serializable format
            serializable_records = [record.to_training_sample() for record in records]
            
            with open(output_file, 'w') as f:
                json.dump(serializable_records, f, indent=2, default=str)
            
            self.logger.info(f"Stored {len(records)} records to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to store records for {source_id}: {e}")
    
    def get_training_data(self, 
                         source_ids: Optional[List[str]] = None,
                         min_confidence: float = 0.5,
                         balance_classes: bool = True,
                         max_records: Optional[int] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Get training data from collected external sources.
        
        Args:
            source_ids: Specific source IDs to include (None for all)
            min_confidence: Minimum confidence threshold
            balance_classes: Whether to balance positive/negative classes
            max_records: Maximum number of records to return
            
        Returns:
            Tuple of (training_data, metadata)
        """
        # Filter data by criteria
        filtered_data = []
        
        for record in self.collected_data:
            # Filter by source
            if source_ids and record.source_id not in source_ids:
                continue
            
            # Filter by confidence
            if record.confidence < min_confidence:
                continue
            
            filtered_data.append(record.to_training_sample())
        
        # Balance classes if requested
        if balance_classes and DATA_PROCESSING_AVAILABLE:
            df = pd.DataFrame(filtered_data)
            if 'label' in df.columns:
                # Separate classes
                positive_samples = df[df['label'] == 1]
                negative_samples = df[df['label'] == 0]
                
                # Balance to smaller class size
                min_size = min(len(positive_samples), len(negative_samples))
                if min_size > 0:
                    positive_balanced = resample(positive_samples, 
                                               n_samples=min_size, 
                                               random_state=42)
                    negative_balanced = resample(negative_samples,
                                               n_samples=min_size,
                                               random_state=42)
                    
                    balanced_df = pd.concat([positive_balanced, negative_balanced])
                    filtered_data = balanced_df.to_dict('records')
        
        # Limit number of records
        if max_records and len(filtered_data) > max_records:
            filtered_data = filtered_data[:max_records]
        
        # Generate metadata
        metadata = {
            'total_records': len(filtered_data),
            'sources_used': list(set(record.get('metadata', {}).get('source_id') for record in filtered_data)),
            'label_distribution': {},
            'severity_distribution': {},
            'vulnerability_type_distribution': {},
            'generated_at': datetime.now().isoformat()
        }
        
        # Calculate distributions
        if filtered_data:
            labels = [record.get('label', 0) for record in filtered_data]
            metadata['label_distribution'] = {
                'vulnerable': labels.count(1),
                'safe': labels.count(0)
            }
            
            severities = [record.get('severity', 'UNKNOWN') for record in filtered_data]
            metadata['severity_distribution'] = dict(Counter(severities))
            
            vuln_types = [record.get('vulnerability_type', 'UNKNOWN') for record in filtered_data]
            metadata['vulnerability_type_distribution'] = dict(Counter(vuln_types))
        
        self.logger.info(f"Generated training data: {len(filtered_data)} records from "
                        f"{len(metadata['sources_used'])} sources")
        
        return filtered_data, metadata
    
    def export_training_data(self, 
                           output_file: str,
                           format: str = 'json',
                           **kwargs) -> bool:
        """
        Export training data to file.
        
        Args:
            output_file: Output file path
            format: Export format ('json', 'csv', 'pkl')
            **kwargs: Additional arguments for get_training_data()
            
        Returns:
            Success status
        """
        try:
            training_data, metadata = self.get_training_data(**kwargs)
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump({
                        'training_data': training_data,
                        'metadata': metadata
                    }, f, indent=2, default=str)
            
            elif format == 'csv' and DATA_PROCESSING_AVAILABLE:
                df = pd.DataFrame(training_data)
                df.to_csv(output_path, index=False)
                
                # Save metadata separately
                metadata_file = output_path.with_suffix('.metadata.json')
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2, default=str)
            
            elif format == 'pkl' and DATA_PROCESSING_AVAILABLE:
                import pickle
                with open(output_path, 'wb') as f:
                    pickle.dump({'training_data': training_data, 'metadata': metadata}, f)
            
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Exported {len(training_data)} training samples to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export training data: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about external data integration."""
        stats = self.stats.copy()
        
        # Add source-specific statistics
        source_stats = {}
        for source_id, source in self.data_sources.items():
            source_stats[source_id] = {
                'enabled': source.enabled,
                'last_updated': source.last_updated.isoformat() if source.last_updated else None,
                'record_count': source.record_count,
                'update_frequency': source.update_frequency,
                'priority': source.priority
            }
        
        stats['sources'] = source_stats
        stats['collected_records'] = len(self.collected_data)
        
        # Label distribution
        if self.collected_data:
            labels = [record.label for record in self.collected_data]
            stats['label_distribution'] = {
                'vulnerable': labels.count(1),
                'safe': labels.count(0)
            }
            
            # Source distribution
            sources = [record.source_id for record in self.collected_data]
            stats['source_distribution'] = dict(Counter(sources))
        
        return stats


# Integration with existing AODS AI/ML training pipeline
def integrate_external_data_with_aods(ai_manager, external_integrator: ExternalDataIntegrator):
    """
    Integrate external training data with AODS AI/ML training pipeline.
    
    Args:
        ai_manager: AODS AI/ML integration manager
        external_integrator: External data integrator instance
    """
    try:
        # Get external training data
        external_data, metadata = external_integrator.get_training_data(
            min_confidence=0.7,
            balance_classes=True,
            max_records=10000
        )
        
        # Convert to AODS format and add to training pipeline
        for record in external_data:
            ai_manager.vulnerability_detector.add_feedback(
                text=record['text'],
                actual_result=bool(record['label']),
                user_feedback=f"External data from {record['metadata']['source_id']}"
            )
            
            ai_manager.fp_reducer.add_feedback(
                text=record['text'],
                is_actual_fp=(record['label'] == 0),
                user_notes=f"External data: {record.get('vulnerability_type', 'unknown')}"
            )
        
        # Trigger model retraining
        training_results = ai_manager.train_from_feedback(external_data)
        
        logging.info(f"Integrated {len(external_data)} external training samples")
        logging.info(f"Training results: {training_results}")
        
        return training_results
        
    except Exception as e:
        logging.error(f"Failed to integrate external data with AODS: {e}")
        return None


# Example usage and testing
if __name__ == "__main__":
    # Initialize external data integrator
    integrator = ExternalDataIntegrator()
    
    # Add custom data source
    custom_source = DataSource(
        source_id="custom_vulns",
        name="Custom Vulnerability Dataset",
        source_type="file",
        file_path="data/custom_vulnerabilities.json",
        format="json",
        update_frequency="weekly",
        license="Internal Use"
    )
    integrator.add_data_source(custom_source)
    
    # Update all sources
    results = integrator.update_all_sources()
    print(f"Update results: {results}")
    
    # Get training data
    training_data, metadata = integrator.get_training_data(
        min_confidence=0.6,
        balance_classes=True,
        max_records=1000
    )
    
    print(f"Generated {len(training_data)} training samples")
    print(f"Metadata: {metadata}")
    
    # Export training data
    integrator.export_training_data(
        "output/external_training_data.json",
        format="json"
    ) 
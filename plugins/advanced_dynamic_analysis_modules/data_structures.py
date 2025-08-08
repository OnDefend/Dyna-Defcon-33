"""
Data Structures for Advanced Dynamic Analysis Plugin

This module defines the core data structures used throughout the advanced dynamic
analysis plugin for consistent data handling and type safety.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class DeviceStatus(Enum):
    """Device connection status enumeration"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    UNKNOWN = "unknown"

class AppStatus(Enum):
    """Application installation status enumeration"""
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    INSTALL_FAILED = "install_failed"
    UNINSTALL_FAILED = "uninstall_failed"
    UNKNOWN = "unknown"

class NetworkStatus(Enum):
    """Network analysis status enumeration"""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PROXY_ERROR = "proxy_error"
    CONFIGURATION_ERROR = "configuration_error"
    UNKNOWN = "unknown"

class AnalysisType(Enum):
    """Type of dynamic analysis performed"""
    DYNAMIC = "dynamic"
    INTENT_FUZZING = "intent_fuzzing"
    NETWORK_TRAFFIC = "network_traffic"
    WEBVIEW_SECURITY = "webview_security"
    RUNTIME_MONITORING = "runtime_monitoring"
    EXTERNAL_SERVICE = "external_service"
    COMPREHENSIVE = "comprehensive"

class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class DeviceInfo:
    """Device information structure"""
    device_id: str
    status: DeviceStatus
    android_version: Optional[str] = None
    api_level: Optional[int] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    architecture: Optional[str] = None
    root_status: Optional[bool] = None
    error_message: Optional[str] = None

@dataclass
class AppInfo:
    """Application information structure"""
    package_name: str
    status: AppStatus
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    install_location: Optional[str] = None
    permissions: Optional[List[str]] = None
    activities: Optional[List[str]] = None
    services: Optional[List[str]] = None
    receivers: Optional[List[str]] = None
    error_message: Optional[str] = None

@dataclass
class NetworkConfig:
    """Network analysis configuration"""
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    proxy_type: str = "http"
    mitm_available: bool = False
    certificate_path: Optional[str] = None
    capture_duration: int = 30
    max_requests: int = 1000
    filter_patterns: Optional[List[str]] = None

@dataclass
class DynamicAnalysisConfig:
    """Configuration for dynamic analysis"""
    analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE
    timeout: int = 300
    max_iterations: int = 100
    deep_mode: bool = True
    enable_intent_fuzzing: bool = True
    enable_network_analysis: bool = True
    enable_webview_testing: bool = True
    enable_runtime_monitoring: bool = True
    network_config: NetworkConfig = None
    custom_scripts: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.network_config is None:
            self.network_config = NetworkConfig()

@dataclass
class Finding:
    """Individual security finding"""
    id: str
    title: str
    description: str
    risk_level: RiskLevel
    category: str
    masvs_control: str
    evidence: Dict[str, Any]
    remediation: str
    confidence: float
    timestamp: datetime
    source_component: str
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class AnalysisResult:
    """Complete analysis result structure"""
    analysis_id: str
    package_name: str
    analysis_type: AnalysisType
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    device_info: Optional[DeviceInfo] = None
    app_info: Optional[AppInfo] = None
    network_config: Optional[NetworkConfig] = None
    findings: List[Finding] = None
    summary: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    error_message: Optional[str] = None
    network_analysis: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.summary is None:
            self.summary = {}
        if self.metadata is None:
            self.metadata = {}
        if self.end_time is None and self.status in ["completed", "failed"]:
            self.end_time = datetime.now()
    
    def add_finding(self, finding: Finding):
        """Add a finding to the analysis result"""
        self.findings.append(finding)
    
    def get_findings_by_risk(self, risk_level: RiskLevel) -> List[Finding]:
        """Get findings filtered by risk level"""
        return [f for f in self.findings if f.risk_level == risk_level]
    
    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings filtered by category"""
        return [f for f in self.findings if f.category == category]
    
    def get_risk_summary(self) -> Dict[str, int]:
        """Get summary of findings by risk level"""
        risk_counts = {level.value: 0 for level in RiskLevel}
        for finding in self.findings:
            risk_counts[finding.risk_level.value] += 1
        return risk_counts

@dataclass
class ComponentStatus:
    """Status of individual analysis components"""
    component_name: str
    status: str
    start_time: datetime
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    results: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = {}

# Common constants
DEFAULT_TIMEOUT = 300
DEFAULT_MAX_ITERATIONS = 100
DEFAULT_ANALYSIS_TYPE = AnalysisType.COMPREHENSIVE
DEFAULT_RISK_LEVEL = RiskLevel.INFO

# MASVS control mappings
MASVS_CONTROLS = {
    "MSTG-PLATFORM-01": "App Permissions and Intent Handling",
    "MSTG-PLATFORM-02": "WebView Security Configuration", 
    "MASVS-PLATFORM-3": "WebView JavaScript Bridge Security",
    "MSTG-NETWORK-01": "Network Architecture Analysis",
    "MSTG-NETWORK-02": "Network Request Authentication",
    "MSTG-CODE-02": "Dynamic Code Loading Protection",
    "MSTG-RESILIENCE-10": "Runtime Application Self Protection"
}

# Risk level colors for display
RISK_COLORS = {
    RiskLevel.CRITICAL: "red",
    RiskLevel.HIGH: "orange",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.INFO: "blue"
} 
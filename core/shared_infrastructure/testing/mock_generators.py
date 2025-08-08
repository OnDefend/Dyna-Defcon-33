#!/usr/bin/env python3
"""
Mock Generators for AODS Testing Framework

Comprehensive mock object generation for AODS components, enabling consistent
and realistic testing scenarios across the platform.

Features:
- Mock APK contexts with realistic data structures
- Mock analysis contexts with dependency injection
- Mock vulnerability and security findings
- Mock plugin managers and execution contexts
- Mock network and file system components
- Configurable mock data for different test scenarios
- Integration with existing AODS data structures

This component provides high-quality mock objects that mirror real AODS
components for comprehensive unit and integration testing.
"""

import os
import time
import json
import tempfile
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import uuid

from ..analysis_exceptions import ContextualLogger

logger = logging.getLogger(__name__)

@dataclass
class MockConfiguration:
    """Configuration for mock object generation."""
    package_name: str = "com.test.mock.app"
    apk_size_mb: float = 25.0
    complexity_level: str = "medium"  # simple, medium, complex
    vulnerability_count: int = 5
    include_real_data: bool = True
    enable_network_mocks: bool = True
    enable_file_mocks: bool = True
    simulation_delay: float = 0.1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'package_name': self.package_name,
            'apk_size_mb': self.apk_size_mb,
            'complexity_level': self.complexity_level,
            'vulnerability_count': self.vulnerability_count,
            'include_real_data': self.include_real_data,
            'enable_network_mocks': self.enable_network_mocks,
            'enable_file_mocks': self.enable_file_mocks,
            'simulation_delay': self.simulation_delay
        }

class MockAPKContext:
    """
    Comprehensive mock APK context for testing.
    
    Provides realistic APK context with configurable data
    for different testing scenarios.
    """
    
    def __init__(self, config: MockConfiguration):
        self.config = config
        self.logger = ContextualLogger("mock_apk_context")
        
        # Basic APK information
        self.package_name = config.package_name
        self.apk_path = f"/mock/path/{config.package_name}.apk"
        self.apk_size = int(config.apk_size_mb * 1024 * 1024)
        
        # Directory paths
        self.jadx_output_dir = f"/mock/jadx/{config.package_name}"
        self.apktool_output_dir = f"/mock/apktool/{config.package_name}"
        self.temp_dir = f"/mock/temp/{config.package_name}"
        
        # APK components
        self.manifest_path = f"{self.apktool_output_dir}/AndroidManifest.xml"
        self.source_files = self._generate_source_files()
        self.resource_files = self._generate_resource_files()
        self.native_libraries = self._generate_native_libraries()
        self.certificates = self._generate_certificates()
        
        # Analysis cache
        self._cache = {}
        
        # Metadata
        self.analysis_metadata = {
            'created_at': datetime.now().isoformat(),
            'mock_version': '1.0.0',
            'configuration': config.to_dict()
        }
    
    def _generate_source_files(self) -> Dict[str, str]:
        """Generate mock source files based on complexity level."""
        base_files = {
            f"com/test/mock/{self.package_name.replace('.', '/')}/MainActivity.java": """
public class MainActivity extends AppCompatActivity {
    private static final String API_KEY = "sk_test_1234567890abcdef";
    private String serverUrl = "https://api.example.com/v1/";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Test network request
        makeApiRequest();
    }
    
    private void makeApiRequest() {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(serverUrl + "data");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("Authorization", "Bearer " + API_KEY);
            connection.setRequestMethod("GET");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                // Process response
            }
        } catch (Exception e) {
            Log.e("MainActivity", "API request failed", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
            """,
            f"com/test/mock/{self.package_name.replace('.', '/')}/DatabaseHelper.java": """
public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "app_database.db";
    private static final int DATABASE_VERSION = 1;
    
    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }
    
    public User getUserById(String userId) {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Cursor cursor = db.rawQuery(query, null);
        
        User user = null;
        if (cursor.moveToFirst()) {
            user = new User();
            user.setId(cursor.getString(0));
            user.setName(cursor.getString(1));
        }
        cursor.close();
        return user;
    }
}
            """,
            f"com/test/mock/{self.package_name.replace('.', '/')}/CryptoUtils.java": """
public class CryptoUtils {
    private static final String ENCRYPTION_KEY = "mySecretKey123";
    
    public static String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        } catch (Exception e) {
            return null;
        }
    }
    
    public static String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.DEFAULT));
            return new String(decrypted);
        } catch (Exception e) {
            return null;
        }
    }
}
            """
        }
        
        # Add complexity-based files
        if self.config.complexity_level == "complex":
            base_files.update({
                f"com/test/mock/{self.package_name.replace('.', '/')}/NetworkManager.java": """
public class NetworkManager {
    private static final String BASE_URL = "http://10.0.2.2:8080/api/";
    private static final String SECRET_TOKEN = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
    
    public void sendUserData(String userData) {
        // Potential data leak - sending sensitive data over HTTP
        String url = BASE_URL + "user/data?token=" + SECRET_TOKEN;
        // Implementation would send data
    }
}
                """,
                f"com/test/mock/{self.package_name.replace('.', '/')}/FileManager.java": """
public class FileManager {
    public void saveCredentials(String username, String password) {
        try {
            File file = new File(getExternalFilesDir(null), "credentials.txt");
            FileWriter writer = new FileWriter(file);
            writer.write(username + ":" + password);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
                """
            })
        
        return base_files
    
    def _generate_resource_files(self) -> Dict[str, str]:
        """Generate mock resource files."""
        return {
            "res/values/strings.xml": """
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Mock Test App</string>
    <string name="api_endpoint">https://api.mocktest.com/v1/</string>
    <string name="api_key">sk_test_mock_key_1234567890</string>
    <string name="database_password">admin123</string>
    <string name="encryption_key">mySecretEncryptionKey</string>
    <string name="server_ip">192.168.1.100</string>
</resources>
            """,
            "res/values/config.xml": """
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="server_url">http://insecure-api.example.com</string>
    <bool name="debug_mode">true</bool>
    <bool name="ssl_verification">false</bool>
    <integer name="connection_timeout">30000</integer>
</resources>
            """,
            "AndroidManifest.xml": f"""
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{self.package_name}">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:name=".MockApplication">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <activity
            android:name=".SettingsActivity"
            android:exported="true" />
        
        <service
            android:name=".BackgroundService"
            android:exported="false" />
        
        <receiver
            android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        
    </application>
</manifest>
            """
        }
    
    def _generate_native_libraries(self) -> List[str]:
        """Generate mock native library list."""
        return [
            "lib/arm64-v8a/libnative.so",
            "lib/arm64-v8a/libssl.so",
            "lib/armeabi-v7a/libnative.so",
            "lib/armeabi-v7a/libssl.so"
        ]
    
    def _generate_certificates(self) -> List[Dict[str, Any]]:
        """Generate mock certificate information."""
        return [
            {
                "subject": f"CN=Mock Test App, O=Test Organization, C=US",
                "issuer": "CN=Test CA, O=Test CA Organization, C=US",
                "serial_number": "1234567890",
                "not_before": "2023-01-01T00:00:00Z",
                "not_after": "2025-01-01T00:00:00Z",
                "signature_algorithm": "SHA256withRSA",
                "version": 3
            }
        ]
    
    # APK Context interface methods
    def get_package_name(self) -> str:
        """Get package name."""
        return self.package_name
    
    def get_apk_path(self) -> str:
        """Get APK file path."""
        return self.apk_path
    
    def get_source_files(self) -> Dict[str, str]:
        """Get source files."""
        return self.source_files
    
    def get_manifest_content(self) -> str:
        """Get manifest content."""
        return self.resource_files.get("AndroidManifest.xml", "")
    
    def get_cache(self, key: str, default=None) -> Any:
        """Get cached value."""
        return self._cache.get(key, default)
    
    def set_cache(self, key: str, value: Any) -> None:
        """Set cached value."""
        self._cache[key] = value
    
    def get_classes(self) -> List[str]:
        """Get list of classes."""
        classes = []
        for file_path in self.source_files.keys():
            if file_path.endswith('.java'):
                class_name = file_path.replace('/', '.').replace('.java', '')
                classes.append(class_name)
        return classes
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """Get content of specific file."""
        return self.source_files.get(file_path) or self.resource_files.get(file_path)

class MockAnalysisContext:
    """Mock analysis context for dependency injection testing."""
    
    def __init__(self, apk_ctx: MockAPKContext, plugin_name: str = "mock_plugin"):
        self.apk_ctx = apk_ctx
        self.plugin_name = plugin_name
        self.analysis_type = "mock_analysis"
        self.config = {}
        self.logger = ContextualLogger(f"mock_analysis_{plugin_name}")
        
        # Mock services
        self.pattern_matcher = self._create_mock_pattern_matcher()
        self.confidence_calculator = self._create_mock_confidence_calculator()
        self.vulnerability_detector = self._create_mock_vulnerability_detector()
    
    def _create_mock_pattern_matcher(self):
        """Create mock pattern matcher."""
        mock_matcher = Mock()
        mock_matcher.find_patterns.return_value = [
            {
                'pattern_name': 'hardcoded_secret',
                'matches': ['sk_test_1234567890abcdef', 'mySecretKey123'],
                'confidence': 0.85
            },
            {
                'pattern_name': 'sql_injection',
                'matches': ["SELECT * FROM users WHERE id = '" + userId + "'"],
                'confidence': 0.92
            }
        ]
        return mock_matcher
    
    def _create_mock_confidence_calculator(self):
        """Create mock confidence calculator."""
        mock_calculator = Mock()
        mock_calculator.calculate_confidence.return_value = 0.78
        return mock_calculator
    
    def _create_mock_vulnerability_detector(self):
        """Create mock vulnerability detector."""
        mock_detector = Mock()
        mock_detector.detect_vulnerabilities.return_value = [
            {
                'type': 'Hardcoded Secret',
                'severity': 'HIGH',
                'description': 'API key found in source code',
                'location': 'MainActivity.java:3'
            },
            {
                'type': 'SQL Injection',
                'severity': 'CRITICAL',
                'description': 'Unsanitized user input in SQL query',
                'location': 'DatabaseHelper.java:15'
            }
        ]
        return mock_detector

class MockVulnerabilityFinding:
    """Mock vulnerability finding for testing."""
    
    def __init__(self, **kwargs):
        # Default values
        self.id = kwargs.get('id', str(uuid.uuid4()))
        self.title = kwargs.get('title', 'Mock Vulnerability')
        self.description = kwargs.get('description', 'Mock vulnerability description')
        self.severity = kwargs.get('severity', 'MEDIUM')
        self.category = kwargs.get('category', 'MASVS-CODE')
        self.location = kwargs.get('location', 'mock/location.java:10')
        self.evidence = kwargs.get('evidence', 'Mock evidence')
        self.confidence = kwargs.get('confidence', 0.75)
        self.risk_level = kwargs.get('risk_level', 'MEDIUM')
        self.remediation = kwargs.get('remediation', 'Mock remediation advice')
        self.references = kwargs.get('references', ['https://example.com/ref'])
        self.tags = kwargs.get('tags', ['mock', 'test'])
        self.discovered_at = kwargs.get('discovered_at', datetime.now())
        
        # MASVS/MASTG compliance
        self.masvs_category = kwargs.get('masvs_category', 'MASVS-CODE-4')
        self.mastg_test = kwargs.get('mastg_test', 'MASTG-TEST-0014')
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'location': self.location,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'risk_level': self.risk_level,
            'remediation': self.remediation,
            'references': self.references,
            'tags': self.tags,
            'discovered_at': self.discovered_at.isoformat(),
            'masvs_category': self.masvs_category,
            'mastg_test': self.mastg_test
        }

class MockSecurityFinding:
    """Mock security finding for compliance testing."""
    
    def __init__(self, **kwargs):
        self.finding_id = kwargs.get('finding_id', str(uuid.uuid4()))
        self.finding_type = kwargs.get('finding_type', 'Security Misconfiguration')
        self.severity_level = kwargs.get('severity_level', 'HIGH')
        self.description_text = kwargs.get('description_text', 'Mock security finding')
        self.location_info = kwargs.get('location_info', 'AndroidManifest.xml:25')
        self.evidence_data = kwargs.get('evidence_data', 'android:debuggable="true"')
        self.confidence_score = kwargs.get('confidence_score', 0.88)
        self.remediation_steps = kwargs.get('remediation_steps', ['Disable debug mode in production'])
        self.compliance_mapping = kwargs.get('compliance_mapping', {
            'masvs': 'MASVS-CODE-8',
            'mastg': 'MASTG-TEST-0033',
            'owasp_top10': 'A06:2021'
        })

class MockPluginManager:
    """Mock plugin manager for testing plugin execution."""
    
    def __init__(self):
        self.plugins = {}
        self.execution_results = {}
        self.logger = ContextualLogger("mock_plugin_manager")
    
    def register_mock_plugin(self, plugin_name: str, execution_result: Any = None):
        """Register a mock plugin with expected result."""
        mock_plugin = Mock()
        mock_plugin.name = plugin_name
        mock_plugin.run.return_value = execution_result or f"Mock result from {plugin_name}"
        
        self.plugins[plugin_name] = mock_plugin
        self.execution_results[plugin_name] = execution_result
    
    def execute_plugin(self, plugin_name: str, apk_ctx: MockAPKContext) -> Any:
        """Execute a mock plugin."""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            return plugin.run(apk_ctx)
        else:
            return f"Mock result from unknown plugin: {plugin_name}"
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available mock plugins."""
        return list(self.plugins.keys())

class MockGenerator:
    """
    Main mock generator for AODS testing framework.
    
    Provides comprehensive mock object generation with configurable
    scenarios for different testing requirements.
    """
    
    def __init__(self, config: Optional[MockConfiguration] = None):
        self.config = config or MockConfiguration()
        self.logger = ContextualLogger("mock_generator")
        
        # Mock object cache
        self._mock_cache = {}
        
        # Predefined scenarios
        self._scenarios = {
            'simple_app': MockConfiguration(
                package_name='com.test.simple',
                complexity_level='simple',
                vulnerability_count=2,
                apk_size_mb=5.0
            ),
            'complex_app': MockConfiguration(
                package_name='com.test.complex',
                complexity_level='complex',
                vulnerability_count=15,
                apk_size_mb=100.0
            ),
            'vulnerable_app': MockConfiguration(
                package_name='com.test.vulnerable',
                complexity_level='medium',
                vulnerability_count=25,
                apk_size_mb=30.0
            ),
            'enterprise_app': MockConfiguration(
                package_name='com.enterprise.production',
                complexity_level='complex',
                vulnerability_count=8,
                apk_size_mb=250.0
            )
        }
    
    def create_mock_apk_context(self, scenario: str = 'default', 
                              custom_config: Optional[MockConfiguration] = None) -> MockAPKContext:
        """Create mock APK context for testing."""
        if custom_config:
            config = custom_config
        elif scenario in self._scenarios:
            config = self._scenarios[scenario]
        else:
            config = self.config
        
        cache_key = f"apk_context_{scenario}_{hash(str(config.to_dict()))}"
        
        if cache_key not in self._mock_cache:
            self._mock_cache[cache_key] = MockAPKContext(config)
        
        return self._mock_cache[cache_key]
    
    def create_mock_analysis_context(self, apk_ctx: Optional[MockAPKContext] = None,
                                   plugin_name: str = 'mock_plugin') -> MockAnalysisContext:
        """Create mock analysis context."""
        if not apk_ctx:
            apk_ctx = self.create_mock_apk_context()
        
        return MockAnalysisContext(apk_ctx, plugin_name)
    
    def create_mock_vulnerability_findings(self, count: int = 5, 
                                         scenario: str = 'mixed') -> List[MockVulnerabilityFinding]:
        """Create mock vulnerability findings."""
        findings = []
        
        # Predefined finding templates
        templates = {
            'hardcoded_secrets': {
                'title': 'Hardcoded API Key',
                'description': 'API key found hardcoded in source code',
                'severity': 'HIGH',
                'category': 'MASVS-CRYPTO',
                'evidence': 'sk_test_1234567890abcdef'
            },
            'sql_injection': {
                'title': 'SQL Injection Vulnerability',
                'description': 'Unsanitized user input in SQL query',
                'severity': 'CRITICAL',
                'category': 'MASVS-CODE',
                'evidence': "SELECT * FROM users WHERE id = '" + userId + "'"
            },
            'insecure_network': {
                'title': 'Insecure Network Communication',
                'description': 'HTTP connection without encryption',
                'severity': 'MEDIUM',
                'category': 'MASVS-NETWORK',
                'evidence': 'http://api.example.com/data'
            },
            'debug_enabled': {
                'title': 'Debug Mode Enabled',
                'description': 'Application allows debugging in production',
                'severity': 'LOW',
                'category': 'MASVS-CODE',
                'evidence': 'android:debuggable="true"'
            },
            'weak_crypto': {
                'title': 'Weak Encryption Algorithm',
                'description': 'DES encryption algorithm detected',
                'severity': 'HIGH',
                'category': 'MASVS-CRYPTO',
                'evidence': 'Cipher.getInstance("DES/ECB/PKCS5Padding")'
            }
        }
        
        # Generate findings based on scenario
        if scenario == 'high_severity':
            finding_types = ['sql_injection', 'hardcoded_secrets', 'weak_crypto']
        elif scenario == 'low_severity':
            finding_types = ['debug_enabled', 'insecure_network']
        else:  # mixed
            finding_types = list(templates.keys())
        
        for i in range(count):
            template_key = finding_types[i % len(finding_types)]
            template = templates[template_key]
            
            finding = MockVulnerabilityFinding(
                id=f"mock_finding_{i+1}",
                title=f"{template['title']} #{i+1}",
                description=template['description'],
                severity=template['severity'],
                category=template['category'],
                evidence=template['evidence'],
                location=f"mock_file_{i+1}.java:{10 + i}",
                confidence=0.7 + (i * 0.05) % 0.3  # Vary confidence
            )
            
            findings.append(finding)
        
        return findings
    
    def create_mock_plugin_manager(self, plugins: Optional[List[str]] = None) -> MockPluginManager:
        """Create mock plugin manager."""
        manager = MockPluginManager()
        
        # Default plugins if none specified
        if not plugins:
            plugins = [
                'static_analysis',
                'dynamic_analysis',
                'network_analysis',
                'crypto_analysis',
                'native_analysis'
            ]
        
        # Register mock plugins
        for plugin_name in plugins:
            mock_result = {
                'plugin_name': plugin_name,
                'findings': self.create_mock_vulnerability_findings(count=3),
                'execution_time': 5.0 + (hash(plugin_name) % 10),
                'success': True
            }
            manager.register_mock_plugin(plugin_name, mock_result)
        
        return manager
    
    def create_test_environment(self, scenario: str = 'standard') -> Dict[str, Any]:
        """Create complete test environment."""
        apk_ctx = self.create_mock_apk_context(scenario)
        analysis_ctx = self.create_mock_analysis_context(apk_ctx)
        plugin_manager = self.create_mock_plugin_manager()
        findings = self.create_mock_vulnerability_findings(count=10)
        
        return {
            'apk_context': apk_ctx,
            'analysis_context': analysis_ctx,
            'plugin_manager': plugin_manager,
            'mock_findings': findings,
            'scenario': scenario,
            'created_at': datetime.now().isoformat()
        }
    
    def cleanup_mock_cache(self) -> None:
        """Clear mock object cache."""
        self._mock_cache.clear()
        self.logger.info("Mock cache cleared")

# Global mock generator instance
_mock_generator: Optional[MockGenerator] = None

def get_mock_generator() -> MockGenerator:
    """Get the global mock generator instance."""
    global _mock_generator
    if _mock_generator is None:
        _mock_generator = MockGenerator()
    return _mock_generator 
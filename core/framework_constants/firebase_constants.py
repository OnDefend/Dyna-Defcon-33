#!/usr/bin/env python3
"""
Firebase Framework Constants - Focused Single Source of Truth

This module contains ALL Firebase-specific constants in one focused location.
Extracted from framework_constants.py to maintain <500 lines per file.

ZERO DUPLICATION: All Firebase patterns centralized here.
SINGLE RESPONSIBILITY: Firebase constants only.
"""

from typing import Dict, List, Set

class FirebaseConstants:
    """Firebase-specific constants - single source of truth."""
    
    # Firebase library internals (always exclude)
    INTERNAL_PATTERNS: Set[str] = frozenset({
        'com/google/firebase/internal/',
        'com/google/firebase/impl/',
        'com/google/firebase/provider/',
        'com/google/firebase/common/',
        'com/google/firebase/components/',
    })
    
    # Firebase library patterns (context-dependent)
    LIBRARY_PATTERNS: Set[str] = frozenset({
        'com/google/firebase/auth/',
        'com/google/firebase/database/',
        'com/google/firebase/storage/',
        'com/google/firebase/messaging/',
        'com/google/firebase/analytics/',
        'com/google/firebase/config/',
        'com/google/firebase/firestore/',
        'com/google/firebase/functions/',
        'com/google/firebase/performance/',
        'com/google/android/gms/firebase/',
    })
    
    # Firebase integration files (never filter)
    INTEGRATION_FILES: Set[str] = frozenset({
        'google-services.json',
        'firebase-config.json', 
        'firebase.json',
        'firebase.rules',
        'firestore.rules',
        'storage.rules',
        'googleservice-info.plist',
        'firebase-messaging-sw.js',
    })
    
    # Firebase integration keywords (within app package only)
    INTEGRATION_KEYWORDS: Set[str] = frozenset({
        'firebasemanager', 'firebaseconfig', 'firebasehelper', 'firebaseservice',
        'firebaseutil', 'firebaseauth', 'firebasedatabase', 'firebaseanalytics',
        'firebasemessaging', 'firebasestorage', 'firebaseremoteconfig', 'firebaseperformance',
        'firebase',  # When in app package context
    })
    
    # Firebase service detection patterns
    SERVICE_PATTERNS: Dict[str, List[str]] = {
        'auth': ['auth', 'authentication', 'signin', 'login'],
        'database': ['database', 'realtimedatabase', 'rtdb'],
        'firestore': ['firestore', 'cloudfirestore'],
        'storage': ['storage', 'cloudstorage'],
        'messaging': ['messaging', 'fcm', 'cloudmessaging'],
        'analytics': ['analytics', 'googleanalytics'],
        'remoteconfig': ['remoteconfig', 'config'],
        'performance': ['performance', 'perf'],
        'functions': ['functions', 'cloudfunctions']
    }
    
    # Common Firebase detection strings (to eliminate string literals)
    FRAMEWORK_NAME: str = 'firebase'
    PACKAGE_DETECTION_STRING: str = 'firebase'
    FULL_PACKAGE_NAME: str = 'com.google.firebase'
    
    # Firebase service indicators for content detection
    SERVICE_INDICATORS: List[str] = [
        'firebase', 'FirebaseAuth', 'FirebaseDatabase', 'FirebaseStorage',
        'FirebaseMessaging', 'FirebaseAnalytics', 'FirebaseRemoteConfig',
        'FirebaseFirestore', 'FirebasePerformance', 'com.google.firebase'
    ]
    
    # Metadata keys for Firebase analysis (to eliminate string duplications)
    METADATA_KEYS = {
        'SERVICES_DETECTED': 'firebase_services_detected',
        'SERVICES_COUNT': 'firebase_services_count', 
        'FILTER_ACTIVE': 'firebase_filter_active',
        'CONFIG_FILES_ANALYZED': 'config_files_analyzed',
        'RULES_FILES_ANALYZED': 'rules_files_analyzed',
        'ANALYSIS_CATEGORIES': 'analysis_categories',
        'SECURITY_SCORE': 'firebase_security_score'
    }
    
    # Common file names to eliminate string duplications
    CONFIG_FILE_NAMES = {
        'FIREBASE_CONFIG': 'firebase-config.json',
        'FIREBASE_JSON': 'firebase.json', 
        'FIREBASE_RULES': 'firebase.rules',
        'FIRESTORE_RULES': 'firestore.rules',
        'STORAGE_RULES': 'storage.rules'
    }
    
    # Security analysis category names (to eliminate string duplications)
    ANALYSIS_CATEGORIES = {
        'AUTHENTICATION': 'firebase_authentication_vulnerabilities',
        'DATABASE': 'firebase_database_security_issues',
        'STORAGE': 'firebase_storage_vulnerabilities', 
        'MESSAGING': 'firebase_cloud_messaging_issues',
        'ANALYTICS': 'firebase_analytics_privacy_issues',
        'REMOTE_CONFIG': 'firebase_remote_config_vulnerabilities',
        'PERFORMANCE': 'firebase_performance_security_concerns',
        'CONFIGURATION': 'firebase_configuration_hardcoding'
    }
    
    # Analysis method name constants
    ANALYSIS_METHOD_NAME: str = 'enhanced_firebase_integration'
    
    # Firebase service detection patterns for comprehensive coverage
    SERVICE_DETECTION_PATTERNS: Dict[str, List[str]] = {
        'authentication_services': [
            'FirebaseAuth', 'signIn', 'createUser', 'signOut', 'getCurrentUser',
            'AuthCredential', 'GoogleAuthProvider', 'FacebookAuthProvider'
        ],
        'database_services': [
            'FirebaseDatabase', 'DatabaseReference', 'getValue', 'setValue',
            'push', 'child', 'orderBy', 'limitTo', 'addValueEventListener'
        ],
        'firestore_services': [
            'FirebaseFirestore', 'CollectionReference', 'DocumentReference',
            'get', 'set', 'update', 'delete', 'collection', 'document'
        ],
        'storage_services': [
            'FirebaseStorage', 'StorageReference', 'putFile', 'putBytes',
            'getDownloadUrl', 'getFile', 'delete'
        ],
        'messaging_services': [
            'FirebaseMessaging', 'getToken', 'subscribeToTopic', 'send',
            'onMessageReceived', 'RemoteMessage'
        ],
        'analytics_services': [
            'FirebaseAnalytics', 'logEvent', 'setUserId', 'setUserProperty',
            'Bundle', 'Param'
        ],
        'remote_config_services': [
            'FirebaseRemoteConfig', 'fetch', 'activate', 'getString',
            'getBoolean', 'getLong', 'getDouble'
        ],
        'performance_services': [
            'FirebasePerformance', 'newTrace', 'start', 'stop',
            'putAttribute', 'incrementMetric'
        ]
    }

    # Firebase vulnerability analysis patterns (centralized from enhanced analyzer)
    SECURITY_ANALYSIS_PATTERNS: Dict[str, List[Dict]] = {
        'firebase_authentication_vulnerabilities': [
            {
                'pattern': r'signInAnonymously\(\)',
                'severity': 'HIGH',
                'description': 'Anonymous authentication enabled without proper validation',
                'owasp': 'MASVS-AUTH-1',
                'cwe': 'CWE-287',
                'remediation': 'Implement proper user validation and limit anonymous access scope'
            },
            {
                'pattern': r'signInWithEmailAndPassword\([^,]+,\s*["\'][^"\']*["\'][^)]*\)',
                'severity': 'CRITICAL',
                'description': 'Hardcoded password in Firebase authentication',
                'owasp': 'MASVS-CRYPTO-1',
                'cwe': 'CWE-798',
                'remediation': 'Remove hardcoded credentials, use secure credential storage'
            },
            {
                'pattern': r'sendPasswordResetEmail\([^)]*\).*(?!validateEmail)',
                'severity': 'MEDIUM',
                'description': 'Password reset without email validation',
                'owasp': 'MASVS-AUTH-2',
                'cwe': 'CWE-640',
                'remediation': 'Implement email validation before password reset'
            },
            {
                'pattern': r'linkWithCredential\([^)]*\).*(?!verifyBeforeUpdate)',
                'severity': 'HIGH',
                'description': 'Account linking without verification',
                'owasp': 'MASVS-AUTH-3',
                'cwe': 'CWE-287',
                'remediation': 'Verify user identity before account linking'
            },
            {
                'pattern': r'signInWithCustomToken\([^)]*\).*(?!validateToken)',
                'severity': 'HIGH',
                'description': 'Custom token authentication without validation',
                'owasp': 'MASVS-AUTH-1',
                'cwe': 'CWE-347',
                'remediation': 'Implement proper custom token validation'
            },
            {
                'pattern': r'updatePassword\([^)]*\).*(?!getCurrentPassword)',
                'severity': 'MEDIUM',
                'description': 'Password update without current password verification',
                'owasp': 'MASVS-AUTH-2',
                'cwe': 'CWE-620',
                'remediation': 'Require current password verification before update'
            }
        ],
        
        'firebase_database_security_issues': [
            {
                'pattern': r'\.write.*true',
                'severity': 'CRITICAL',
                'description': 'Firebase database with unrestricted write access',
                'owasp': 'MASVS-PLATFORM-11',
                'cwe': 'CWE-276',
                'remediation': 'Implement proper write access controls and authentication checks'
            },
            {
                'pattern': r'\.read.*true',
                'severity': 'HIGH',
                'description': 'Firebase database with unrestricted read access',
                'owasp': 'MASVS-PLATFORM-11',
                'cwe': 'CWE-276',
                'remediation': 'Implement proper read access controls and data privacy'
            },
            {
                'pattern': r'child\(["\'][^"\']*["\'].*(?!sanitize|validate)',
                'severity': 'MEDIUM',
                'description': 'Firebase database child access without input validation',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-20',
                'remediation': 'Validate and sanitize all input before database operations'
            },
            {
                'pattern': r'push\(\)\.setValue\([^)]*\).*(?!encrypt|hash)',
                'severity': 'MEDIUM',
                'description': 'Storing unencrypted sensitive data in Firebase',
                'owasp': 'MASVS-STORAGE-1',
                'cwe': 'CWE-312',
                'remediation': 'Encrypt sensitive data before storing in Firebase'
            },
            {
                'pattern': r'orderBy.*(?!\.limitTo)',
                'severity': 'LOW',
                'description': 'Firebase query without result limiting (potential DoS)',
                'owasp': 'MASVS-RESILIENCE-1',
                'cwe': 'CWE-770',
                'remediation': 'Implement query result limits to prevent resource exhaustion'
            },
            {
                'pattern': r'removeValue\(\).*(?!auth|permission)',
                'severity': 'HIGH',
                'description': 'Data deletion without proper authorization checks',
                'owasp': 'MASVS-AUTH-1',
                'cwe': 'CWE-285',
                'remediation': 'Implement authorization checks before data deletion'
            }
        ],
        
        'firebase_storage_vulnerabilities': [
            {
                'pattern': r'allow\s+read.*true',
                'severity': 'CRITICAL',
                'description': 'Firebase Storage with unrestricted read access',
                'owasp': 'MASVS-PLATFORM-11',
                'cwe': 'CWE-276',
                'remediation': 'Implement proper access controls for storage resources'
            },
            {
                'pattern': r'allow\s+write.*true',
                'severity': 'CRITICAL',
                'description': 'Firebase Storage with unrestricted write access',
                'owasp': 'MASVS-PLATFORM-11',
                'cwe': 'CWE-276',
                'remediation': 'Implement proper write access controls and file validation'
            },
            {
                'pattern': r'putBytes?\([^)]*\).*(?!encryptFile|validateFile)',
                'severity': 'MEDIUM',
                'description': 'File upload without validation or encryption',
                'owasp': 'MASVS-STORAGE-1',
                'cwe': 'CWE-434',
                'remediation': 'Validate file types and encrypt sensitive files before upload'
            },
            {
                'pattern': r'getDownloadUrl\(\).*(?!validateAccess)',
                'severity': 'MEDIUM',
                'description': 'File download URL generation without access validation',
                'owasp': 'MASVS-AUTH-1',
                'cwe': 'CWE-285',
                'remediation': 'Validate user access before generating download URLs'
            },
            {
                'pattern': r'getFile\([^)]*\).*(?!validatePath)',
                'severity': 'HIGH',
                'description': 'File access without path validation (potential path traversal)',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-22',
                'remediation': 'Validate and sanitize file paths before access'
            }
        ],
        
        'firebase_cloud_messaging_issues': [
            {
                'pattern': r'send.*(?!encrypt|sign)',
                'severity': 'MEDIUM',
                'description': 'FCM message sent without encryption or signing',
                'owasp': 'MASVS-NETWORK-1',
                'cwe': 'CWE-319',
                'remediation': 'Encrypt sensitive FCM message content'
            },
            {
                'pattern': r'subscribeToTopic\(["\'][^"\']*["\'].*(?!validateTopic)',
                'severity': 'LOW',
                'description': 'FCM topic subscription without validation',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-20',
                'remediation': 'Validate topic names and user permissions'
            },
            {
                'pattern': r'token.*(?!refresh|validate)',
                'severity': 'MEDIUM',
                'description': 'FCM token handling without proper validation or refresh',
                'owasp': 'MASVS-AUTH-3',
                'cwe': 'CWE-613',
                'remediation': 'Implement proper token validation and refresh mechanisms'
            }
        ],
        
        'firebase_analytics_privacy_issues': [
            {
                'pattern': r'logEvent.*(?!anonymize|consent)',
                'severity': 'MEDIUM',
                'description': 'Analytics event logging without user consent or data anonymization',
                'owasp': 'MASVS-PRIVACY-1',
                'cwe': 'CWE-359',
                'remediation': 'Obtain user consent and anonymize sensitive analytics data'
            },
            {
                'pattern': r'setUserId\([^)]*\).*(?!hash|pseudonymize)',
                'severity': 'HIGH',
                'description': 'Setting raw user ID in analytics without pseudonymization',
                'owasp': 'MASVS-PRIVACY-1',
                'cwe': 'CWE-359',
                'remediation': 'Hash or pseudonymize user IDs before analytics logging'
            },
            {
                'pattern': r'setUserProperty.*(?!sanitize|consent)',
                'severity': 'MEDIUM',
                'description': 'User property setting without sanitization or consent',
                'owasp': 'MASVS-PRIVACY-1',
                'cwe': 'CWE-359',
                'remediation': 'Sanitize user properties and ensure proper consent'
            }
        ],
        
        'firebase_remote_config_vulnerabilities': [
            {
                'pattern': r'fetchAndActivate\(\).*(?!validateConfig)',
                'severity': 'MEDIUM',
                'description': 'Remote config fetching without validation',
                'owasp': 'MASVS-RESILIENCE-3',
                'cwe': 'CWE-829',
                'remediation': 'Validate remote configuration before activation'
            },
            {
                'pattern': r'getString\(["\'][^"\']*key[^"\']*["\'].*(?!default|fallback)',
                'severity': 'LOW',
                'description': 'Remote config value retrieval without fallback',
                'owasp': 'MASVS-RESILIENCE-1',
                'cwe': 'CWE-754',
                'remediation': 'Implement fallback values for critical configuration'
            },
            {
                'pattern': r'setMinimumFetchIntervalInSeconds\(0\)',
                'severity': 'LOW',
                'description': 'Remote config with no fetch interval (potential abuse)',
                'owasp': 'MASVS-RESILIENCE-1',
                'cwe': 'CWE-770',
                'remediation': 'Set reasonable minimum fetch intervals'
            }
        ],
        
        'firebase_performance_security_concerns': [
            {
                'pattern': r'newTrace\(["\'][^"\']*["\'].*(?!sanitize)',
                'severity': 'LOW',
                'description': 'Performance trace with unsanitized trace name',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-20',
                'remediation': 'Sanitize trace names to prevent information disclosure'
            },
            {
                'pattern': r'putAttribute.*(?!validate|limit)',
                'severity': 'LOW',
                'description': 'Performance trace attribute without validation or limits',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-770',
                'remediation': 'Validate and limit performance trace attributes'
            }
        ],
        
        'firebase_configuration_hardcoding': [
            {
                'pattern': r'["\']AIza[a-zA-Z0-9_-]{35}["\']',
                'severity': 'CRITICAL',
                'description': 'Hardcoded Firebase API key',
                'owasp': 'MASVS-CRYPTO-1',
                'cwe': 'CWE-798',
                'remediation': 'Move API keys to secure configuration or environment variables'
            },
            {
                'pattern': r'["\'][a-zA-Z0-9-]+\.firebaseapp\.com["\']',
                'severity': 'MEDIUM',
                'description': 'Hardcoded Firebase project URL',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-526',
                'remediation': 'Move project configuration to external config files'
            },
            {
                'pattern': r'["\'][a-zA-Z0-9-]+\.appspot\.com["\']',
                'severity': 'MEDIUM',
                'description': 'Hardcoded Firebase storage bucket URL',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-526',
                'remediation': 'Use configuration management for storage URLs'
            },
            {
                'pattern': r'["\'][0-9]+:[0-9]+:android:[a-f0-9]+["\']',
                'severity': 'HIGH',
                'description': 'Hardcoded Firebase app ID',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-798',
                'remediation': 'Store app IDs in secure configuration'
            },
            {
                'pattern': r'messagingSenderId["\']?\s*:\s*["\'][0-9]+["\']',
                'severity': 'MEDIUM',
                'description': 'Hardcoded FCM sender ID',
                'owasp': 'MASVS-CODE-8',
                'cwe': 'CWE-526',
                'remediation': 'Move messaging configuration to external files'
            }
        ]
    }

    @classmethod
    def get_all_excluded_patterns(cls) -> Set[str]:
        """Get all Firebase patterns that should be excluded."""
        return cls.INTERNAL_PATTERNS | cls.LIBRARY_PATTERNS
    
    @classmethod 
    def get_all_integration_patterns(cls) -> Set[str]:
        """Get all Firebase integration patterns that should NOT be filtered."""
        return cls.INTEGRATION_FILES | cls.INTEGRATION_KEYWORDS

    @classmethod
    def get_statistics(cls) -> Dict[str, int]:
        """Get Firebase constants statistics."""
        return {
            'firebase_excluded_patterns': len(cls.get_all_excluded_patterns()),
            'firebase_integration_patterns': len(cls.get_all_integration_patterns()),
            'firebase_service_categories': len(cls.SERVICE_PATTERNS),
            'firebase_detection_indicators': len(cls.SERVICE_INDICATORS)
        }
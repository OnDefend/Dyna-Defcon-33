"""
Database Security Analyzer Module

Specialized analyzer for database security analysis.
Comprehensive implementation for the modular architecture.
"""

import logging
import re
import os
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    DatabaseAnalysis, StorageVulnerability, StorageVulnerabilitySeverity,
    StorageType, StorageSecurityLevel
)
from .confidence_calculator import StorageConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class DatabaseAnalyzer:
    """Database security analyzer with comprehensive database security analysis."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize database analysis patterns
        self.database_patterns = self._initialize_database_patterns()
        self.encryption_patterns = self._initialize_encryption_patterns()
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'databases_analyzed': 0,
            'vulnerabilities_found': 0,
            'encrypted_databases': 0,
            'files_analyzed': 0
        }
    
    def analyze(self, apk_ctx) -> List[DatabaseAnalysis]:
        """Analyze database security comprehensively."""
        analyses = []
        
        try:
            self.logger.info("Starting comprehensive database security analysis")
            
            # Get database-related files
            database_files = self._find_database_files(apk_ctx)
            
            # Analyze Java/Kotlin source files for database usage
            source_files = self._find_source_files(apk_ctx)
            
            # Analyze each database file
            for db_file in database_files:
                try:
                    analysis = self._analyze_database_file(db_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                        self.analysis_stats['databases_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze database file {db_file}: {e}")
            
            # Analyze source code for database security patterns
            for source_file in source_files:
                try:
                    db_analysis = self._analyze_source_for_database_patterns(source_file, apk_ctx)
                    if db_analysis:
                        analyses.append(db_analysis)
                        self.analysis_stats['databases_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze source file {source_file}: {e}")
            
            # Update analysis statistics
            self.analysis_stats['files_analyzed'] = len(database_files) + len(source_files)
            
            self.logger.info(f"Database analysis completed: {len(analyses)} databases analyzed")
            
            return analyses
            
        except Exception as e:
            self.logger.error(f"Database analysis failed: {e}")
            return []
    
    def _find_database_files(self, apk_ctx) -> List[str]:
        """Find database-related files in the APK."""
        database_files = []
        
        try:
            # Look for SQLite database files
            db_extensions = ['.db', '.sqlite', '.sqlite3', '.db3']
            
            if hasattr(apk_ctx, 'get_files'):
                all_files = apk_ctx.get_files()
                for file_path in all_files:
                    if any(file_path.lower().endswith(ext) for ext in db_extensions):
                        database_files.append(file_path)
            
            # Also look in assets and raw directories
            asset_paths = ['assets/', 'res/raw/']
            for asset_path in asset_paths:
                if hasattr(apk_ctx, 'get_files_in_dir'):
                    files_in_dir = apk_ctx.get_files_in_dir(asset_path)
                    for file_path in files_in_dir:
                        if any(file_path.lower().endswith(ext) for ext in db_extensions):
                            database_files.append(file_path)
            
        except Exception as e:
            self.logger.debug(f"Error finding database files: {e}")
        
        return database_files
    
    def _find_source_files(self, apk_ctx) -> List[str]:
        """Find Java/Kotlin source files that might contain database code."""
        source_files = []
        
        try:
            if hasattr(apk_ctx, 'get_java_files'):
                java_files = apk_ctx.get_java_files()
                for file_path in java_files:
                    # Look for files that likely contain database code
                    if any(keyword in file_path.lower() for keyword in 
                           ['database', 'db', 'sqlite', 'room', 'dao', 'entity', 'repository']):
                        source_files.append(file_path)
                
                # Also include files with database-related imports or usage
                for file_path in java_files[:100]:  # Limit to first 100 files for performance
                    try:
                        if hasattr(apk_ctx, 'get_file_content'):
                            content = apk_ctx.get_file_content(file_path)
                            if content and self._contains_database_code(content):
                                source_files.append(file_path)
                    except Exception:
                        continue
            
        except Exception as e:
            self.logger.debug(f"Error finding source files: {e}")
        
        return list(set(source_files))  # Remove duplicates
    
    def _contains_database_code(self, content: str) -> bool:
        """Check if source code contains database-related patterns."""
        database_indicators = [
            'SQLiteDatabase',
            'SQLiteOpenHelper',
            'android.database',
            'Room',
            'androidx.room',
            'openOrCreateDatabase',
            'getReadableDatabase',
            'getWritableDatabase',
            'execSQL',
            'rawQuery',
            'query(',
            'ContentValues',
            'Cursor'
        ]
        
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in database_indicators)
    
    def _analyze_database_file(self, db_file: str, apk_ctx) -> Optional[DatabaseAnalysis]:
        """Analyze a specific database file."""
        try:
            # **FIX**: Create database analysis object with correct parameters
            analysis = DatabaseAnalysis(
                database_path=db_file,
                database_type="SQLite",
                encryption_status="unencrypted"  # Will be updated below
            )
            
            # Check if database is encrypted
            encryption_status = self._check_database_encryption(db_file, apk_ctx)
            analysis.is_encrypted = encryption_status.get('encrypted', False)
            
            if not analysis.is_encrypted:
                # Create vulnerability for unencrypted database
                vulnerability = StorageVulnerability(
                    id=f"db_unencrypted_{hash(db_file)}",
                    title="Unencrypted Database",
                    description=f"Database file '{os.path.basename(db_file)}' is not encrypted",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[db_file],
                    evidence=f"Database file: {db_file}",
                    remediation="Encrypt database files using SQLCipher or Android Room with encryption",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        db_file, "unencrypted", {"file_path": db_file}
                    )
                )
                analysis.vulnerabilities.append(vulnerability)
                self.analysis_stats['vulnerabilities_found'] += 1
            else:
                self.analysis_stats['encrypted_databases'] += 1
            
            # Check database permissions
            permission_vulns = self._check_database_permissions(db_file, apk_ctx)
            analysis.vulnerabilities.extend(permission_vulns)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing database file {db_file}: {e}")
            return None
    
    def _analyze_source_for_database_patterns(self, source_file: str, apk_ctx) -> Optional[DatabaseAnalysis]:
        """Analyze source code for database security patterns."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(source_file)
            if not content:
                return None
            
            # **FIX**: Create database analysis object with correct parameters
            analysis = DatabaseAnalysis(
                database_path=source_file,
                database_type="Source Code",
                encryption_status="unknown"  # Will be determined by analysis
            )
            
            # Analyze various database security patterns
            vulns = []
            
            # Check for insecure database creation
            vulns.extend(self._check_insecure_database_creation(content, source_file))
            
            # Check for SQL injection vulnerabilities
            vulns.extend(self._check_sql_injection_patterns(content, source_file))
            
            # Check for database backup vulnerabilities
            vulns.extend(self._check_database_backup_issues(content, source_file))
            
            # Check for database encryption issues
            vulns.extend(self._check_database_encryption_issues(content, source_file))
            
            # Check for database permission issues
            vulns.extend(self._check_database_permission_issues(content, source_file))
            
            analysis.vulnerabilities = vulns
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing source file {source_file}: {e}")
            return None
    
    def _check_database_encryption(self, db_file: str, apk_ctx) -> Dict[str, Any]:
        """Check if database is encrypted."""
        try:
            # Check file header for SQLCipher signature
            if hasattr(apk_ctx, 'get_file_binary_content'):
                binary_content = apk_ctx.get_file_binary_content(db_file)
                if binary_content:
                    # SQLCipher databases have a different header
                    if binary_content.startswith(b'SQLite format 3\x00'):
                        return {'encrypted': False, 'method': 'none'}
                    elif len(binary_content) >= 16:
                        # Could be encrypted or unknown format
                        return {'encrypted': True, 'method': 'unknown'}
            
            # Default to unencrypted if we can't determine
            return {'encrypted': False, 'method': 'none'}
            
        except Exception as e:
            self.logger.debug(f"Error checking database encryption: {e}")
            return {'encrypted': False, 'method': 'none'}
    
    def _check_database_permissions(self, db_file: str, apk_ctx) -> List[StorageVulnerability]:
        """Check database file permissions."""
        vulnerabilities = []
        
        try:
            # Check if database is in external storage
            if 'external' in db_file.lower() or 'sdcard' in db_file.lower():
                vulnerability = StorageVulnerability(
                    id=f"db_external_{hash(db_file)}",
                    title="Database in External Storage",
                    description=f"Database '{os.path.basename(db_file)}' is stored in external storage",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-2",
                    affected_files=[db_file],
                    evidence=f"Database in external storage: {db_file}",
                    remediation="Store database in internal storage with proper permissions",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        db_file, "external_storage", {"file_path": db_file}
                    )
                )
                vulnerabilities.append(vulnerability)
            
            # Check if database is in world-readable location
            if any(path in db_file.lower() for path in ['/sdcard/', '/external/', '/storage/emulated/0/']):
                vulnerability = StorageVulnerability(
                    id=f"db_world_readable_{hash(db_file)}",
                    title="Database in World-Readable Location",
                    description=f"Database '{os.path.basename(db_file)}' is in a world-readable location",
                    severity=StorageVulnerabilitySeverity.CRITICAL,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[db_file],
                    evidence=f"World-readable database: {db_file}",
                    remediation="Move database to app's private internal storage",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        db_file, "world_readable", {"file_path": db_file}
                    )
                )
                vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.debug(f"Error checking database permissions: {e}")
        
        return vulnerabilities
    
    def _check_insecure_database_creation(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for insecure database creation patterns."""
        vulnerabilities = []
        
        # Check for MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE
        world_readable_pattern = r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'
        matches = re.finditer(world_readable_pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            vulnerability = StorageVulnerability(
                id=f"db_world_mode_{hash(file_path + str(line_num))}",
                title="Database Created with World-Accessible Mode",
                description=f"Database creation uses {match.group()} mode",
                severity=StorageVulnerabilitySeverity.CRITICAL,
                storage_type=StorageType.DATABASE,
                masvs_control="MSTG-STORAGE-1",
                affected_files=[file_path],
                evidence=f"Line {line_num}: {match.group()}",
                remediation="Use MODE_PRIVATE for database creation",
                confidence=self.confidence_calculator.calculate_database_confidence(
                    file_path, "world_accessible_mode", {"line_number": line_num, "pattern": match.group()}
                )
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_sql_injection_patterns(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for SQL injection vulnerabilities."""
        vulnerabilities = []
        
        # Check for string concatenation in SQL queries
        sql_concat_patterns = [
            r'execSQL\s*\(\s*[^)]*\+',
            r'rawQuery\s*\(\s*[^)]*\+',
            r'query\s*\([^)]*\+',
            r'\"SELECT\s+[^\"]*\"\s*\+',
            r'\"INSERT\s+[^\"]*\"\s*\+',
            r'\"UPDATE\s+[^\"]*\"\s*\+',
            r'\"DELETE\s+[^\"]*\"\s*\+'
        ]
        
        for pattern in sql_concat_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                vulnerability = StorageVulnerability(
                    id=f"sql_injection_{hash(file_path + str(line_num))}",
                    title="Potential SQL Injection",
                    description="SQL query constructed using string concatenation",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use parameterized queries or prepared statements",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        file_path, "sql_injection", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_database_backup_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for database backup security issues."""
        vulnerabilities = []
        
        # Check for unencrypted database backup
        backup_patterns = [
            r'backup.*database.*unencrypt',
            r'database.*backup.*plain',
            r'copy.*database.*external',
            r'export.*database.*sdcard'
        ]
        
        for pattern in backup_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                vulnerability = StorageVulnerability(
                    id=f"db_backup_{hash(file_path + str(line_num))}",
                    title="Insecure Database Backup",
                    description="Database backup may be performed without encryption",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Encrypt database backups and store in secure location",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        file_path, "insecure_backup", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_database_encryption_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for database encryption implementation issues."""
        vulnerabilities = []
        
        # Check for weak encryption or hardcoded keys
        encryption_issues = [
            r'SQLiteDatabase.*openDatabase.*password.*""',
            r'SQLiteDatabase.*openDatabase.*password.*null',
            r'SQLCipher.*password.*"[^"]*"',
            r'database.*encrypt.*key.*"[^"]*"'
        ]
        
        for pattern in encryption_issues:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                if '""' in match.group() or 'null' in match.group():
                    severity = StorageVulnerabilitySeverity.HIGH
                    title = "Database Encryption Disabled"
                    description = "Database encryption is disabled or uses empty password"
                else:
                    severity = StorageVulnerabilitySeverity.MEDIUM
                    title = "Hardcoded Database Encryption Key"
                    description = "Database encryption uses hardcoded key"
                
                vulnerability = StorageVulnerability(
                    id=f"db_encryption_{hash(file_path + str(line_num))}",
                    title=title,
                    description=description,
                    severity=severity,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use proper encryption with securely generated keys",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        file_path, "encryption_issue", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_database_permission_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for database permission issues in code."""
        vulnerabilities = []
        
        # Check for database creation in external storage
        external_storage_patterns = [
            r'getExternalStorageDirectory\(\).*database',
            r'Environment\.getExternalStorageDirectory\(\).*\.db',
            r'sdcard.*database',
            r'/storage/emulated/0.*\.db'
        ]
        
        for pattern in external_storage_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                vulnerability = StorageVulnerability(
                    id=f"db_external_code_{hash(file_path + str(line_num))}",
                    title="Database Created in External Storage",
                    description="Code creates database in external storage",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.DATABASE,
                    masvs_control="MSTG-STORAGE-2",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Create database in internal storage using Context.getDatabasePath()",
                    confidence=self.confidence_calculator.calculate_database_confidence(
                        file_path, "external_storage_code", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _initialize_database_patterns(self) -> Dict[str, List[str]]:
        """Initialize database detection patterns."""
        return {
            'sqlite_patterns': [
                'SQLiteDatabase',
                'SQLiteOpenHelper',
                'getReadableDatabase',
                'getWritableDatabase',
                'openOrCreateDatabase',
                'android.database.sqlite'
            ],
            'room_patterns': [
                'androidx.room',
                '@Database',
                '@Entity',
                '@Dao',
                'Room.databaseBuilder'
            ],
            'realm_patterns': [
                'io.realm',
                'RealmObject',
                'RealmConfiguration',
                'Realm.getDefaultInstance'
            ]
        }
    
    def _initialize_encryption_patterns(self) -> Dict[str, List[str]]:
        """Initialize encryption detection patterns."""
        return {
            'sqlcipher_patterns': [
                'SQLCipher',
                'net.sqlcipher',
                'SQLiteDatabase.openDatabase',
                'SQLiteDatabase.openOrCreateDatabase'
            ],
            'encrypted_room_patterns': [
                'Room.databaseBuilder().openHelperFactory',
                'SupportSQLiteOpenHelper.Factory',
                'SafeHelperFactory'
            ]
        }
    
    def _initialize_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Initialize vulnerability detection patterns."""
        return {
            'sql_injection_patterns': [
                'execSQL.*+',
                'rawQuery.*+',
                'query.*+',
                'SELECT.*+',
                'INSERT.*+',
                'UPDATE.*+',
                'DELETE.*+'
            ],
            'insecure_creation_patterns': [
                'MODE_WORLD_READABLE',
                'MODE_WORLD_WRITEABLE',
                'getExternalStorageDirectory',
                'sdcard',
                '/storage/emulated/0'
            ]
        } 
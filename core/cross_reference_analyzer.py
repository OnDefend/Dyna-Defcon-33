#!/usr/bin/env python3
"""
🚀 Advanced Cross-Reference Analysis - Advanced Cross-Reference Analysis System
============================================

Advanced cross-reference analysis system for correlating:
- Database findings with source code usage
- Database vulnerabilities to dynamic analysis results
- Enhanced context reporting and vulnerability chaining
- Better evidence collection and reporting

OWASP MASTG Compliance:
- MASTG-TECH-0019: String Resource Analysis
- MASTG-TEST-0001: Local Storage Security
- MASTG-TEST-0009: Backup Security Analysis
- MASTG-TEST-0200: External Storage Analysis

"""

import re
import json
import logging
from datetime import datetime
from datetime import datetime
from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
from pathlib import Path

@dataclass
class CrossReference:
    """Represents a cross-reference between findings"""
    source_finding_id: str
    target_finding_id: str
    relationship_type: str
    confidence: float
    evidence: List[str]
    context: Dict[str, Any]

@dataclass
class VulnerabilityChain:
    """Represents a chain of related vulnerabilities"""
    chain_id: str
    primary_finding: Dict[str, Any]
    related_findings: List[Dict[str, Any]]
    chain_severity: str
    chain_confidence: float
    impact_description: str
    mitigation_strategy: str

class CrossReferenceAnalyzer:
    """
    🚀 Advanced Cross-Reference Analysis - Advanced Cross-Reference Analysis System
    
    Correlates database findings with source code usage, links database
    vulnerabilities to dynamic analysis results, and provides enhanced
    context reporting with vulnerability chaining.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cross_references = []
        self.vulnerability_chains = []
        self.finding_index = {}
        self.database_code_patterns = self._initialize_database_code_patterns()
        self.dynamic_correlation_patterns = self._initialize_dynamic_correlation_patterns()
        self.evidence_collectors = self._initialize_evidence_collectors()
        self.context_enhancers = self._initialize_context_enhancers()
        
    def _initialize_database_code_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for correlating database findings with source code"""
        return {
            'sqlite_usage': [
                r'SQLiteDatabase',
                r'SQLiteOpenHelper',
                r'getWritableDatabase',
                r'getReadableDatabase',
                r'rawQuery|execSQL',
                r'ContentProvider',
                r'database\.sqlite'
            ],
            'database_operations': [
                r'INSERT\s+INTO',
                r'SELECT.*FROM',
                r'UPDATE.*SET',
                r'DELETE\s+FROM',
                r'CREATE\s+TABLE',
                r'DROP\s+TABLE',
                r'ALTER\s+TABLE'
            ],
            'sensitive_data_handling': [
                r'password.*database',
                r'token.*store',
                r'key.*database',
                r'credentials.*save',
                r'secret.*store',
                r'hash.*database'
            ],
            'encryption_usage': [
                r'SQLCipher',
                r'encrypt.*database',
                r'cipher.*key',
                r'AES.*database',
                r'encryption.*storage'
            ]
        }
    
    def _initialize_dynamic_correlation_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for correlating with dynamic analysis results"""
        return {
            'file_access': [
                r'database.*access',
                r'file.*read|write',
                r'storage.*access',
                r'external.*storage'
            ],
            'network_database': [
                r'database.*network',
                r'remote.*database',
                r'sync.*database',
                r'upload.*database'
            ],
            'permission_usage': [
                r'WRITE_EXTERNAL_STORAGE.*database',
                r'READ_EXTERNAL_STORAGE.*database',
                r'permission.*database'
            ]
        }
    
    def _initialize_evidence_collectors(self) -> Dict[str, callable]:
        """Initialize evidence collection methods"""
        return {
            'database_structure': self._collect_database_structure_evidence,
            'code_usage': self._collect_code_usage_evidence,
            'file_references': self._collect_file_reference_evidence,
            'permission_correlation': self._collect_permission_correlation_evidence,
            'network_correlation': self._collect_network_correlation_evidence
        }
    
    def _initialize_context_enhancers(self) -> Dict[str, callable]:
        """Initialize context enhancement methods"""
        return {
            'database_context': self._enhance_database_context,
            'security_context': self._enhance_security_context,
            'impact_context': self._enhance_impact_context,
            'mitigation_context': self._enhance_mitigation_context
        }
    
    def analyze_cross_references(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        🚀 Advanced Cross-Reference Analysis - Main cross-reference analysis entry point
        
        Analyzes all findings to identify cross-references and vulnerability chains.
        """
        self.logger.debug(f"🔍 Starting cross-reference analysis for {len(findings)} findings")
        
        # Build finding index for fast lookup
        self._build_finding_index(findings)
        
        # Correlate database findings with source code
        database_code_correlations = self._correlate_database_with_code(findings)
        
        # Link database vulnerabilities to dynamic analysis
        dynamic_correlations = self._correlate_with_dynamic_analysis(findings)
        
        # Create vulnerability chains
        vulnerability_chains = self._create_vulnerability_chains(findings)
        
        # Enhanced context reporting
        enhanced_context = self._generate_enhanced_context_reports(findings)
        
        # Collect enhanced evidence
        enhanced_evidence = self._collect_enhanced_evidence(findings)
        
        results = {
            'cross_references_found': len(self.cross_references),
            'vulnerability_chains': len(vulnerability_chains),
            'database_code_correlations': database_code_correlations,
            'dynamic_correlations': dynamic_correlations,
            'enhanced_context': enhanced_context,
            'enhanced_evidence': enhanced_evidence,
            'cross_reference_details': self.cross_references,
            'vulnerability_chain_details': vulnerability_chains,
            'analysis_metrics': self._generate_analysis_metrics(findings)
        }
        
        self.logger.debug(f"✅ Cross-reference analysis completed: {len(self.cross_references)} correlations, {len(vulnerability_chains)} chains")
        return results
    
    def _build_finding_index(self, findings: List[Dict[str, Any]]):
        """Build optimized index for fast finding lookup with O(1) performance."""
        # PERFORMANCE OPTIMIZATION: Use proper dictionary structure for O(1) lookups
        self.finding_index = {}
        self.finding_by_type = {}  # Separate index for type-based lookups
        
        for i, finding in enumerate(findings):
            finding_id = finding.get('id', f"finding_{i}")
            self.finding_index[finding_id] = finding
            
            # OPTIMIZED: Index by type using dictionary of lists for fast cross-reference lookup
            finding_type = finding.get('type', 'unknown')
            if finding_type not in self.finding_by_type:
                self.finding_by_type[finding_type] = []
            self.finding_by_type[finding_type].append(finding)
        
        # PERFORMANCE ENHANCEMENT: Pre-compute commonly used lookup sets for O(1) access
        self.finding_types = set(self.finding_by_type.keys())
        self.finding_ids = set(self.finding_index.keys())
        
        # OPTIMIZATION: Create reverse lookup indexes for cross-references
        self.findings_by_file = {}
        self.findings_by_severity = {}
        
        for finding in findings:
            # Index by file path for file-based correlations
            file_path = finding.get('file_path', finding.get('location', 'unknown'))
            if file_path not in self.findings_by_file:
                self.findings_by_file[file_path] = []
            self.findings_by_file[file_path].append(finding)
            
            # Index by severity for priority-based analysis
            severity = finding.get('severity', 'UNKNOWN')
            if severity not in self.findings_by_severity:
                self.findings_by_severity[severity] = []
            self.findings_by_severity[severity].append(finding)
    
    def _correlate_database_with_code(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        🚀 Advanced Cross-Reference Analysis - Correlate database findings with source code usage
        """
        correlations = {
            'database_findings': [],
            'code_findings': [],
            'correlations': [],
            'correlation_count': 0
        }
        
        # Identify database-related findings
        database_findings = [f for f in findings if self._is_database_finding(f)]
        code_findings = [f for f in findings if self._is_code_finding(f)]
        
        correlations['database_findings'] = database_findings
        correlations['code_findings'] = code_findings
        
        # Cross-correlate database findings with code findings
        for db_finding in database_findings:
            for code_finding in code_findings:
                correlation = self._analyze_database_code_correlation(db_finding, code_finding)
                if correlation:
                    correlations['correlations'].append(correlation)
                    correlations['correlation_count'] += 1
                    
                    # Create cross-reference
                    cross_ref = CrossReference(
                        source_finding_id=db_finding.get('id', ''),
                        target_finding_id=code_finding.get('id', ''),
                        relationship_type='database_code_correlation',
                        confidence=correlation['confidence'],
                        evidence=correlation['evidence'],
                        context=correlation['context']
                    )
                    self.cross_references.append(cross_ref)
        
        self.logger.debug(f"📊 Database-code correlations: {correlations['correlation_count']}")
        return correlations
    
    def _correlate_with_dynamic_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        🚀 Advanced Cross-Reference Analysis - Link database vulnerabilities to dynamic analysis results
        """
        correlations = {
            'dynamic_findings': [],
            'static_findings': [],
            'correlations': [],
            'correlation_count': 0
        }
        
        # Identify dynamic vs static findings
        dynamic_findings = [f for f in findings if self._is_dynamic_finding(f)]
        static_findings = [f for f in findings if not self._is_dynamic_finding(f)]
        
        correlations['dynamic_findings'] = dynamic_findings
        correlations['static_findings'] = static_findings
        
        # Cross-correlate dynamic with static findings
        for dynamic_finding in dynamic_findings:
            for static_finding in static_findings:
                if self._is_database_related(static_finding):
                    correlation = self._analyze_dynamic_static_correlation(dynamic_finding, static_finding)
                    if correlation:
                        correlations['correlations'].append(correlation)
                        correlations['correlation_count'] += 1
                        
                        # Create cross-reference
                        cross_ref = CrossReference(
                            source_finding_id=dynamic_finding.get('id', ''),
                            target_finding_id=static_finding.get('id', ''),
                            relationship_type='dynamic_static_correlation',
                            confidence=correlation['confidence'],
                            evidence=correlation['evidence'],
                            context=correlation['context']
                        )
                        self.cross_references.append(cross_ref)
        
        self.logger.debug(f"📊 Dynamic-static correlations: {correlations['correlation_count']}")
        return correlations
    
    def _create_vulnerability_chains(self, findings: List[Dict[str, Any]]) -> List[VulnerabilityChain]:
        """
        🚀 Advanced Cross-Reference Analysis - Enhanced context reporting and vulnerability chaining
        """
        chains = []
        processed_findings = set()
        
        for finding in findings:
            if finding.get('id') in processed_findings:
                continue
                
            if self._is_chain_starter(finding):
                chain = self._build_vulnerability_chain(finding, findings, processed_findings)
                if chain and len(chain.related_findings) > 0:
                    chains.append(chain)
                    processed_findings.add(finding.get('id'))
                    for related in chain.related_findings:
                        processed_findings.add(related.get('id'))
        
        self.vulnerability_chains = chains
        self.logger.debug(f"🔗 Vulnerability chains created: {len(chains)}")
        return chains
    
    def _collect_enhanced_evidence(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        🚀 Advanced Cross-Reference Analysis - Better evidence collection and reporting
        """
        evidence = {
            'database_structure_evidence': [],
            'code_usage_evidence': [],
            'file_reference_evidence': [],
            'permission_correlation_evidence': [],
            'network_correlation_evidence': [],
            'total_evidence_items': 0
        }
        
        for finding in findings:
            for evidence_type, collector in self.evidence_collectors.items():
                collected = collector(finding)
                if collected:
                    evidence_key = f"{evidence_type}_evidence"
                    if evidence_key in evidence:
                        evidence[evidence_key].extend(collected)
                        evidence['total_evidence_items'] += len(collected)
        
        self.logger.debug(f"📋 Enhanced evidence collected: {evidence['total_evidence_items']} items")
        return evidence
    
    def _generate_enhanced_context_reports(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate enhanced context reports for findings"""
        context_reports = {
            'database_context_reports': [],
            'security_context_reports': [],
            'impact_context_reports': [],
            'mitigation_context_reports': [],
            'total_context_reports': 0
        }
        
        for finding in findings:
            for context_type, enhancer in self.context_enhancers.items():
                enhanced = enhancer(finding)
                if enhanced:
                    context_key = f"{context_type}_reports"
                    if context_key in context_reports:
                        context_reports[context_key].append(enhanced)
                        context_reports['total_context_reports'] += 1
        
        return context_reports
    
    def _is_database_finding(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is database-related"""
        finding_type = finding.get('type', '').lower()
        tags = finding.get('tags', [])
        location = finding.get('location', '').lower()
        
        database_indicators = [
            'database', 'sqlite', 'db', 'sql', 'table', 'column',
            'hash_detection', 'unencrypted_database', 'foreign_key'
        ]
        
        return any(indicator in finding_type for indicator in database_indicators) or \
               any(indicator in str(tags).lower() for indicator in database_indicators) or \
               '.db' in location or 'database' in location
    
    def _is_code_finding(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is code-related"""
        file_path = finding.get('file_path', '').lower()
        location = finding.get('location', '').lower()
        
        code_extensions = ['.java', '.kt', '.js', '.xml', '.json']
        return any(ext in file_path for ext in code_extensions) or \
               any(ext in location for ext in code_extensions)
    
    def _is_dynamic_finding(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is from dynamic analysis"""
        source = finding.get('source', '').lower()
        tags = finding.get('tags', [])
        
        dynamic_indicators = ['dynamic', 'runtime', 'execution', 'behavior']
        return any(indicator in source for indicator in dynamic_indicators) or \
               any(indicator in str(tags).lower() for indicator in dynamic_indicators)
    
    def _is_database_related(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is database-related (broader check)"""
        return self._is_database_finding(finding)
    
    def _analyze_database_code_correlation(self, db_finding: Dict[str, Any], code_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze correlation between database and code findings"""
        correlation_strength = 0.0
        evidence = []
        context = {}
        
        # Check for database name/table correlations
        db_location = db_finding.get('location', '')
        code_content = str(code_finding.get('evidence', '')) + str(code_finding.get('description', ''))
        code_location = code_finding.get('location', '')
        
        # Extract database/table names from database finding
        db_names = self._extract_database_names(db_location)
        table_names = self._extract_table_names(db_finding)
        
        # Enhanced database name matching
        for db_name in db_names:
            if db_name.lower() in code_content.lower():
                correlation_strength += 0.4  # Increased weight for direct database name match
                evidence.append(f"Database name '{db_name}' referenced in code")
            
            # Check for partial database name matches
            db_base = db_name.replace('.db', '').replace('_', '').replace('-', '')
            if len(db_base) > 3 and db_base.lower() in code_content.lower():
                correlation_strength += 0.2
                evidence.append(f"Database base name '{db_base}' referenced in code")
        
        # Enhanced table name matching
        for table_name in table_names:
            if table_name.lower() in code_content.lower():
                correlation_strength += 0.3  # Increased weight for table name match
                evidence.append(f"Table name '{table_name}' referenced in code")
        
        # Check for database operation patterns with higher weights
        for pattern_type, patterns in self.database_code_patterns.items():
            pattern_matches = 0
            for pattern in patterns:
                if re.search(pattern, code_content, re.IGNORECASE):
                    pattern_matches += 1
                    evidence.append(f"Database operation pattern '{pattern}' found in code")
            
            if pattern_matches > 0:
                # Weight based on pattern type importance
                if pattern_type == 'sqlite_usage':
                    correlation_strength += min(pattern_matches * 0.15, 0.4)
                elif pattern_type == 'sensitive_data_handling':
                    correlation_strength += min(pattern_matches * 0.2, 0.5)
                elif pattern_type == 'encryption_usage':
                    correlation_strength += min(pattern_matches * 0.25, 0.6)
                else:
                    correlation_strength += min(pattern_matches * 0.1, 0.3)
        
        # Enhanced sensitive data correlation
        if 'sensitive' in db_finding.get('type', '').lower() or 'hash' in db_finding.get('type', '').lower():
            sensitive_patterns = self.database_code_patterns.get('sensitive_data_handling', [])
            for pattern in sensitive_patterns:
                if re.search(pattern, code_content, re.IGNORECASE):
                    correlation_strength += 0.3  # Reduced from 0.4 to balance
                    evidence.append(f"Sensitive data handling pattern found in code")
        
        # Check for custom field correlations (enhanced semantic matching)
        db_custom = db_finding.get('custom_fields', {})
        code_custom = code_finding.get('custom_fields', {})
        
        # Database reference correlation
        if db_custom.get('database_reference') and code_custom.get('database_reference'):
            if db_custom['database_reference'] == code_custom['database_reference']:
                correlation_strength += 0.5
                evidence.append(f"Direct database reference match: {db_custom['database_reference']}")
        
        # Table/column correlation
        if db_custom.get('table_name') and code_custom.get('table_reference'):
            if db_custom['table_name'] == code_custom['table_reference']:
                correlation_strength += 0.4
                evidence.append(f"Table reference match: {db_custom['table_name']}")
        
        if db_custom.get('column_name') and code_custom.get('column_reference'):
            if db_custom['column_name'] == code_custom['column_reference']:
                correlation_strength += 0.3
                evidence.append(f"Column reference match: {db_custom['column_name']}")
        
        # Location-based correlation (same application/package)
        if self._locations_related(db_location, code_location):
            correlation_strength += 0.2
            evidence.append("Related file locations detected")
        
        # Severity-based correlation boost
        if db_finding.get('severity') == code_finding.get('severity') and db_finding.get('severity') in ['HIGH', 'CRITICAL']:
            correlation_strength += 0.1
            evidence.append("Matching high/critical severity levels")
        
        context = {
            'database_finding_type': db_finding.get('type'),
            'code_finding_type': code_finding.get('type'),
            'database_location': db_location,
            'code_location': code_location,
            'correlation_methods': ['name_matching', 'pattern_matching', 'content_analysis', 'semantic_matching'],
            'database_names_found': db_names,
            'table_names_found': table_names
        }
        
        # Lowered threshold for better recall, but ensure quality
        if correlation_strength >= 0.25 and len(evidence) >= 1:  # Minimum threshold with evidence requirement
            return {
                'confidence': min(correlation_strength, 1.0),
                'evidence': evidence,
                'context': context,
                'correlation_type': 'database_code_usage'
            }
        
        return None
    
    def _analyze_dynamic_static_correlation(self, dynamic_finding: Dict[str, Any], static_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze correlation between dynamic and static findings"""
        correlation_strength = 0.0
        evidence = []
        context = {}
        
        # Check location/file correlations
        dynamic_location = dynamic_finding.get('location', '')
        static_location = static_finding.get('location', '')
        
        if self._locations_related(dynamic_location, static_location):
            correlation_strength += 0.5  # Increased weight for location correlation
            evidence.append("Related file/location paths")
        
        # Enhanced location matching for database files
        if '.db' in dynamic_location and '.db' in static_location:
            # Extract database names for comparison
            dynamic_db_names = self._extract_database_names(dynamic_location)
            static_db_names = self._extract_database_names(static_location)
            
            for dyn_db in dynamic_db_names:
                for stat_db in static_db_names:
                    if dyn_db == stat_db:
                        correlation_strength += 0.6
                        evidence.append(f"Same database file referenced: {dyn_db}")
        
        # Check for similar vulnerability types
        dynamic_type = dynamic_finding.get('type', '').lower()
        static_type = static_finding.get('type', '').lower()
        
        if self._types_related(dynamic_type, static_type):
            correlation_strength += 0.4  # Increased weight for type correlation
            evidence.append("Related vulnerability types")
        
        # Enhanced type matching for database-related findings
        database_types = ['database', 'sqlite', 'hash', 'unencrypted', 'sql']
        dynamic_is_db = any(db_type in dynamic_type for db_type in database_types)
        static_is_db = any(db_type in static_type for db_type in database_types)
        
        if dynamic_is_db and static_is_db:
            correlation_strength += 0.3
            evidence.append("Both findings are database-related")
        
        # Check for dynamic correlation patterns
        dynamic_content = str(dynamic_finding.get('evidence', '')) + str(dynamic_finding.get('description', ''))
        static_content = str(static_finding.get('evidence', '')) + str(static_finding.get('description', ''))
        
        for pattern_type, patterns in self.dynamic_correlation_patterns.items():
            pattern_matches = 0
            for pattern in patterns:
                if re.search(pattern, dynamic_content, re.IGNORECASE) or re.search(pattern, static_content, re.IGNORECASE):
                    pattern_matches += 1
                    evidence.append(f"Dynamic correlation pattern '{pattern}' found")
            
            if pattern_matches > 0:
                correlation_strength += min(pattern_matches * 0.15, 0.3)
        
        # Check for custom field correlations
        dynamic_custom = dynamic_finding.get('custom_fields', {})
        static_custom = static_finding.get('custom_fields', {})
        
        # Database file correlation
        if dynamic_custom.get('database_reference') and static_custom.get('database_reference'):
            if dynamic_custom['database_reference'] == static_custom['database_reference']:
                correlation_strength += 0.5
                evidence.append(f"Database reference match: {dynamic_custom['database_reference']}")
        
        # Table correlation
        if dynamic_custom.get('table_name') and static_custom.get('table_name'):
            if dynamic_custom['table_name'] == static_custom['table_name']:
                correlation_strength += 0.4
                evidence.append(f"Table name match: {dynamic_custom['table_name']}")
        
        # Access type correlation
        if dynamic_custom.get('access_type') and 'database' in static_type:
            correlation_strength += 0.2
            evidence.append(f"Runtime access to database: {dynamic_custom['access_type']}")
        
        # Severity correlation
        if dynamic_finding.get('severity') == static_finding.get('severity') and dynamic_finding.get('severity') in ['HIGH', 'CRITICAL']:
            correlation_strength += 0.1
            evidence.append("Matching high/critical severity levels")
        
        # Tag correlation
        dynamic_tags = set(dynamic_finding.get('tags', []))
        static_tags = set(static_finding.get('tags', []))
        tag_overlap = len(dynamic_tags.intersection(static_tags))
        
        if tag_overlap > 0:
            correlation_strength += min(tag_overlap * 0.1, 0.2)
            evidence.append(f"Shared tags: {list(dynamic_tags.intersection(static_tags))}")
        
        context = {
            'dynamic_finding_type': dynamic_type,
            'static_finding_type': static_type,
            'dynamic_location': dynamic_location,
            'static_location': static_location,
            'correlation_methods': ['location_matching', 'type_matching', 'pattern_matching', 'semantic_matching'],
            'tag_overlap': tag_overlap
        }
        
        # Lowered threshold for better recall, but ensure quality
        if correlation_strength >= 0.25 and len(evidence) >= 1:  # Minimum threshold with evidence requirement
            return {
                'confidence': min(correlation_strength, 1.0),
                'evidence': evidence,
                'context': context,
                'correlation_type': 'dynamic_static_correlation'
            }
        
        return None
    
    def _is_chain_starter(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding can start a vulnerability chain"""
        severity = finding.get('severity', '').upper()
        finding_type = finding.get('type', '').lower()
        
        # High/Critical severity findings can start chains
        if severity in ['HIGH', 'CRITICAL']:
            return True
        
        # Database-related findings can start chains
        if self._is_database_finding(finding):
            return True
        
        # Certain vulnerability types can start chains
        chain_starter_types = [
            'unencrypted_database', 'hash_detection', 'sensitive_data',
            'permission_issue', 'configuration_issue'
        ]
        
        return any(starter_type in finding_type for starter_type in chain_starter_types)
    
    def _build_vulnerability_chain(self, primary_finding: Dict[str, Any], 
                                 all_findings: List[Dict[str, Any]], 
                                 processed: Set[str]) -> Optional[VulnerabilityChain]:
        """Build a vulnerability chain starting from primary finding"""
        related_findings = []
        chain_confidence = 0.0
        
        primary_id = primary_finding.get('id', '')
        
        for finding in all_findings:
            if finding.get('id') == primary_id or finding.get('id') in processed:
                continue
            
            # Check if finding is related to primary finding
            relation_strength = self._calculate_relation_strength(primary_finding, finding)
            if relation_strength >= 0.5:  # Threshold for inclusion in chain
                related_findings.append(finding)
                chain_confidence += relation_strength
        
        if related_findings:
            chain_confidence = chain_confidence / (len(related_findings) + 1)  # Average confidence
            
            # Determine chain severity (highest among findings)
            severities = [primary_finding.get('severity', 'LOW')] + [f.get('severity', 'LOW') for f in related_findings]
            chain_severity = self._determine_highest_severity(severities)
            
            # Generate impact description and mitigation strategy
            impact_description = self._generate_impact_description(primary_finding, related_findings)
            mitigation_strategy = self._generate_mitigation_strategy(primary_finding, related_findings)
            
            return VulnerabilityChain(
                chain_id=f"chain_{primary_id}",
                primary_finding=primary_finding,
                related_findings=related_findings,
                chain_severity=chain_severity,
                chain_confidence=chain_confidence,
                impact_description=impact_description,
                mitigation_strategy=mitigation_strategy
            )
        
        return None
    
    def _calculate_relation_strength(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate strength of relationship between two findings"""
        strength = 0.0
        
        # Location similarity
        loc1 = finding1.get('location', '')
        loc2 = finding2.get('location', '')
        if self._locations_related(loc1, loc2):
            strength += 0.3
        
        # Type similarity
        type1 = finding1.get('type', '').lower()
        type2 = finding2.get('type', '').lower()
        if self._types_related(type1, type2):
            strength += 0.4
        
        # Tag similarity
        tags1 = set(finding1.get('tags', []))
        tags2 = set(finding2.get('tags', []))
        tag_overlap = len(tags1.intersection(tags2))
        if tag_overlap > 0:
            strength += min(tag_overlap * 0.1, 0.3)
        
        return min(strength, 1.0)
    
    def _locations_related(self, loc1: str, loc2: str) -> bool:
        """Check if two locations are related"""
        if not loc1 or not loc2:
            return False
        
        # Same file
        if loc1 == loc2:
            return True
        
        # Same directory
        try:
            path1 = Path(loc1.split(':')[0])
            path2 = Path(loc2.split(':')[0])
            return path1.parent == path2.parent
        except:
            return False
    
    def _types_related(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are related"""
        related_groups = [
            ['database', 'sqlite', 'sql', 'hash', 'encryption'],
            ['permission', 'access', 'security'],
            ['network', 'communication', 'tls', 'ssl'],
            ['webview', 'javascript', 'web'],
            ['storage', 'external', 'backup', 'file']
        ]
        
        for group in related_groups:
            type1_match = any(keyword in type1 for keyword in group)
            type2_match = any(keyword in type2 for keyword in group)
            if type1_match and type2_match:
                return True
        
        return False
    
    def _determine_highest_severity(self, severities: List[str]) -> str:
        """Determine the highest severity from a list"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for severity in severity_order:
            if severity in severities:
                return severity
        return 'LOW'
    
    def _extract_database_names(self, location: str) -> List[str]:
        """Extract database names from location string"""
        names = []
        if '.db' in location:
            # Extract database filename
            db_file = location.split('/')[-1].split(':')[0]
            if db_file.endswith('.db'):
                names.append(db_file[:-3])  # Remove .db extension
        return names
    
    def _extract_table_names(self, finding: Dict[str, Any]) -> List[str]:
        """Extract table names from database finding"""
        names = []
        evidence = finding.get('evidence', '')
        custom_fields = finding.get('custom_fields', {})
        
        # Look for table names in evidence
        table_matches = re.findall(r'Table:\s*(\w+)', evidence)
        names.extend(table_matches)
        
        # Look for table names in custom fields
        if 'table_name' in custom_fields:
            names.append(custom_fields['table_name'])
        
        return list(set(names))  # Remove duplicates
    
    # Evidence collector methods
    def _collect_database_structure_evidence(self, finding: Dict[str, Any]) -> List[str]:
        """Collect database structure evidence"""
        evidence = []
        if self._is_database_finding(finding):
            custom_fields = finding.get('custom_fields', {})
            if 'table_name' in custom_fields:
                evidence.append(f"Database table: {custom_fields['table_name']}")
            if 'column_name' in custom_fields:
                evidence.append(f"Database column: {custom_fields['column_name']}")
            if 'hash_type' in custom_fields:
                evidence.append(f"Hash type detected: {custom_fields['hash_type']}")
        return evidence
    
    def _collect_code_usage_evidence(self, finding: Dict[str, Any]) -> List[str]:
        """Collect code usage evidence"""
        evidence = []
        if self._is_code_finding(finding):
            content = str(finding.get('evidence', '')) + str(finding.get('description', ''))
            for pattern_type, patterns in self.database_code_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence.append(f"Code pattern detected: {pattern_type}")
        return evidence
    
    def _collect_file_reference_evidence(self, finding: Dict[str, Any]) -> List[str]:
        """Collect file reference evidence"""
        evidence = []
        location = finding.get('location', '')
        if location:
            evidence.append(f"File reference: {location}")
        return evidence
    
    def _collect_permission_correlation_evidence(self, finding: Dict[str, Any]) -> List[str]:
        """Collect permission correlation evidence"""
        evidence = []
        finding_type = finding.get('type', '').lower()
        if 'permission' in finding_type:
            evidence.append(f"Permission-related finding: {finding_type}")
        return evidence
    
    def _collect_network_correlation_evidence(self, finding: Dict[str, Any]) -> List[str]:
        """Collect network correlation evidence"""
        evidence = []
        finding_type = finding.get('type', '').lower()
        tags = finding.get('tags', [])
        if 'network' in finding_type or any('network' in str(tag).lower() for tag in tags):
            evidence.append(f"Network-related finding: {finding_type}")
        return evidence
    
    # Context enhancer methods
    def _enhance_database_context(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enhance database context for finding"""
        if self._is_database_finding(finding):
            return {
                'finding_id': finding.get('id'),
                'context_type': 'database',
                'database_file': finding.get('location', '').split(':')[0],
                'database_operation': finding.get('type'),
                'security_impact': self._assess_database_security_impact(finding)
            }
        return None
    
    def _enhance_security_context(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enhance security context for finding"""
        severity = finding.get('severity', 'LOW')
        if severity in ['HIGH', 'CRITICAL']:
            return {
                'finding_id': finding.get('id'),
                'context_type': 'security',
                'severity_level': severity,
                'security_category': finding.get('type'),
                'potential_exploit': self._assess_exploit_potential(finding)
            }
        return None
    
    def _enhance_impact_context(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enhance impact context for finding"""
        return {
            'finding_id': finding.get('id'),
            'context_type': 'impact',
            'business_impact': self._assess_business_impact(finding),
            'technical_impact': self._assess_technical_impact(finding),
            'data_impact': self._assess_data_impact(finding)
        }
    
    def _enhance_mitigation_context(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enhance mitigation context for finding"""
        return {
            'finding_id': finding.get('id'),
            'context_type': 'mitigation',
            'recommended_actions': self._recommend_mitigation_actions(finding),
            'implementation_complexity': self._assess_implementation_complexity(finding),
            'priority_level': self._determine_mitigation_priority(finding)
        }
    
    def _assess_database_security_impact(self, finding: Dict[str, Any]) -> str:
        """Assess security impact of database finding"""
        finding_type = finding.get('type', '').lower()
        if 'unencrypted' in finding_type:
            return "Data exposure risk - sensitive data stored without encryption"
        elif 'hash' in finding_type:
            return "Credential compromise risk - weak hash algorithms detected"
        elif 'permission' in finding_type:
            return "Access control bypass risk - improper file permissions"
        else:
            return "General database security risk"
    
    def _assess_exploit_potential(self, finding: Dict[str, Any]) -> str:
        """Assess exploit potential of finding"""
        severity = finding.get('severity', 'LOW')
        finding_type = finding.get('type', '').lower()
        
        if severity == 'CRITICAL':
            return "High - immediate exploitation possible"
        elif severity == 'HIGH':
            return "Medium - exploitation requires moderate effort"
        else:
            return "Low - exploitation requires significant effort"
    
    def _assess_business_impact(self, finding: Dict[str, Any]) -> str:
        """Assess business impact of finding"""
        if self._is_database_finding(finding):
            return "Data breach potential, regulatory compliance risk"
        else:
            return "Security posture degradation, potential service disruption"
    
    def _assess_technical_impact(self, finding: Dict[str, Any]) -> str:
        """Assess technical impact of finding"""
        severity = finding.get('severity', 'LOW')
        if severity in ['CRITICAL', 'HIGH']:
            return "System compromise, data integrity loss"
        else:
            return "Security weakness, monitoring required"
    
    def _assess_data_impact(self, finding: Dict[str, Any]) -> str:
        """Assess data impact of finding"""
        if 'sensitive' in finding.get('type', '').lower():
            return "Sensitive data exposure risk"
        elif self._is_database_finding(finding):
            return "Database integrity and confidentiality risk"
        else:
            return "General data security risk"
    
    def _recommend_mitigation_actions(self, finding: Dict[str, Any]) -> List[str]:
        """Recommend mitigation actions for finding"""
        finding_type = finding.get('type', '').lower()
        actions = []
        
        if 'unencrypted' in finding_type:
            actions.extend([
                "Implement database encryption (SQLCipher)",
                "Review data sensitivity classification",
                "Apply access controls"
            ])
        elif 'hash' in finding_type:
            actions.extend([
                "Upgrade to secure hash algorithms (bcrypt, Argon2)",
                "Implement proper salting",
                "Review password policies"
            ])
        elif 'permission' in finding_type:
            actions.extend([
                "Set restrictive file permissions (600)",
                "Review filesystem access controls",
                "Implement principle of least privilege"
            ])
        else:
            actions.append("Review security configuration and apply best practices")
        
        return actions
    
    def _assess_implementation_complexity(self, finding: Dict[str, Any]) -> str:
        """Assess implementation complexity of mitigation"""
        finding_type = finding.get('type', '').lower()
        
        if 'permission' in finding_type:
            return "Low - configuration change"
        elif 'encryption' in finding_type:
            return "High - requires code changes and migration"
        else:
            return "Medium - requires code or configuration changes"
    
    def _determine_mitigation_priority(self, finding: Dict[str, Any]) -> str:
        """Determine mitigation priority"""
        severity = finding.get('severity', 'LOW')
        if severity == 'CRITICAL':
            return "Immediate"
        elif severity == 'HIGH':
            return "High"
        elif severity == 'MEDIUM':
            return "Medium"
        else:
            return "Low"
    
    def _generate_impact_description(self, primary_finding: Dict[str, Any], related_findings: List[Dict[str, Any]]) -> str:
        """Generate impact description for vulnerability chain"""
        primary_type = primary_finding.get('type', '')
        primary_severity = primary_finding.get('severity', 'LOW')
        
        description = f"Vulnerability chain impact: {primary_type} ({primary_severity} severity)"
        
        if related_findings:
            related_types = [f.get('type', '') for f in related_findings]
            description += f" combined with {len(related_findings)} related issues: {', '.join(related_types[:3])}"
            if len(related_findings) > 3:
                description += f" and {len(related_findings) - 3} more"
        
        return description
    
    def _generate_mitigation_strategy(self, primary_finding: Dict[str, Any], related_findings: List[Dict[str, Any]]) -> str:
        """Generate mitigation strategy for vulnerability chain"""
        all_findings = [primary_finding] + related_findings
        
        # Collect all recommended actions
        all_actions = []
        for finding in all_findings:
            actions = self._recommend_mitigation_actions(finding)
            all_actions.extend(actions)
        
        # Remove duplicates and prioritize
        unique_actions = list(set(all_actions))
        
        strategy = "Comprehensive mitigation strategy: "
        strategy += "; ".join(unique_actions[:5])  # Top 5 actions
        
        if len(unique_actions) > 5:
            strategy += f" and {len(unique_actions) - 5} additional actions"
        
        return strategy
    
    def _generate_analysis_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analysis metrics"""
        return {
            'total_findings_analyzed': len(findings),
            'database_findings_count': len([f for f in findings if self._is_database_finding(f)]),
            'code_findings_count': len([f for f in findings if self._is_code_finding(f)]),
            'dynamic_findings_count': len([f for f in findings if self._is_dynamic_finding(f)]),
            'cross_references_found': len(self.cross_references),
            'vulnerability_chains_created': len(self.vulnerability_chains),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of cross-reference analysis"""
        return {
            'cross_references': len(self.cross_references),
            'vulnerability_chains': len(self.vulnerability_chains),
            'correlation_types': list(set([cr.relationship_type for cr in self.cross_references])),
            'chain_severities': list(set([vc.chain_severity for vc in self.vulnerability_chains]))
        } 
 
 
 
 
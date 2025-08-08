#!/usr/bin/env python3
"""
Enhanced Deduplication Precision Fix
===================================

This module provides a surgical fix to the deduplication system to prevent
legitimate unique vulnerabilities from being incorrectly grouped as duplicates.

The fix addresses the specific issue where enhanced vulnerabilities with:
- Same file_path (manifest-related issues)
- Same line_number (configuration issues)
- Similar descriptions (same vulnerability category)

are incorrectly identified as duplicates when they represent distinct security issues.
"""

import hashlib
import logging
from typing import Dict, List, Any, Set
from core.unified_deduplication_framework.data_structures import DeduplicationStrategy

class EnhancedDeduplicationPrecisionFix:
    """
    Precision fix for deduplication that preserves unique vulnerabilities
    while still removing actual duplicates.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Enhanced vulnerability patterns that should never be considered duplicates
        # even if they share location information
        self.unique_vulnerability_indicators = {
            'title_keywords': [
                'debuggable', 'backup', 'network security', 'exported activities',
                'exported services', 'exported receivers', 'dangerous intent',
                'non-isolated', 'dangerous permission', 'deprecated permission',
                'excessive read/write'
            ],
            'pattern_types': [
                'm1', 'm2', 'm3', 'm8', 'insecure_storage', 'm1:_improper_platform_usage',
                'm8:_code_tampering', 'm3:_insecure_communication'
            ],
            'cwe_ids': [
                'CWE-200', 'CWE-319', 'CWE-693', 'CWE-20'
            ]
        }
    
    def calculate_enhanced_finding_hash(self, finding: Dict[str, Any]) -> str:
        """
        Calculate a more precise hash that considers vulnerability-specific fields
        to avoid false positive duplicates.
        """
        # Core identifying fields for true duplicates
        hash_content = []
        
        # Use vulnerability-specific ID if available (enhanced vulnerabilities)
        if finding.get('id'):
            hash_content.append(f"id:{finding['id']}")
        
        # Use title as primary identifier (more specific than file_path)
        if finding.get('title'):
            hash_content.append(f"title:{finding['title']}")
        
        # Include vulnerability pattern for enhanced precision
        if finding.get('vulnerable_pattern'):
            hash_content.append(f"pattern:{finding['vulnerable_pattern']}")
        
        # Include MASVS control for categorization
        if finding.get('masvs_control'):
            hash_content.append(f"masvs:{finding['masvs_control']}")
        
        # Include CWE ID for vulnerability type distinction
        if finding.get('cwe_id'):
            hash_content.append(f"cwe:{finding['cwe_id']}")
        
        # Only include file_path and line_number if they're specific (not generic)
        file_path = finding.get('file_path', '')
        line_number = finding.get('line_number', 0)
        
        # Skip generic file paths and line numbers that don't add specificity
        if file_path and not self._is_generic_location(file_path, line_number):
            hash_content.append(f"location:{file_path}:{line_number}")
        
        content_str = '|'.join(hash_content)
        return hashlib.md5(content_str.encode('utf-8')).hexdigest()
    
    def _is_generic_location(self, file_path: str, line_number: int) -> bool:
        """
        Check if a file path and line number are too generic to be useful
        for deduplication (e.g., manifest issues all at line 1).
        """
        # Configuration/metadata issues typically have generic locations
        if line_number is not None and line_number <= 1:
            return True
        
        # Manifest-related paths are often generic for multiple issues
        if 'AndroidManifest.xml' in file_path:
            return True
        
        # Decompiled files with same activity often have multiple issues
        if 'Activity.java' in file_path and line_number is not None and line_number <= 5:
            return True
        
        return False
    
    def is_legitimate_unique_vulnerability(self, finding1: Dict[str, Any], 
                                         finding2: Dict[str, Any]) -> bool:
        """
        Determine if two findings are legitimate unique vulnerabilities
        even if they have similar metadata.
        """
        # Check if they have different titles (strong indicator of uniqueness)
        title1 = finding1.get('title', '').lower()
        title2 = finding2.get('title', '').lower()
        
        if title1 != title2:
            # Check if titles contain different vulnerability indicators
            for keyword in self.unique_vulnerability_indicators['title_keywords']:
                if (keyword in title1) != (keyword in title2):
                    self.logger.info(f"🔍 Found unique vulnerabilities: '{title1}' vs '{title2}'")
                    return True
        
        # Check if they have different vulnerability patterns
        pattern1 = finding1.get('vulnerable_pattern', '')
        pattern2 = finding2.get('vulnerable_pattern', '')
        if pattern1 and pattern2 and pattern1 != pattern2:
            self.logger.info(f"🔍 Different patterns: '{pattern1}' vs '{pattern2}'")
            return True
        
        # Check if they have different CWE IDs
        cwe1 = finding1.get('cwe_id', '')
        cwe2 = finding2.get('cwe_id', '')
        if cwe1 and cwe2 and cwe1 != cwe2:
            self.logger.info(f"🔍 Different CWE IDs: '{cwe1}' vs '{cwe2}'")
            return True
        
        # Check if they have different MASVS controls
        masvs1 = finding1.get('masvs_control', '')
        masvs2 = finding2.get('masvs_control', '')
        if masvs1 and masvs2 and masvs1 != masvs2:
            self.logger.info(f"🔍 Different MASVS controls: '{masvs1}' vs '{masvs2}'")
            return True
        
        return False
    
    def apply_precision_deduplication(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply precision deduplication that preserves legitimate unique vulnerabilities.
        """
        if not findings:
            return findings
        
        self.logger.info(f"🔧 Applying precision deduplication to {len(findings)} findings")
        
        # Group findings by enhanced hash
        hash_groups = {}
        for finding in findings:
            finding_hash = self.calculate_enhanced_finding_hash(finding)
            if finding_hash not in hash_groups:
                hash_groups[finding_hash] = []
            hash_groups[finding_hash].append(finding)
        
        # Process each group
        unique_findings = []
        duplicates_removed = 0
        
        for finding_hash, group_findings in hash_groups.items():
            if len(group_findings) == 1:
                # Single finding - definitely unique
                unique_findings.append(group_findings[0])
            else:
                # Multiple findings with same hash - check if they're truly duplicates
                processed_in_group = set()
                
                for i, finding1 in enumerate(group_findings):
                    if i in processed_in_group:
                        continue
                    
                    # Check against remaining findings in group
                    is_unique = True
                    for j, finding2 in enumerate(group_findings[i+1:], i+1):
                        if j in processed_in_group:
                            continue
                        
                        # If they're NOT legitimate unique vulnerabilities, they're duplicates
                        if not self.is_legitimate_unique_vulnerability(finding1, finding2):
                            # finding2 is a duplicate of finding1
                            processed_in_group.add(j)
                            duplicates_removed += 1
                            is_unique = False
                    
                    if is_unique or i not in processed_in_group:
                        unique_findings.append(finding1)
                        processed_in_group.add(i)
        
        self.logger.info(f"✅ Precision deduplication complete: {len(findings)} → {len(unique_findings)} "
                        f"({duplicates_removed} duplicates removed)")
        
        return unique_findings

def apply_enhanced_deduplication_precision(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function to apply enhanced deduplication precision fix.
    """
    precision_fix = EnhancedDeduplicationPrecisionFix()
    return precision_fix.apply_precision_deduplication(findings)
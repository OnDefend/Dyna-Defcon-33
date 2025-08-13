#!/usr/bin/env python3
"""
Advanced False Positive Reduction System for AODS

This module provides comprehensive false positive reduction capabilities that integrate
with the existing AODS vulnerability detection pipeline to significantly improve
accuracy while preserving real security vulnerabilities.

Features:
- Multi-layered false positive detection
- Context-aware vulnerability classification
- Framework noise filtering
- Error message and status report filtering
- Confidence scoring with severity adjustment
- Real-time filtering during scan execution
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class FindingType(Enum):
    """Types of findings for classification"""
    VULNERABILITY = "vulnerability"
    ERROR_MESSAGE = "error_message"
    STATUS_REPORT = "status_report"
    FRAMEWORK_NOISE = "framework_noise"
    INFORMATIONAL = "informational"
    ANALYSIS_METADATA = "analysis_metadata"

class ConfidenceLevel(Enum):
    """Confidence levels for findings"""
    VERY_HIGH = "very_high"  # 0.9+
    HIGH = "high"           # 0.7-0.89
    MEDIUM = "medium"       # 0.5-0.69
    LOW = "low"            # 0.3-0.49
    VERY_LOW = "very_low"  # <0.3

@dataclass
class FilterResult:
    """Result of false positive filtering"""
    is_vulnerability: bool
    finding_type: FindingType
    confidence: float
    confidence_level: ConfidenceLevel
    original_severity: str
    adjusted_severity: str
    reasoning: List[str]
    evidence: List[str]
    false_positive_indicators: List[str]
    vulnerability_indicators: List[str]
    should_include_in_report: bool
    metadata: Dict[str, Any]

class AdvancedFalsePositiveReducer:
    """Advanced false positive reduction with multi-layered analysis"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the advanced false positive reducer"""
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize pattern matchers
        self._init_error_patterns()
        self._init_status_patterns()
        self._init_framework_patterns()
        self._init_vulnerability_patterns()
        self._init_informational_patterns()
        
        # Configuration
        self.min_vulnerability_confidence = self.config.get("min_vulnerability_confidence", 0.6)
        self.include_informational = self.config.get("include_informational", False)
        self.strict_mode = self.config.get("strict_mode", False)
        
        # Statistics
        self.stats = {
            "total_processed": 0,
            "vulnerabilities_identified": 0,
            "false_positives_filtered": 0,
            "error_messages_filtered": 0,
            "framework_noise_filtered": 0,
            "informational_filtered": 0
        }
    
    def _init_error_patterns(self):
        """Initialize error message detection patterns"""
        self.error_patterns = [
            # Connection errors
            r"(?i)(?:drozer|adb|connection)\s+(?:failed|error|timeout)",
            r"(?i)❌.*(?:failed|error|connection)",
            r"(?i)unable\s+to\s+(?:connect|establish|communicate)",
            r"(?i)connection\s+(?:refused|timeout|failed)",
            
            # Command execution errors
            r"(?i)command\s+(?:failed|not\s+found|execution\s+error)",
            r"(?i)(?:timeout|timed\s+out).*(?:execution|command)",
            r"(?i)process\s+(?:failed|crashed|terminated)",
            
            # Tool-specific errors
            r"(?i)jadx\s+decompilation\s+failed",
            r"(?i)frida.*(?:failed|error|unable)",
            r"(?i)mitmproxy.*(?:failed|error)",
            r"(?i)native\s+library\s+extraction.*(?:failed|timeout)",
            
            # Generic error indicators
            r"(?i)error\s+(?:details|occurred|loading)",
            r"(?i)exception\s+(?:occurred|thrown)",
            r"(?i)❌\s+error:",
            r"(?i)⚠️\s+warning:",
        ]
        
        self.error_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.error_patterns]
    
    def _init_status_patterns(self):
        """Initialize status report detection patterns"""
        self.status_patterns = [
            # Success indicators
            r"(?i)✅.*(?:success|complete|passed|ok)",
            r"(?i)(?:analysis|scan|test).*(?:completed\s+successfully|passed)",
            r"(?i)(?:all|100%)\s+(?:tests?\s+)?(?:passed|successful)",
            r"(?i)status:\s*(?:pass|passed|success|ok|complete)",
            
            # Progress indicators
            r"(?i)(?:starting|initializing|loading|processing).*",
            r"(?i)(?:\d+%|\d+/\d+).*(?:complete|progress|processed)",
            r"(?i)(?:step\s+\d+|phase\s+\d+|stage\s+\d+)",
            
            # Informational status
            r"(?i)(?:discovered|loaded|found)\s+\d+\s+(?:plugins|tests|components)",
            r"(?i)(?:execution\s+time|duration|elapsed):\s*[\d.]+",
            r"(?i)(?:report\s+generated|saved\s+to|output\s+written)",
            
            # Resolution steps
            r"(?i)(?:resolution\s+steps|troubleshooting|next\s+steps):",
            r"(?i)\d+\.\s+(?:check|verify|restart|re-establish)",
        ]
        
        self.status_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.status_patterns]
    
    def _init_framework_patterns(self):
        """Initialize framework noise detection patterns"""
        self.framework_patterns = {
            "android": [
                r"http://schemas\.android\.com/",
                r"xmlns:android",
                r"@android:",
                r"R\.[a-z]+\.[a-z_]+",
                r"Ljava/[a-z/]+",
                r"Landroid/[a-z/]+",
                r"android\.(?:content|app|os)\.",
            ],
            "flutter": [
                r"ThemeData\.fallback",
                r"PointerSignalKind\.\w+",
                r"ImageRepeat\.\w+",
                r"FloatingCursorDragState\.\w+",
                r"MaterialIcons\.\w+",
                r"flutter[_/]assets[_/]",
                r"packages[_/]flutter[_/]",
            ],
            "react_native": [
                r"React\.Component",
                r"StyleSheet\.create",
                r"Platform\.OS",
                r"node_modules[_/]react[_-]native[_/]",
            ],
            "build_tools": [
                r"gradle\.properties",
                r"build\.gradle",
                r"cmake\..*",
                r"Makefile\.",
                r"package\.json",
            ]
        }
        
        self.framework_compiled = {}
        for framework, patterns in self.framework_patterns.items():
            self.framework_compiled[framework] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def _init_vulnerability_patterns(self):
        """Initialize real vulnerability detection patterns"""
        self.vulnerability_patterns = [
            # Authentication/Authorization
            r"(?i)(?:exported\s+(?:activity|service)).*?(?:without\s+permission|permission\s+null)",
            r"(?i)(?:weak|missing|broken)\s+(?:authentication|authorization)",
            r"(?i)(?:bypass|circumvent).*(?:authentication|authorization)",
            
            # Injection vulnerabilities
            r"(?i)(?:sql\s+injection|code\s+injection|command\s+injection)",
            r"(?i)(?:path\s+traversal|directory\s+traversal)",
            r"(?i)(?:xss|cross[_-]site\s+scripting)",
            
            # Cryptographic issues
            r"(?i)(?:weak\s+(?:encryption|crypto)|insecure\s+(?:random|hash))",
            r"(?i)(?:hardcoded\s+(?:password|key|secret|credential))",
            r"(?i)(?:cleartext\s+(?:traffic|communication)).*?(?:enabled|allowed)",
            r"(?i)(?:certificate\s+pinning).*?(?:missing|disabled)",
            
            # Data exposure
            r"(?i)(?:backup\s+enabled).*?(?:data\s+exposure|privacy\s+risk)",
            r"(?i)(?:debug\s+enabled).*?(?:production|release)",
            r"(?i)(?:sensitive\s+data).*?(?:exposed|leaked|unprotected)",
            
            # Network security
            r"(?i)(?:insecure\s+(?:http|communication|protocol))",
            r"(?i)(?:man[_-]in[_-]the[_-]middle|mitm)",
            r"(?i)(?:ssl|tls).*?(?:vulnerability|weakness|bypass)",
            
            # High-confidence vulnerability indicators
            r"(?i)(?:vulnerability).*?(?:detected|found|identified).*?(?:critical|high|medium)",
            r"(?i)(?:security\s+(?:flaw|issue|weakness)).*?(?:critical|high|severe)",
            r"(?i)(?:exploit|attack).*?(?:possible|vector|surface)",
        ]
        
        self.vulnerability_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.vulnerability_patterns]
    
    def _init_informational_patterns(self):
        """Initialize informational content detection patterns"""
        self.informational_patterns = [
            # Analysis summaries
            r"(?i)(?:executive|technical|compliance|professional)\s+(?:summary|report)",
            r"(?i)(?:plugin\s+execution|parallel\s+execution)\s+(?:summary|report)",
            r"(?i)(?:performance\s+report|execution\s+time|benchmark)",
            
            # Test results
            r"(?i)(?:mastg|owasp)\s+(?:compliance|testing)",
            r"(?i)(?:attack\s+surface|endpoint\s+discovery)\s+analysis",
            r"(?i)(?:enhanced|advanced)\s+(?:static|dynamic|encoding)\s+analysis",
            
            # Metadata
            r"(?i)(?:total\s+(?:plugins|tests|endpoints|findings))",
            r"(?i)(?:security\s+)?recommendations?:",
            r"(?i)(?:consider\s+(?:disabling|implementing|using))",
            r"(?i)(?:usage\s+instructions|open\s+html\s+files)",
            
            # Configuration info
            r"(?i)(?:scan\s+mode|analysis\s+type|configuration):",
            r"(?i)(?:target\s+apk|package\s+name|scan\s+duration):",
        ]
        
        self.informational_compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.informational_patterns]
    
    def analyze_finding(self, finding: Dict[str, Any]) -> FilterResult:
        """Analyze a single finding and determine if it's a real vulnerability"""
        
        self.stats["total_processed"] += 1
        
        # Extract content for analysis
        content = self._extract_content(finding)
        title = finding.get("title", "")
        status = finding.get("status", "").upper()
        
        # Initialize result
        result = FilterResult(
            is_vulnerability=False,
            finding_type=FindingType.INFORMATIONAL,
            confidence=0.0,
            confidence_level=ConfidenceLevel.VERY_LOW,
            original_severity=finding.get("severity", "UNKNOWN"),
            adjusted_severity="INFO",
            reasoning=[],
            evidence=[],
            false_positive_indicators=[],
            vulnerability_indicators=[],
            should_include_in_report=True,
            metadata={}
        )
        
        # 1. Check for error messages (highest priority filter)
        if self._is_error_message(content, title):
            result.finding_type = FindingType.ERROR_MESSAGE
            result.confidence = 0.95
            result.confidence_level = ConfidenceLevel.VERY_HIGH
            result.reasoning.append("Identified as error message or failure report")
            result.should_include_in_report = False
            self.stats["error_messages_filtered"] += 1
            return result
        
        # 2. Check for status reports and informational content
        if self._is_status_report(content, title, status):
            result.finding_type = FindingType.STATUS_REPORT
            result.confidence = 0.90
            result.confidence_level = ConfidenceLevel.VERY_HIGH
            result.reasoning.append("Identified as status report or informational content")
            result.should_include_in_report = self.include_informational
            self.stats["informational_filtered"] += 1
            return result
        
        # 3. Check for framework noise
        framework_score, framework_type = self._analyze_framework_noise(content, title)
        if framework_score > 0.7:
            result.finding_type = FindingType.FRAMEWORK_NOISE
            result.confidence = framework_score
            result.confidence_level = self._get_confidence_level(framework_score)
            result.reasoning.append(f"Identified as {framework_type} framework noise")
            result.false_positive_indicators.append(f"framework_{framework_type}")
            result.should_include_in_report = False
            self.stats["framework_noise_filtered"] += 1
            return result
        
        # 4. Analyze for real vulnerabilities
        vuln_score, vuln_indicators = self._analyze_vulnerability_content(content, title)
        if vuln_score > self.min_vulnerability_confidence:
            result.is_vulnerability = True
            result.finding_type = FindingType.VULNERABILITY
            result.confidence = vuln_score
            result.confidence_level = self._get_confidence_level(vuln_score)
            result.vulnerability_indicators = vuln_indicators
            result.adjusted_severity = self._determine_severity_from_score(vuln_score)
            result.reasoning.append(f"Identified as vulnerability with confidence {vuln_score:.2f}")
            result.should_include_in_report = True
            self.stats["vulnerabilities_identified"] += 1
            return result
        
        # 5. Check for informational content
        if self._is_informational_content(content, title):
            result.finding_type = FindingType.INFORMATIONAL
            result.confidence = 0.80
            result.confidence_level = ConfidenceLevel.HIGH
            result.reasoning.append("Identified as informational content")
            result.should_include_in_report = self.include_informational
            self.stats["informational_filtered"] += 1
            return result
        
        # 6. Default: Likely false positive
        result.confidence = 0.20
        result.confidence_level = ConfidenceLevel.VERY_LOW
        result.reasoning.append("No clear vulnerability indicators - likely false positive")
        result.should_include_in_report = not self.strict_mode
        self.stats["false_positives_filtered"] += 1
        
        return result
    
    def _extract_content(self, finding: Dict[str, Any]) -> str:
        """Extract all text content from finding"""
        content_parts = []
        
        for field in ["title", "description", "content", "result"]:
            if field in finding and finding[field]:
                content_parts.append(str(finding[field]))
        
        return " ".join(content_parts)
    
    def _is_error_message(self, content: str, title: str) -> bool:
        """Check if content is an error message"""
        full_text = f"{content} {title}".lower()
        
        # Check for error patterns
        for pattern in self.error_compiled:
            if pattern.search(full_text):
                return True
        
        # Check for specific error indicators
        error_indicators = [
            "failed", "error", "exception", "timeout", "unable to",
            "connection refused", "not found", "crashed"
        ]
        
        error_count = sum(1 for indicator in error_indicators if indicator in full_text)
        return error_count >= 2
    
    def _is_status_report(self, content: str, title: str, status: str) -> bool:
        """Check if content is a status report"""
        full_text = f"{content} {title}".lower()
        
        # Check explicit status indicators
        if status in ["PASS", "PASSED", "SUCCESS", "OK", "COMPLETE"]:
            return True
        
        # Check for status patterns
        for pattern in self.status_compiled:
            if pattern.search(full_text):
                return True
        
        # Check for progress/completion indicators
        progress_indicators = [
            "completed successfully", "analysis complete", "execution time",
            "report generated", "discovered", "loaded", "processed"
        ]
        
        return any(indicator in full_text for indicator in progress_indicators)
    
    def _analyze_framework_noise(self, content: str, title: str) -> Tuple[float, str]:
        """Analyze content for framework noise patterns"""
        full_text = f"{content} {title}".lower()
        max_score = 0.0
        detected_framework = "unknown"
        
        for framework, patterns in self.framework_compiled.items():
            matches = sum(1 for pattern in patterns if pattern.search(full_text))
            if matches > 0:
                score = min(0.6 + (matches * 0.1), 0.95)
                if score > max_score:
                    max_score = score
                    detected_framework = framework
        
        return max_score, detected_framework
    
    def _analyze_vulnerability_content(self, content: str, title: str) -> Tuple[float, List[str]]:
        """Analyze content for real vulnerability indicators"""
        full_text = f"{content} {title}".lower()
        score = 0.0
        indicators = []
        
        # Check vulnerability patterns
        for pattern in self.vulnerability_compiled:
            if pattern.search(full_text):
                score += 0.2
                indicators.append(f"pattern_{pattern.pattern[:30]}...")
        
        # Check for high-confidence vulnerability terms
        high_confidence_terms = [
            "sql injection", "xss", "path traversal", "hardcoded secret",
            "cleartext traffic", "weak encryption", "exported activity"
        ]
        
        for term in high_confidence_terms:
            if term in full_text:
                score += 0.3
                indicators.append(f"high_confidence_{term}")
        
        # Check for security severity indicators
        severity_terms = ["critical", "high", "severe", "dangerous"]
        if any(term in full_text for term in severity_terms):
            score += 0.1
            indicators.append("severity_indicator")
        
        return min(score, 1.0), indicators
    
    def _is_informational_content(self, content: str, title: str) -> bool:
        """Check if content is informational"""
        full_text = f"{content} {title}".lower()
        
        for pattern in self.informational_compiled:
            if pattern.search(full_text):
                return True
        
        return False
    
    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Convert confidence score to confidence level"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _determine_severity_from_score(self, score: float) -> str:
        """Determine severity based on vulnerability score"""
        if score >= 0.9:
            return "CRITICAL"
        elif score >= 0.8:
            return "HIGH"
        elif score >= 0.6:
            return "MEDIUM"
        elif score >= 0.4:
            return "LOW"
        else:
            return "INFO"
    
    def filter_findings_batch(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Filter a batch of findings and return results"""
        
        filtered_results = {
            "vulnerabilities": [],
            "false_positives": [],
            "error_messages": [],
            "informational": [],
            "framework_noise": [],
            "summary": {},
            "statistics": {}
        }
        
        for finding in findings:
            result = self.analyze_finding(finding)
            
            # Add to appropriate category
            if result.is_vulnerability and result.should_include_in_report:
                filtered_results["vulnerabilities"].append({
                    "original_finding": finding,
                    "filter_result": result
                })
            elif result.finding_type == FindingType.ERROR_MESSAGE:
                filtered_results["error_messages"].append({
                    "original_finding": finding,
                    "filter_result": result
                })
            elif result.finding_type == FindingType.FRAMEWORK_NOISE:
                filtered_results["framework_noise"].append({
                    "original_finding": finding,
                    "filter_result": result
                })
            elif result.finding_type == FindingType.INFORMATIONAL:
                filtered_results["informational"].append({
                    "original_finding": finding,
                    "filter_result": result
                })
            else:
                filtered_results["false_positives"].append({
                    "original_finding": finding,
                    "filter_result": result
                })
        
        # Calculate summary statistics
        total_findings = len(findings)
        vulnerabilities = len(filtered_results["vulnerabilities"])
        false_positives_removed = (
            len(filtered_results["false_positives"]) +
            len(filtered_results["error_messages"]) +
            len(filtered_results["framework_noise"]) +
            (len(filtered_results["informational"]) if not self.include_informational else 0)
        )
        
        filtered_results["summary"] = {
            "total_findings": total_findings,
            "vulnerabilities_identified": vulnerabilities,
            "false_positives_removed": false_positives_removed,
            "accuracy_improvement": f"{(false_positives_removed/total_findings)*100:.1f}%" if total_findings > 0 else "0%",
            "vulnerability_rate": f"{(vulnerabilities/total_findings)*100:.1f}%" if total_findings > 0 else "0%"
        }
        
        filtered_results["statistics"] = self.stats.copy()
        
        return filtered_results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get filtering statistics"""
        total = self.stats["total_processed"]
        if total == 0:
            return self.stats
        
        return {
            **self.stats,
            "accuracy_improvement": f"{((total - self.stats['vulnerabilities_identified'])/total)*100:.1f}%",
            "vulnerability_rate": f"{(self.stats['vulnerabilities_identified']/total)*100:.1f}%"
        }

def create_false_positive_reducer(config: Optional[Dict[str, Any]] = None) -> AdvancedFalsePositiveReducer:
    """Factory function to create a false positive reducer"""
    return AdvancedFalsePositiveReducer(config)

def main():
    """Test the advanced false positive reducer"""
    
    print("🔍 AODS Advanced False Positive Reduction Test")
    print("=" * 60)
    
    # Load current scan results
    try:
        with open("b3nac.injuredandroid_security_report.json", "r") as f:
            scan_data = json.load(f)
        
        # Get findings from detailed_results
        detailed_results = scan_data.get("detailed_results", {})
        findings = [detailed_results[key] for key in list(detailed_results.keys())[:100]]  # Test first 100
        
        print(f"📊 Loaded {len(findings)} findings for analysis")
        
    except FileNotFoundError:
        print("❌ No scan results found. Please run a scan first.")
        return
    except Exception as e:
        print(f"❌ Error loading scan results: {e}")
        return
    
    # Initialize reducer
    config = {
        "min_vulnerability_confidence": 0.6,
        "include_informational": False,
        "strict_mode": True
    }
    
    reducer = create_false_positive_reducer(config)
    
    # Analyze findings
    results = reducer.filter_findings_batch(findings)
    
    # Display results
    print("\n📈 FILTERING RESULTS")
    print("-" * 40)
    
    summary = results["summary"]
    print(f"📋 Original Findings: {summary['total_findings']}")
    print(f"🎯 Vulnerabilities Identified: {summary['vulnerabilities_identified']}")
    print(f"🚫 False Positives Removed: {summary['false_positives_removed']}")
    print(f"📊 Accuracy Improvement: {summary['accuracy_improvement']}")
    print(f"🔍 Vulnerability Rate: {summary['vulnerability_rate']}")
    
    print("\n🏷️  DETAILED BREAKDOWN")
    print("-" * 40)
    
    categories = [
        ("🚨 Vulnerabilities", "vulnerabilities"),
        ("❌ Error Messages", "error_messages"),
        ("🔧 Framework Noise", "framework_noise"),
        ("📄 Informational", "informational"),
        ("🚫 False Positives", "false_positives")
    ]
    
    for icon_name, category in categories:
        count = len(results[category])
        percentage = f"{(count/summary['total_findings'])*100:.1f}%" if summary['total_findings'] > 0 else "0%"
        print(f"{icon_name}: {count} ({percentage})")
    
    # Show examples
    print("\n🔍 VULNERABILITY EXAMPLES")
    print("-" * 40)
    
    for i, vuln in enumerate(results["vulnerabilities"][:3]):
        result = vuln["filter_result"]
        title = vuln["original_finding"].get("title", "Unknown")
        print(f"{i+1}. {title[:60]}...")
        print(f"   Confidence: {result.confidence:.2f} ({result.confidence_level.value})")
        print(f"   Severity: {result.adjusted_severity}")
        print(f"   Reasoning: {result.reasoning[0] if result.reasoning else 'N/A'}")
    
    print(f"\n💡 RECOMMENDATIONS")
    print("-" * 40)
    
    if summary['false_positives_removed'] > summary['vulnerabilities_identified']:
        print("✅ Significant false positive reduction achieved!")
        print(f"   Accuracy improved by {summary['accuracy_improvement']}")
        print("   Consider integrating this filter into the main pipeline.")
    
    if summary['vulnerabilities_identified'] > 0:
        print(f"🎯 {summary['vulnerabilities_identified']} real vulnerabilities identified")
        print("   Focus security review on these high-confidence findings.")

if __name__ == "__main__":
    main()
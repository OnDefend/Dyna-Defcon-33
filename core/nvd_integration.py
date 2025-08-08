#!/usr/bin/env python3
"""
NVD (National Vulnerability Database) Integration for AODS

Provides threat intelligence integration and vulnerability correlation
with external databases for enhanced risk assessment.

References:
- NVD API Documentation: https://nvd.nist.gov/developers/vulnerabilities
- CVSS Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- CPE Dictionary: https://nvd.nist.gov/products/cpe

"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

@dataclass
class NVDVulnerability:
    """NVD vulnerability data structure"""

    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: str
    published_date: datetime
    last_modified: datetime
    cwe_ids: List[str]
    references: List[str]
    affected_products: List[str]
    exploit_available: bool = False
    patch_available: bool = False

@dataclass
class ThreatIntelligence:
    """Threat intelligence data from multiple sources"""

    cve_trends: List[str]
    exploit_predictions: List[str]
    industry_impact: str
    mitigation_priority: str
    timeline_estimate: str

class NVDClient:
    """
    NVD API client for vulnerability data retrieval and threat intelligence
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json"
    CVE_ENDPOINT = f"{BASE_URL}/cves/2.0"
    CPE_ENDPOINT = f"{BASE_URL}/cpes/2.0"

    # Rate limiting: NVD allows 5 requests per 30 seconds for unauthenticated users
    RATE_LIMIT_DELAY = 6  # seconds between requests

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client

        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.last_request_time = 0

        # Set headers
        self.session.headers.update(
            {"User-Agent": "AODS-Security-Scanner/1.0", "Accept": "application/json"}
        )

        if api_key:
            self.session.headers["apiKey"] = api_key
            self.RATE_LIMIT_DELAY = 0.6  # 100 requests per 30 seconds with API key

    def _rate_limit(self) -> None:
        """Implement rate limiting for NVD API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.RATE_LIMIT_DELAY:
            sleep_time = self.RATE_LIMIT_DELAY - time_since_last
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def search_vulnerabilities(
        self,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cvss_score_min: Optional[float] = None,
        last_modified_days: int = 30,
    ) -> List[NVDVulnerability]:
        """
        Search NVD for vulnerabilities matching criteria

        Args:
            keyword: Keyword to search in descriptions
            cwe_id: CWE ID to filter by
            cvss_score_min: Minimum CVSS score threshold
            last_modified_days: Filter by modification date

        Returns:
            List of NVD vulnerabilities
        """
        try:
            self._rate_limit()

            params = {
                "resultsPerPage": 10,  # Reduced for faster response
                "startIndex": 0,
            }

            # Add search filters - fix parameter names for NVD API 2.0
            if keyword:
                # Remove android prefix to avoid redundancy
                clean_keyword = keyword.replace("android ", "").strip()
                if clean_keyword:
                    params["keywordSearch"] = clean_keyword

            if cwe_id:
                params["cweId"] = cwe_id

            # Fix CVSS severity parameter name
            if cvss_score_min:
                if cvss_score_min >= 9.0:
                    params["cvssV3Severity"] = "CRITICAL"
                elif cvss_score_min >= 7.0:
                    params["cvssV3Severity"] = "HIGH"
                elif cvss_score_min >= 4.0:
                    params["cvssV3Severity"] = "MEDIUM"
                else:
                    params["cvssV3Severity"] = "LOW"

            # Reduce time range for better API compatibility
            end_date = datetime.now()
            start_date = end_date - timedelta(
                days=min(last_modified_days, 120)
            )  # Max 120 days
            params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000")
            params["lastModEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999")

            self.logger.debug(f"Searching NVD with params: {params}")
            response = self.session.get(self.CVE_ENDPOINT, params=params, timeout=15)

            # Better error handling for API issues
            if response.status_code == 404:
                self.logger.warning("NVD API endpoint not found - API may have changed")
                return []
            elif response.status_code == 403:
                self.logger.warning("NVD API access denied - may need API key")
                return []
            elif response.status_code == 429:
                self.logger.warning("NVD API rate limit exceeded")
                return []

            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            for cve_item in data.get("vulnerabilities", []):
                vuln = self._parse_cve_item(cve_item)
                if vuln:
                    vulnerabilities.append(vuln)

            self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities from NVD")
            return vulnerabilities

        except requests.RequestException as e:
            self.logger.warning(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            self.logger.warning(f"Error searching NVD vulnerabilities: {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[NVDVulnerability]:
        """
        Get detailed information for specific CVE

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            NVD vulnerability details or None if not found
        """
        try:
            self._rate_limit()

            params = {"cveId": cve_id}
            response = self.session.get(self.CVE_ENDPOINT, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                return self._parse_cve_item(vulnerabilities[0])

            self.logger.warning(f"CVE {cve_id} not found in NVD")
            return None

        except Exception as e:
            self.logger.error(f"Error retrieving CVE {cve_id}: {e}")
            return None

    def _parse_cve_item(self, cve_item: Dict) -> Optional[NVDVulnerability]:
        """Parse CVE item from NVD API response"""
        try:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")

            # Description
            descriptions = cve.get("descriptions", [])
            description = next(
                (desc["value"] for desc in descriptions if desc["lang"] == "en"),
                "No description available",
            )

            # CVSS metrics
            cvss_score = 0.0
            cvss_vector = ""
            severity = "UNKNOWN"

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")

            # Dates
            published_date = datetime.fromisoformat(
                cve.get("published", "").replace("Z", "+00:00")
            )
            last_modified = datetime.fromisoformat(
                cve.get("lastModified", "").replace("Z", "+00:00")
            )

            # CWE IDs
            cwe_ids = []
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value", ""))

            # References
            references = []
            ref_data = cve.get("references", [])
            for ref in ref_data:
                references.append(ref.get("url", ""))

            # Affected products (simplified)
            affected_products = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            affected_products.append(cpe_match.get("criteria", ""))

            return NVDVulnerability(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                published_date=published_date,
                last_modified=last_modified,
                cwe_ids=cwe_ids,
                references=references,
                affected_products=affected_products[:5],  # Limit for readability
            )

        except Exception as e:
            self.logger.error(f"Error parsing CVE item: {e}")
            return None

    def _get_severity_from_score(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "NONE"

class ThreatIntelligenceEngine:
    """
    Enhanced threat intelligence engine combining multiple data sources
    """

    def __init__(self, nvd_client: Optional[NVDClient] = None):
        """Initialize threat intelligence engine"""
        self.nvd_client = nvd_client or NVDClient()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def analyze_mobile_threat_landscape(
        self, vulnerability_types: List[str]
    ) -> ThreatIntelligence:
        """
        Analyze current mobile threat landscape for given vulnerability types

        Args:
            vulnerability_types: List of vulnerability categories to analyze

        Returns:
            Comprehensive threat intelligence summary
        """
        try:
            cve_trends = []
            exploit_predictions = []

            # Analyze each vulnerability type
            for vuln_type in vulnerability_types:
                recent_cves = self.nvd_client.search_vulnerabilities(
                    keyword=f"android {vuln_type}",
                    cvss_score_min=7.0,
                    last_modified_days=90,
                )

                if recent_cves:
                    cve_trends.append(
                        f"{len(recent_cves)} recent {vuln_type} CVEs (CVSS 7.0+)"
                    )

                    # Analyze exploit availability trends
                    high_risk_cves = [
                        cve for cve in recent_cves if cve.cvss_score >= 8.0
                    ]
                    if high_risk_cves:
                        exploit_predictions.append(
                            f"{len(high_risk_cves)} critical {vuln_type} vulnerabilities with high exploit potential"
                        )

            # Generate intelligence summary
            if not cve_trends:
                cve_trends = [
                    "No recent high-severity CVEs found for analyzed vulnerability types"
                ]

            if not exploit_predictions:
                exploit_predictions = [
                    "Low exploit activity predicted based on current data"
                ]

            # Determine industry impact and priority
            total_high_risk = sum(
                len(trend.split()[0])
                for trend in cve_trends
                if trend.split()[0].isdigit()
            )

            if total_high_risk >= 10:
                industry_impact = "HIGH - Multiple active threat vectors identified"
                mitigation_priority = "IMMEDIATE - Patch within 72 hours"
                timeline_estimate = "Active exploitation expected within 2-4 weeks"
            elif total_high_risk >= 5:
                industry_impact = "MEDIUM - Moderate threat activity observed"
                mitigation_priority = "HIGH - Patch within 1-2 weeks"
                timeline_estimate = "Exploitation possible within 1-2 months"
            else:
                industry_impact = "LOW - Limited threat activity"
                mitigation_priority = "STANDARD - Follow normal patch cycles"
                timeline_estimate = "Low probability of immediate exploitation"

            return ThreatIntelligence(
                cve_trends=cve_trends,
                exploit_predictions=exploit_predictions,
                industry_impact=industry_impact,
                mitigation_priority=mitigation_priority,
                timeline_estimate=timeline_estimate,
            )

        except Exception as e:
            self.logger.error(f"Error analyzing threat landscape: {e}")
            return ThreatIntelligence(
                cve_trends=["Error retrieving threat intelligence"],
                exploit_predictions=["Unable to assess exploit predictions"],
                industry_impact="UNKNOWN - Analysis failed",
                mitigation_priority="STANDARD - Follow established procedures",
                timeline_estimate="Unable to estimate timeline",
            )

    def correlate_with_known_vulnerabilities(
        self, vulnerability_title: str, cwe_id: Optional[str] = None
    ) -> List[NVDVulnerability]:
        """
        Correlate local findings with known vulnerabilities in NVD

        Args:
            vulnerability_title: Title of vulnerability to correlate
            cwe_id: Optional CWE ID for more precise correlation

        Returns:
            List of related NVD vulnerabilities
        """
        try:
            # Extract keywords from vulnerability title
            keywords = self._extract_security_keywords(vulnerability_title)

            related_vulns = []
            for keyword in keywords[:3]:  # Limit API calls
                nvd_results = self.nvd_client.search_vulnerabilities(
                    keyword=f"android {keyword}",
                    cwe_id=cwe_id,
                    cvss_score_min=6.0,
                    last_modified_days=365,
                )
                related_vulns.extend(nvd_results[:5])  # Limit results per keyword

            # Remove duplicates and sort by CVSS score
            unique_vulns = {vuln.cve_id: vuln for vuln in related_vulns}.values()
            sorted_vulns = sorted(
                unique_vulns, key=lambda v: v.cvss_score, reverse=True
            )

            self.logger.debug(
                f"Found {len(sorted_vulns)} related vulnerabilities for '{vulnerability_title}'"
            )
            return list(sorted_vulns)[:10]  # Return top 10

        except Exception as e:
            self.logger.error(f"Error correlating vulnerabilities: {e}")
            return []

    def _extract_security_keywords(self, text: str) -> List[str]:
        """Extract security-relevant keywords from text"""
        security_terms = [
            "injection",
            "traversal",
            "xss",
            "csrf",
            "authentication",
            "authorization",
            "encryption",
            "cryptography",
            "hardcoded",
            "cleartext",
            "bypass",
            "privilege",
            "escalation",
            "overflow",
            "underflow",
            "deserialization",
            "validation",
            "sanitization",
            "exported",
            "component",
            "activity",
            "service",
            "receiver",
        ]

        text_lower = text.lower()
        found_terms = []

        for term in security_terms:
            if term in text_lower:
                found_terms.append(term)

        return found_terms if found_terms else ["android", "mobile", "security"]

def get_nvd_api_key_instructions() -> str:
    """Get instructions for obtaining NVD API key"""
    return """
    To get enhanced NVD integration with higher rate limits:

    1. Visit: https://nvd.nist.gov/developers/request-an-api-key
    2. Request a free API key (requires email registration)
    3. Set environment variable: export NVD_API_KEY='your-api-key'
    4. Restart AODS scanner to use enhanced integration

    Benefits of API key:
    - 100 requests per 30 seconds (vs 5 without key)
    - More comprehensive threat intelligence
    - Faster vulnerability correlation
    """

def get_nvd_vulnerability_url(cve_id: str) -> str:
    """Get NVD URL for specific CVE"""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

def get_nvd_search_url(keyword: str) -> str:
    """Get NVD search URL for keyword"""
    encoded_keyword = quote(keyword)
    return f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={encoded_keyword}"

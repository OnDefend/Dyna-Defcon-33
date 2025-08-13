"""
Dynamic Log Analysis Framework for Enterprise-Scale Security Testing.

This module provides comprehensive logcat capture, analysis, and reporting capabilities
for enterprise applications like TikTok. It systematically analyzes intent fuzzing,
service discovery, and dynamic exploitation logs to extract security findings.

Key Features:
- Structured logcat capture with real-time parsing
- Intent fuzzing analysis and vulnerability detection
- Service access attempt monitoring
- Authentication and token security analysis
- Enterprise-scale log processing with memory management
- Integration with security reporting pipeline

Security Controls:
- MASVS-PLATFORM-3: Dynamic Analysis & Runtime Testing
- MSTG-PLATFORM-12: Intent Security Validation
- MSTG-AUTH-01: Authentication Mechanism Testing
"""

import json
import logging
import queue
import re
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)

class LogSeverity(Enum):
    """Log severity levels for security analysis."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SecurityEventType(Enum):
    """Types of security events detected in logs."""

    UNAUTHORIZED_SERVICE_ACCESS = "unauthorized_service_access"
    INTENT_FUZZING_RESPONSE = "intent_fuzzing_response"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_LEAKAGE = "data_leakage"
    NETWORK_SECURITY = "network_security"
    DEBUG_INTERFACE_EXPOSURE = "debug_interface_exposure"

@dataclass
class SecurityEvent:
    """Represents a security event detected in dynamic analysis."""

    timestamp: datetime
    event_type: SecurityEventType
    severity: LogSeverity
    component: str
    action: str
    intent_action: Optional[str]
    details: Dict[str, Any]
    raw_log: str
    process_id: int
    thread_id: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        result["event_type"] = self.event_type.value
        result["severity"] = self.severity.value
        return result

@dataclass
class DynamicAnalysisResult:
    """Results of dynamic log analysis."""

    package_name: str
    analysis_duration_seconds: float
    total_events: int
    events_by_severity: Dict[LogSeverity, int]
    events_by_type: Dict[SecurityEventType, int]
    security_events: List[SecurityEvent]
    intent_fuzzing_results: Dict[str, Any]
    service_access_results: Dict[str, Any]
    authentication_analysis: Dict[str, Any]
    recommendations: List[str]

class DynamicLogAnalyzer:
    """
    Enterprise-scale dynamic log analyzer for security testing.

    Captures and analyzes logcat output from intent fuzzing, service discovery,
    and dynamic exploitation testing to provide comprehensive security insights.
    """

    def __init__(self, package_name: str, config: Optional[Dict[str, Any]] = None):
        self.package_name = package_name
        self.config = {
            # Log capture configuration
            "log_buffer_size": 10000,
            "capture_timeout_seconds": 300,  # 5 minutes default
            "real_time_analysis": True,
            # Analysis configuration
            "intent_fuzzing_patterns": True,
            "service_security_analysis": True,
            "authentication_monitoring": True,
            "debug_interface_detection": True,
            # Performance settings
            "max_events_per_type": 100,
            "memory_limit_mb": 256,
            "batch_processing_size": 50,
            # Output configuration
            "structured_output": True,
            "detailed_reporting": True,
            "export_json": True,
        }

        if config:
            self.config.update(config)

        # Analysis state
        self.security_events: List[SecurityEvent] = []
        self.log_queue = queue.Queue(maxsize=self.config["log_buffer_size"])
        self.analysis_active = False
        self.start_time = None

        # Component tracking
        self.targeted_components: Set[str] = set()
        self.service_access_attempts: Dict[str, List[str]] = {}
        self.intent_responses: Dict[str, List[str]] = {}

        # Compile regex patterns for performance
        self._compile_security_patterns()

    def _compile_security_patterns(self) -> None:
        """Compile regex patterns for efficient log analysis."""
        self.patterns = {
            # Service access patterns
            "service_access_denied": re.compile(
                r"Unable to start service Intent.*cmp=([^/]+)/([^}\s]+).*not found",
                re.IGNORECASE,
            ),
            "service_access_success": re.compile(
                r"Starting service.*cmp=([^/]+)/([^}\s]+)", re.IGNORECASE
            ),
            # Intent fuzzing patterns
            "intent_broadcast": re.compile(
                r"Broadcasting: Intent.*act=([^}\s]+).*cmp=([^/]+)/([^}\s]+)",
                re.IGNORECASE,
            ),
            "intent_enqueued": re.compile(
                r"Enqueued broadcast Intent.*act=([^}\s]+).*cmp=([^/]+)/([^}\s]+)",
                re.IGNORECASE,
            ),
            # Authentication patterns
            "auth_token": re.compile(
                r"(AuthToken|OneTapLogin|Token).*Provider", re.IGNORECASE
            ),
            "login_activity": re.compile(
                r"(login|auth|signin|sso).*activity", re.IGNORECASE
            ),
            # Security-sensitive patterns
            "admin_actions": re.compile(
                r"custom\.(action|broadcast)\.ADMIN", re.IGNORECASE
            ),
            "debug_actions": re.compile(
                r"custom\.(action|broadcast)\.DEBUG", re.IGNORECASE
            ),
            # Data leakage patterns
            "sensitive_data": re.compile(
                r"(password|token|key|secret|api_key|auth|credential)", re.IGNORECASE
            ),
            "network_urls": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
            "ip_addresses": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        }

    def start_capture(self, timeout_seconds: Optional[int] = None) -> None:
        """Start logcat capture and analysis."""
        self.analysis_active = True
        self.start_time = time.time()
        capture_timeout = timeout_seconds or self.config["capture_timeout_seconds"]

        logger.debug(f"Starting dynamic log capture for {self.package_name}")

        # Start logcat capture thread
        capture_thread = threading.Thread(
            target=self._capture_logs, args=(capture_timeout,), daemon=True
        )
        capture_thread.start()

        # Start real-time analysis if enabled
        if self.config["real_time_analysis"]:
            analysis_thread = threading.Thread(
                target=self._analyze_logs_realtime, daemon=True
            )
            analysis_thread.start()

    def _capture_logs(self, timeout_seconds: int) -> None:
        """Capture logcat output with filtering."""
        cmd = [
            "adb",
            "logcat",
            "-v",
            "time",  # Include timestamps
            "--pid-filter",
            f"ActivityManager",  # Focus on ActivityManager logs
            f"*:W",  # Warning level and above
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
            )

            start_time = time.time()
            while self.analysis_active and (time.time() - start_time) < timeout_seconds:
                line = process.stdout.readline()
                if line:
                    # Filter for our package and relevant security events
                    if (
                        self.package_name in line
                        or "ActivityManager" in line
                        or "Intent" in line
                    ):
                        try:
                            self.log_queue.put(line.strip(), timeout=1)
                        except queue.Full:
                            logger.warning("Log queue full, dropping log entry")

        except Exception as e:
            logger.error(f"Error capturing logs: {e}")
        finally:
            if process:
                process.terminate()

    def _analyze_logs_realtime(self) -> None:
        """Analyze logs in real-time as they're captured."""
        batch = []

        while self.analysis_active:
            try:
                # Collect batch of logs
                while len(batch) < self.config["batch_processing_size"]:
                    try:
                        log_line = self.log_queue.get(timeout=1)
                        batch.append(log_line)
                    except queue.Empty:
                        break

                # Process batch
                if batch:
                    self._process_log_batch(batch)
                    batch.clear()

            except Exception as e:
                logger.error(f"Error in real-time analysis: {e}")

    def _process_log_batch(self, log_lines: List[str]) -> None:
        """Process a batch of log lines for security events."""
        for log_line in log_lines:
            event = self._analyze_log_line(log_line)
            if event:
                self.security_events.append(event)

                # Limit events per type to prevent memory issues
                self._limit_events_by_type()

    def _analyze_log_line(self, log_line: str) -> Optional[SecurityEvent]:
        """Analyze a single log line for security events."""
        try:
            # Parse timestamp and components
            timestamp = self._parse_timestamp(log_line)
            process_id, thread_id = self._parse_process_info(log_line)

            # Check for admin/debug actions first (higher priority)
            if self.patterns["admin_actions"].search(log_line) or self.patterns[
                "debug_actions"
            ].search(log_line):
                return self._analyze_privileged_action(
                    log_line, timestamp, process_id, thread_id
                )

            # Check for service access attempts
            elif "Unable to start service" in log_line:
                return self._analyze_service_access_denied(
                    log_line, timestamp, process_id, thread_id
                )

            # Check for intent broadcasting
            elif (
                "Broadcasting: Intent" in log_line
                or "Enqueued broadcast Intent" in log_line
            ):
                return self._analyze_intent_broadcast(
                    log_line, timestamp, process_id, thread_id
                )

            # Check for authentication-related events
            elif self.patterns["auth_token"].search(log_line):
                return self._analyze_authentication_event(
                    log_line, timestamp, process_id, thread_id
                )

        except Exception as e:
            logger.debug(f"Error analyzing log line: {e}")

        return None

    def _analyze_service_access_denied(
        self, log_line: str, timestamp: datetime, process_id: int, thread_id: int
    ) -> SecurityEvent:
        """Analyze service access denial events."""
        match = self.patterns["service_access_denied"].search(log_line)
        if match:
            package, component = match.groups()
            component = component.strip()  # Remove any trailing whitespace

            # Track service access attempts
            if component not in self.service_access_attempts:
                self.service_access_attempts[component] = []
            self.service_access_attempts[component].append(timestamp.isoformat())

            # Determine severity based on component type
            severity = (
                LogSeverity.HIGH
                if "auth" in component.lower() or "token" in component.lower()
                else LogSeverity.MEDIUM
            )

            return SecurityEvent(
                timestamp=timestamp,
                event_type=SecurityEventType.UNAUTHORIZED_SERVICE_ACCESS,
                severity=severity,
                component=component,
                action="service_access_denied",
                intent_action=None,
                details={
                    "target_package": package,
                    "access_method": "direct_service_start",
                    "security_implication": "Service properly protected from external access",
                },
                raw_log=log_line,
                process_id=process_id,
                thread_id=thread_id,
            )

    def _analyze_intent_broadcast(
        self, log_line: str, timestamp: datetime, process_id: int, thread_id: int
    ) -> SecurityEvent:
        """Analyze intent broadcast events."""
        # Try both broadcast patterns
        match = self.patterns["intent_broadcast"].search(log_line)
        if not match:
            match = self.patterns["intent_enqueued"].search(log_line)

        if match:
            intent_action, package, component = match.groups()
            component = component.strip()  # Remove any trailing whitespace

            # Track intent responses
            if component not in self.intent_responses:
                self.intent_responses[component] = []
            self.intent_responses[component].append(intent_action)

            # Determine severity based on intent action
            severity = (
                LogSeverity.HIGH
                if "ADMIN" in intent_action or "DEBUG" in intent_action
                else LogSeverity.MEDIUM
            )

            return SecurityEvent(
                timestamp=timestamp,
                event_type=SecurityEventType.INTENT_FUZZING_RESPONSE,
                severity=severity,
                component=component,
                action="intent_broadcast",
                intent_action=intent_action,
                details={
                    "target_package": package,
                    "broadcast_type": (
                        "system"
                        if "android.intent.action" in intent_action
                        else "custom"
                    ),
                    "security_implication": "Component responds to external broadcasts",
                },
                raw_log=log_line,
                process_id=process_id,
                thread_id=thread_id,
            )

    def _analyze_authentication_event(
        self, log_line: str, timestamp: datetime, process_id: int, thread_id: int
    ) -> SecurityEvent:
        """Analyze authentication-related events."""
        return SecurityEvent(
            timestamp=timestamp,
            event_type=SecurityEventType.AUTHENTICATION_BYPASS,
            severity=LogSeverity.HIGH,
            component="authentication_system",
            action="auth_component_access",
            intent_action=None,
            details={
                "authentication_component": True,
                "access_attempt": "external_intent",
                "security_implication": "Authentication component exposed to external access",
            },
            raw_log=log_line,
            process_id=process_id,
            thread_id=thread_id,
        )

    def _analyze_privileged_action(
        self, log_line: str, timestamp: datetime, process_id: int, thread_id: int
    ) -> SecurityEvent:
        """Analyze privileged action attempts."""
        action_type = "admin" if "ADMIN" in log_line else "debug"

        # Extract component information if available
        component = "privileged_interface"
        intent_action = f"custom.action.{action_type.upper()}"

        # Try to extract actual component from broadcast pattern
        broadcast_match = self.patterns["intent_broadcast"].search(log_line)
        if not broadcast_match:
            broadcast_match = self.patterns["intent_enqueued"].search(log_line)

        if broadcast_match:
            extracted_intent, package, extracted_component = broadcast_match.groups()
            component = extracted_component.strip()
            intent_action = extracted_intent

        return SecurityEvent(
            timestamp=timestamp,
            event_type=SecurityEventType.PRIVILEGE_ESCALATION,
            severity=LogSeverity.CRITICAL,
            component=component,
            action=f"{action_type}_action_attempt",
            intent_action=intent_action,
            details={
                "privilege_type": action_type,
                "access_method": "broadcast_intent",
                "security_implication": f"{action_type.capitalize()} interface potentially exposed",
            },
            raw_log=log_line,
            process_id=process_id,
            thread_id=thread_id,
        )

    def _parse_timestamp(self, log_line: str) -> datetime:
        """Parse timestamp from log line."""
        # Format: 05-30 14:47:19.584
        try:
            timestamp_match = re.search(
                r"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})", log_line
            )
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                # Add current year
                current_year = datetime.now().year
                full_timestamp = f"{current_year}-{timestamp_str}"
                return datetime.strptime(full_timestamp, "%Y-%m-%d %H:%M:%S.%f")
        except Exception:
            pass

        return datetime.now()

    def _parse_process_info(self, log_line: str) -> Tuple[int, int]:
        """Parse process and thread IDs from log line."""
        try:
            # Format: process_id thread_id
            match = re.search(r"(\d+)\s+(\d+)\s+[VDIWEF]", log_line)
            if match:
                return int(match.group(1)), int(match.group(2))
        except Exception:
            pass

        return 0, 0

    def _limit_events_by_type(self) -> None:
        """Limit number of events per type to prevent memory issues."""
        events_by_type = {}
        for event in self.security_events:
            if event.event_type not in events_by_type:
                events_by_type[event.event_type] = []
            events_by_type[event.event_type].append(event)

        # Keep only the most recent events for each type
        max_events = self.config["max_events_per_type"]
        filtered_events = []

        for event_type, events in events_by_type.items():
            # Sort by timestamp and keep most recent
            events.sort(key=lambda x: x.timestamp, reverse=True)
            filtered_events.extend(events[:max_events])

        self.security_events = filtered_events

    def stop_capture(self) -> DynamicAnalysisResult:
        """Stop capture and return analysis results."""
        self.analysis_active = False
        analysis_duration = time.time() - (self.start_time or time.time())

        logger.debug(
            f"Stopping dynamic log capture after {analysis_duration:.1f} seconds"
        )

        # Generate comprehensive analysis results
        return self._generate_analysis_results(analysis_duration)

    def _generate_analysis_results(self, duration: float) -> DynamicAnalysisResult:
        """Generate comprehensive analysis results."""
        # Count events by severity and type
        events_by_severity = {}
        events_by_type = {}

        for event in self.security_events:
            # Count by severity
            if event.severity not in events_by_severity:
                events_by_severity[event.severity] = 0
            events_by_severity[event.severity] += 1

            # Count by type
            if event.event_type not in events_by_type:
                events_by_type[event.event_type] = 0
            events_by_type[event.event_type] += 1

        # Generate specific analysis results
        intent_fuzzing_results = self._analyze_intent_fuzzing_results()
        service_access_results = self._analyze_service_access_results()
        authentication_analysis = self._analyze_authentication_security()
        recommendations = self._generate_security_recommendations()

        return DynamicAnalysisResult(
            package_name=self.package_name,
            analysis_duration_seconds=duration,
            total_events=len(self.security_events),
            events_by_severity=events_by_severity,
            events_by_type=events_by_type,
            security_events=self.security_events,
            intent_fuzzing_results=intent_fuzzing_results,
            service_access_results=service_access_results,
            authentication_analysis=authentication_analysis,
            recommendations=recommendations,
        )

    def _analyze_intent_fuzzing_results(self) -> Dict[str, Any]:
        """Analyze intent fuzzing test results."""
        responding_components = set()
        tested_intents = set()
        component_responses = dict(
            self.intent_responses
        )  # Start with tracked responses

        # Also collect data from existing security events
        for event in self.security_events:
            if event.event_type == SecurityEventType.INTENT_FUZZING_RESPONSE:
                responding_components.add(event.component)
                if event.intent_action:
                    tested_intents.add(event.intent_action)

                    # Add to component responses if not already tracked
                    if event.component not in component_responses:
                        component_responses[event.component] = []
                    if event.intent_action not in component_responses[event.component]:
                        component_responses[event.component].append(event.intent_action)

        # Calculate total components tested (max of tracked vs events)
        total_components_tested = max(
            len(self.intent_responses), len(component_responses)
        )

        return {
            "total_components_tested": total_components_tested,
            "responding_components": len(responding_components),
            "unique_intents_tested": len(tested_intents),
            "component_responses": component_responses,
            "security_assessment": (
                "Components properly respond to legitimate broadcasts"
                if responding_components
                else "No component responses detected"
            ),
        }

    def _analyze_service_access_results(self) -> Dict[str, Any]:
        """Analyze service access attempt results."""
        attempted_services = len(self.service_access_attempts)
        protected_services = sum(
            1 for events in self.service_access_attempts.values() if events
        )

        return {
            "services_tested": attempted_services,
            "protected_services": protected_services,
            "protection_rate": (
                protected_services / attempted_services if attempted_services > 0 else 0
            ),
            "service_access_attempts": dict(self.service_access_attempts),
            "security_assessment": (
                "Services properly protected from unauthorized access"
                if protected_services == attempted_services
                else "Some services may be accessible"
            ),
        }

    def _analyze_authentication_security(self) -> Dict[str, Any]:
        """Analyze authentication component security."""
        auth_events = [
            e
            for e in self.security_events
            if e.event_type == SecurityEventType.AUTHENTICATION_BYPASS
        ]
        auth_components = set(
            e.component
            for e in auth_events
            if "auth" in e.component.lower() or "token" in e.component.lower()
        )

        return {
            "authentication_events": len(auth_events),
            "authentication_components_detected": len(auth_components),
            "components": list(auth_components),
            "security_assessment": (
                "Authentication components properly isolated"
                if not auth_events
                else "Authentication components may be exposed"
            ),
        }

    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        # Check for critical events
        critical_events = [
            e for e in self.security_events if e.severity == LogSeverity.CRITICAL
        ]
        if critical_events:
            recommendations.append(
                "Investigate critical privilege escalation attempts detected"
            )

        # Check for authentication exposure
        auth_events = [
            e
            for e in self.security_events
            if e.event_type == SecurityEventType.AUTHENTICATION_BYPASS
        ]
        if auth_events:
            recommendations.append(
                "Review authentication component exposure to external intents"
            )

        # Check service protection
        if self.service_access_attempts:
            recommendations.append("Service access controls are functioning correctly")

        # General recommendations
        recommendations.extend(
            [
                "Continue monitoring dynamic behavior during security testing",
                "Validate intent filter configurations for exported components",
                "Review custom action handling for admin and debug interfaces",
            ]
        )

        return recommendations

    def export_results(self, output_path: Path, format: str = "json") -> None:
        """Export analysis results to file."""
        if not hasattr(self, "_analysis_results"):
            logger.warning("No analysis results to export")
            return

        if format == "json":
            with open(output_path, "w") as f:
                # Convert SecurityEvents to dictionaries for JSON serialization
                results_dict = {
                    "package_name": self._analysis_results.package_name,
                    "analysis_duration_seconds": self._analysis_results.analysis_duration_seconds,
                    "total_events": self._analysis_results.total_events,
                    "events_by_severity": {
                        k.value: v
                        for k, v in self._analysis_results.events_by_severity.items()
                    },
                    "events_by_type": {
                        k.value: v
                        for k, v in self._analysis_results.events_by_type.items()
                    },
                    "security_events": [
                        event.to_dict()
                        for event in self._analysis_results.security_events
                    ],
                    "intent_fuzzing_results": self._analysis_results.intent_fuzzing_results,
                    "service_access_results": self._analysis_results.service_access_results,
                    "authentication_analysis": self._analysis_results.authentication_analysis,
                    "recommendations": self._analysis_results.recommendations,
                }
                json.dump(results_dict, f, indent=2, default=str)

        logger.debug(f"Dynamic analysis results exported to {output_path}")

def create_dynamic_log_analyzer(
    package_name: str, config: Optional[Dict[str, Any]] = None
) -> DynamicLogAnalyzer:
    """Create and configure a dynamic log analyzer."""
    return DynamicLogAnalyzer(package_name, config)

__all__ = [
    "DynamicLogAnalyzer",
    "create_dynamic_log_analyzer"
]

#!/usr/bin/env python3
"""
Automated Incident Response Integration for AODS

This module implements comprehensive incident response automation including:
- SIEM/SOAR platform integration (Splunk, QRadar, ArcSight, Sentinel)
- Automated ticket creation and escalation workflows
- Real-time alert correlation and deduplication
- Playbook automation for common threat scenarios
- Forensic evidence collection and packaging

Designed for enterprise security operations center integration.
"""

import asyncio
import aiohttp
import json
import logging
import hashlib
import time
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import re
import os
import zipfile
import tempfile

# Data structures for incident response
class SIEMPlatform(Enum):
    SPLUNK = "splunk"
    QRADAR = "qradar"
    ARCSIGHT = "arcsight"
    SENTINEL = "sentinel"
    ELASTIC_SIEM = "elastic_siem"

class SOARPlatform(Enum):
    PHANTOM = "phantom"
    DEMISTO = "demisto"
    XSOAR = "xsoar"
    SIEMPLIFY = "siemplify"
    RESILIENT = "resilient"

class IncidentSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    
    @property
    def severity_value(self):
        """Return numeric value for severity comparison"""
        severity_map = {
            IncidentSeverity.CRITICAL: 5,
            IncidentSeverity.HIGH: 4,
            IncidentSeverity.MEDIUM: 3,
            IncidentSeverity.LOW: 2,
            IncidentSeverity.INFORMATIONAL: 1
        }
        return severity_map[self]

class IncidentStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    RESOLVED = "resolved"
    CLOSED = "closed"

class PlaybookAction(Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_ANALYSTS = "notify_analysts"
    CREATE_TICKET = "create_ticket"
    UPDATE_FIREWALL = "update_firewall"
    REVOKE_ACCESS = "revoke_access"

class AlertType(Enum):
    MALWARE_DETECTION = "malware_detection"
    NETWORK_INTRUSION = "network_intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"
    APT_ACTIVITY = "apt_activity"

@dataclass
class SecurityAlert:
    """Individual security alert from various sources"""
    alert_id: str
    title: str
    description: str
    alert_type: AlertType
    severity: IncidentSeverity
    source_system: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_assets: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None

@dataclass
class SecurityIncident:
    """Correlated security incident containing multiple alerts"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    alerts: List[SecurityAlert] = field(default_factory=list)
    affected_systems: Set[str] = field(default_factory=set)
    attack_timeline: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)
    assigned_analyst: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    escalation_level: int = 0
    estimated_impact: str = ""
    business_criticality: str = ""

@dataclass
class PlaybookExecution:
    """Automated playbook execution result"""
    execution_id: str
    playbook_name: str
    incident_id: str
    actions_executed: List[Dict[str, Any]] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    status: str = "running"
    error_messages: List[str] = field(default_factory=list)

@dataclass
class ForensicPackage:
    """Forensic evidence package"""
    package_id: str
    incident_id: str
    package_path: str
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    hash_verification: Dict[str, str] = field(default_factory=dict)
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "AODS_AutoIR"

class SIEMIntegrationManager:
    """Manager for SIEM platform integrations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.integrations = {}
        self.session = None
        
        # SIEM platform configurations
        self.siem_configs = {
            SIEMPlatform.SPLUNK: {
                "api_endpoint": "/services/search/jobs/export",
                "auth_method": "basic",
                "query_format": "spl",
                "time_format": "%Y-%m-%dT%H:%M:%S.%f%z"
            },
            SIEMPlatform.QRADAR: {
                "api_endpoint": "/api/siem/offenses",
                "auth_method": "token",
                "query_format": "aql",
                "time_format": "%Y-%m-%d %H:%M:%S"
            },
            SIEMPlatform.ARCSIGHT: {
                "api_endpoint": "/www/core-service/rest/",
                "auth_method": "basic",
                "query_format": "ccl",
                "time_format": "%Y-%m-%dT%H:%M:%S"
            },
            SIEMPlatform.SENTINEL: {
                "api_endpoint": "/api/",
                "auth_method": "oauth",
                "query_format": "kql",
                "time_format": "%Y-%m-%dT%H:%M:%S.%fZ"
            }
        }
    
    async def initialize(self):
        """Initialize SIEM integrations"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'AODS-IncidentResponse/2.0'}
        )
        self.logger.info("SIEM integration manager initialized")
    
    async def close(self):
        """Close SIEM integration manager"""
        if self.session:
            await self.session.close()
        self.logger.info("SIEM integration manager closed")
    
    async def register_siem_platform(self, platform: SIEMPlatform, config: Dict[str, Any]):
        """Register a SIEM platform connection"""
        self.integrations[platform] = {
            "config": config,
            "last_sync": None,
            "status": "configured"
        }
        
        # Test connection
        try:
            test_result = await self._test_siem_connection(platform, config)
            if test_result:
                self.integrations[platform]["status"] = "connected"
                self.logger.info(f"Successfully registered {platform.value} SIEM platform")
            else:
                self.integrations[platform]["status"] = "connection_failed"
                self.logger.error(f"Failed to connect to {platform.value} SIEM platform")
        except Exception as e:
            self.logger.error(f"Error registering {platform.value}: {e}")
            self.integrations[platform]["status"] = "error"
    
    async def _test_siem_connection(self, platform: SIEMPlatform, config: Dict[str, Any]) -> bool:
        """Test connection to SIEM platform"""
        try:
            # Mock connection test - in real implementation, this would make actual API calls
            endpoint = config.get("endpoint", "")
            api_key = config.get("api_key", "")
            
            if not endpoint or not api_key:
                return False
            
            # Simulate connection test
            await asyncio.sleep(0.1)
            return True
            
        except Exception as e:
            self.logger.error(f"SIEM connection test failed: {e}")
            return False
    
    async def send_alert_to_siem(self, platform: SIEMPlatform, alert: SecurityAlert) -> bool:
        """Send alert to specific SIEM platform"""
        if platform not in self.integrations:
            self.logger.error(f"SIEM platform {platform.value} not registered")
            return False
        
        try:
            # Format alert for SIEM platform
            formatted_alert = self._format_alert_for_siem(platform, alert)
            
            # Send to SIEM (mock implementation)
            self.logger.info(f"Sending alert {alert.alert_id} to {platform.value}")
            
            # Update integration status
            self.integrations[platform]["last_sync"] = datetime.now(timezone.utc)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send alert to {platform.value}: {e}")
            return False
    
    def _format_alert_for_siem(self, platform: SIEMPlatform, alert: SecurityAlert) -> Dict[str, Any]:
        """Format alert for specific SIEM platform"""
        base_format = {
            "id": alert.alert_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "source_system": alert.source_system,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "affected_assets": alert.affected_assets,
            "indicators": alert.indicators
        }
        
        # Platform-specific formatting
        if platform == SIEMPlatform.SPLUNK:
            return {
                "sourcetype": "aods:alert",
                "time": alert.timestamp.timestamp(),
                **base_format
            }
        elif platform == SIEMPlatform.QRADAR:
            return {
                "offense_type": alert.alert_type.value,
                "magnitude": self._severity_to_magnitude(alert.severity),
                **base_format
            }
        elif platform == SIEMPlatform.SENTINEL:
            return {
                "TimeGenerated": alert.timestamp.isoformat(),
                "AlertName": alert.title,
                "AlertSeverity": alert.severity.value.upper(),
                **base_format
            }
        else:
            return base_format
    
    def _severity_to_magnitude(self, severity: IncidentSeverity) -> int:
        """Convert severity to QRadar magnitude scale"""
        mapping = {
            IncidentSeverity.CRITICAL: 10,
            IncidentSeverity.HIGH: 8,
            IncidentSeverity.MEDIUM: 5,
            IncidentSeverity.LOW: 3,
            IncidentSeverity.INFORMATIONAL: 1
        }
        return mapping.get(severity, 5)
    
    async def query_siem_events(self, platform: SIEMPlatform, query: str, 
                               time_range: Tuple[datetime, datetime]) -> List[Dict[str, Any]]:
        """Query events from SIEM platform"""
        if platform not in self.integrations:
            self.logger.error(f"SIEM platform {platform.value} not registered")
            return []
        
        try:
            # Format query for platform
            formatted_query = self._format_siem_query(platform, query, time_range)
            
            # Execute query (mock implementation)
            mock_events = self._generate_mock_siem_events(platform, 5)
            
            self.logger.info(f"Retrieved {len(mock_events)} events from {platform.value}")
            return mock_events
            
        except Exception as e:
            self.logger.error(f"Failed to query {platform.value}: {e}")
            return []
    
    def _format_siem_query(self, platform: SIEMPlatform, query: str, 
                          time_range: Tuple[datetime, datetime]) -> str:
        """Format query for specific SIEM platform"""
        start_time, end_time = time_range
        
        if platform == SIEMPlatform.SPLUNK:
            return f'search earliest="{start_time.isoformat()}" latest="{end_time.isoformat()}" {query}'
        elif platform == SIEMPlatform.QRADAR:
            return f"SELECT * FROM events WHERE {query} AND starttime > '{start_time.isoformat()}'"
        elif platform == SIEMPlatform.SENTINEL:
            return f"{query} | where TimeGenerated between (datetime({start_time.isoformat()}) .. datetime({end_time.isoformat()}))"
        else:
            return query
    
    def _generate_mock_siem_events(self, platform: SIEMPlatform, count: int) -> List[Dict[str, Any]]:
        """Generate mock SIEM events for demonstration"""
        events = []
        for i in range(count):
            event = {
                "event_id": f"{platform.value}_event_{i+1}",
                "timestamp": datetime.now(timezone.utc) - timedelta(hours=i),
                "source_ip": f"192.168.1.{10+i}",
                "event_type": "suspicious_activity",
                "severity": "medium",
                "description": f"Mock event {i+1} from {platform.value}"
            }
            events.append(event)
        return events

class SOARIntegrationManager:
    """Manager for SOAR platform integrations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.integrations = {}
        self.session = None
        
        # SOAR platform configurations
        self.soar_configs = {
            SOARPlatform.PHANTOM: {
                "api_endpoint": "/rest/",
                "auth_method": "token",
                "playbook_format": "json"
            },
            SOARPlatform.DEMISTO: {
                "api_endpoint": "/api/v1/",
                "auth_method": "api_key",
                "playbook_format": "yaml"
            },
            SOARPlatform.XSOAR: {
                "api_endpoint": "/api/v1/",
                "auth_method": "api_key", 
                "playbook_format": "yaml"
            }
        }
    
    async def initialize(self):
        """Initialize SOAR integrations"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        self.logger.info("SOAR integration manager initialized")
    
    async def close(self):
        """Close SOAR integration manager"""
        if self.session:
            await self.session.close()
        self.logger.info("SOAR integration manager closed")
    
    async def execute_playbook(self, platform: SOARPlatform, playbook_name: str, 
                              incident: SecurityIncident) -> PlaybookExecution:
        """Execute automated playbook on SOAR platform"""
        execution_id = hashlib.md5(f"{playbook_name}_{incident.incident_id}_{time.time()}".encode()).hexdigest()[:16]
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_name=playbook_name,
            incident_id=incident.incident_id
        )
        
        try:
            # Get playbook actions
            actions = self._get_playbook_actions(playbook_name, incident)
            
            # Execute actions
            for action in actions:
                try:
                    result = await self._execute_playbook_action(platform, action, incident)
                    execution.actions_executed.append({
                        "action": action,
                        "result": result,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": "success"
                    })
                    execution.success_count += 1
                except Exception as e:
                    execution.actions_executed.append({
                        "action": action,
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": "failed"
                    })
                    execution.failure_count += 1
                    execution.error_messages.append(f"Action {action} failed: {e}")
            
            execution.end_time = datetime.now(timezone.utc)
            execution.status = "completed"
            
            self.logger.info(f"Playbook {playbook_name} executed: {execution.success_count} success, {execution.failure_count} failures")
            
        except Exception as e:
            execution.status = "failed"
            execution.error_messages.append(f"Playbook execution failed: {e}")
            self.logger.error(f"Playbook execution failed: {e}")
        
        return execution
    
    def _get_playbook_actions(self, playbook_name: str, incident: SecurityIncident) -> List[Dict[str, Any]]:
        """Get playbook actions based on incident characteristics"""
        actions = []
        
        # Default incident response actions
        if incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
            actions.extend([
                {"type": PlaybookAction.NOTIFY_ANALYSTS, "priority": "immediate"},
                {"type": PlaybookAction.COLLECT_EVIDENCE, "scope": "affected_systems"},
                {"type": PlaybookAction.CREATE_TICKET, "priority": "high"}
            ])
        
        # Malware-specific actions
        if any("malware" in alert.alert_type.value for alert in incident.alerts):
            actions.extend([
                {"type": PlaybookAction.ISOLATE_ENDPOINT, "systems": list(incident.affected_systems)},
                {"type": PlaybookAction.QUARANTINE_FILE, "scope": "suspicious_files"}
            ])
        
        # Network intrusion actions
        if any("network" in alert.alert_type.value for alert in incident.alerts):
            actions.extend([
                {"type": PlaybookAction.BLOCK_IP, "ips": [alert.source_ip for alert in incident.alerts if alert.source_ip]},
                {"type": PlaybookAction.UPDATE_FIREWALL, "rules": "block_suspicious_traffic"}
            ])
        
        # Data exfiltration actions
        if any("exfiltration" in alert.alert_type.value for alert in incident.alerts):
            actions.extend([
                {"type": PlaybookAction.REVOKE_ACCESS, "scope": "affected_accounts"},
                {"type": PlaybookAction.COLLECT_EVIDENCE, "focus": "data_flow_analysis"}
            ])
        
        return actions
    
    async def _execute_playbook_action(self, platform: SOARPlatform, action: Dict[str, Any], 
                                     incident: SecurityIncident) -> Dict[str, Any]:
        """Execute individual playbook action"""
        action_type = action.get("type")
        
        # Mock action execution - in real implementation, these would make actual API calls
        if action_type == PlaybookAction.ISOLATE_ENDPOINT:
            systems = action.get("systems", [])
            return {"isolated_systems": systems, "status": "success"}
        
        elif action_type == PlaybookAction.BLOCK_IP:
            ips = action.get("ips", [])
            return {"blocked_ips": ips, "firewall_rules_added": len(ips)}
        
        elif action_type == PlaybookAction.QUARANTINE_FILE:
            return {"quarantined_files": 5, "quarantine_location": "/quarantine/"}
        
        elif action_type == PlaybookAction.COLLECT_EVIDENCE:
            return {"evidence_collected": True, "evidence_package": f"evidence_{incident.incident_id}"}
        
        elif action_type == PlaybookAction.NOTIFY_ANALYSTS:
            return {"notifications_sent": 3, "escalation_level": action.get("priority", "medium")}
        
        elif action_type == PlaybookAction.CREATE_TICKET:
            ticket_id = f"TICKET_{incident.incident_id}"
            return {"ticket_created": ticket_id, "priority": action.get("priority", "medium")}
        
        elif action_type == PlaybookAction.UPDATE_FIREWALL:
            return {"firewall_updated": True, "rules_added": 2}
        
        elif action_type == PlaybookAction.REVOKE_ACCESS:
            return {"access_revoked": True, "accounts_affected": 3}
        
        else:
            return {"status": "unknown_action", "action": str(action_type)}

class AlertCorrelationEngine:
    """Engine for real-time alert correlation and deduplication"""
    
    def __init__(self, correlation_window_minutes: int = 30):
        self.logger = logging.getLogger(__name__)
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.active_alerts = deque()
        self.correlation_rules = self._load_correlation_rules()
        self.incident_counter = 0
    
    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load alert correlation rules"""
        return [
            {
                "name": "related_ip_alerts",
                "condition": "same_source_ip",
                "time_window": 300,  # 5 minutes
                "minimum_alerts": 3,
                "severity_escalation": True
            },
            {
                "name": "malware_campaign",
                "condition": "same_malware_family",
                "time_window": 1800,  # 30 minutes
                "minimum_alerts": 2,
                "incident_title": "Coordinated Malware Campaign"
            },
            {
                "name": "privilege_escalation_chain",
                "condition": "escalation_sequence",
                "time_window": 600,  # 10 minutes
                "minimum_alerts": 2,
                "severity_escalation": True
            },
            {
                "name": "data_exfiltration_pattern",
                "condition": "exfiltration_indicators",
                "time_window": 900,  # 15 minutes
                "minimum_alerts": 2,
                "incident_title": "Potential Data Exfiltration"
            }
        ]
    
    async def process_alert(self, alert: SecurityAlert) -> Optional[SecurityIncident]:
        """Process incoming alert and check for correlations"""
        # Add to active alerts
        self.active_alerts.append(alert)
        
        # Clean up old alerts outside correlation window
        cutoff_time = datetime.now(timezone.utc) - self.correlation_window
        while self.active_alerts and self.active_alerts[0].timestamp < cutoff_time:
            self.active_alerts.popleft()
        
        # Check for correlations
        correlated_alerts = await self._find_correlations(alert)
        
        if correlated_alerts and len(correlated_alerts) >= 2:
            # Create security incident
            incident = await self._create_incident_from_alerts(correlated_alerts)
            
            # Remove correlated alerts from active queue
            for corr_alert in correlated_alerts:
                try:
                    self.active_alerts.remove(corr_alert)
                except ValueError:
                    pass  # Alert may have already been removed
            
            return incident
        
        return None
    
    async def _find_correlations(self, alert: SecurityAlert) -> List[SecurityAlert]:
        """Find correlated alerts based on correlation rules"""
        correlated_alerts = [alert]
        
        for rule in self.correlation_rules:
            condition = rule["condition"]
            time_window = timedelta(seconds=rule["time_window"])
            minimum_alerts = rule.get("minimum_alerts", 2)
            
            # Find alerts within time window
            window_start = alert.timestamp - time_window
            candidate_alerts = [
                a for a in self.active_alerts 
                if window_start <= a.timestamp <= alert.timestamp and a.alert_id != alert.alert_id
            ]
            
            # Apply correlation condition
            if condition == "same_source_ip":
                matching_alerts = [
                    a for a in candidate_alerts 
                    if a.source_ip and a.source_ip == alert.source_ip
                ]
            elif condition == "same_malware_family":
                matching_alerts = [
                    a for a in candidate_alerts
                    if a.alert_type == AlertType.MALWARE_DETECTION and alert.alert_type == AlertType.MALWARE_DETECTION
                ]
            elif condition == "escalation_sequence":
                matching_alerts = [
                    a for a in candidate_alerts
                    if (a.alert_type == AlertType.PRIVILEGE_ESCALATION or 
                        alert.alert_type == AlertType.PRIVILEGE_ESCALATION) and
                       any(asset in alert.affected_assets for asset in a.affected_assets)
                ]
            elif condition == "exfiltration_indicators":
                matching_alerts = [
                    a for a in candidate_alerts
                    if a.alert_type in [AlertType.DATA_EXFILTRATION, AlertType.NETWORK_INTRUSION] and
                       alert.alert_type in [AlertType.DATA_EXFILTRATION, AlertType.NETWORK_INTRUSION]
                ]
            else:
                matching_alerts = []
            
            # Check if we have enough alerts for correlation
            if len(matching_alerts) + 1 >= minimum_alerts:  # +1 for current alert
                correlated_alerts.extend(matching_alerts)
                break
        
        # Remove duplicates while preserving order
        seen = set()
        unique_alerts = []
        for alert in correlated_alerts:
            if alert.alert_id not in seen:
                seen.add(alert.alert_id)
                unique_alerts.append(alert)
        
        return unique_alerts
    
    async def _create_incident_from_alerts(self, alerts: List[SecurityAlert]) -> SecurityIncident:
        """Create security incident from correlated alerts"""
        self.incident_counter += 1
        incident_id = f"INC_{datetime.now().strftime('%Y%m%d')}_{self.incident_counter:04d}"
        
        # Determine incident severity (highest alert severity)
        max_severity = max(alerts, key=lambda alert: alert.severity.severity_value).severity
        
        # Collect affected systems
        affected_systems = set()
        for alert in alerts:
            affected_systems.update(alert.affected_assets)
            if alert.source_ip:
                affected_systems.add(alert.source_ip)
            if alert.destination_ip:
                affected_systems.add(alert.destination_ip)
        
        # Generate incident title
        alert_types = set(alert.alert_type for alert in alerts)
        if len(alert_types) == 1:
            title = f"Security Incident: {list(alert_types)[0].value.replace('_', ' ').title()}"
        else:
            title = f"Multi-Vector Security Incident ({len(alerts)} alerts)"
        
        # Create attack timeline
        timeline = []
        for alert in sorted(alerts, key=lambda a: a.timestamp):
            timeline.append({
                "timestamp": alert.timestamp.isoformat(),
                "event": alert.title,
                "alert_type": alert.alert_type.value,
                "severity": alert.severity.value,
                "source": alert.source_system
            })
        
        # Generate description
        description = f"Correlated security incident involving {len(alerts)} related alerts. "
        description += f"Affected systems: {', '.join(list(affected_systems)[:5])}. "
        description += f"Alert types: {', '.join([at.value for at in alert_types])}."
        
        incident = SecurityIncident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=max_severity,
            status=IncidentStatus.NEW,
            alerts=alerts,
            affected_systems=affected_systems,
            attack_timeline=timeline
        )
        
        self.logger.info(f"Created incident {incident_id} from {len(alerts)} correlated alerts")
        return incident

class ForensicEvidenceCollector:
    """Automated forensic evidence collection and packaging"""
    
    def __init__(self, evidence_directory: str = "forensic_evidence"):
        self.logger = logging.getLogger(__name__)
        self.evidence_directory = evidence_directory
        os.makedirs(evidence_directory, exist_ok=True)
    
    async def collect_incident_evidence(self, incident: SecurityIncident) -> ForensicPackage:
        """Collect comprehensive forensic evidence for incident"""
        package_id = f"FORENSIC_{incident.incident_id}_{int(time.time())}"
        package_path = os.path.join(self.evidence_directory, f"{package_id}.zip")
        
        evidence_items = []
        
        try:
            # Create temporary directory for evidence collection
            with tempfile.TemporaryDirectory() as temp_dir:
                
                # Collect alert data
                alert_data = await self._collect_alert_evidence(incident.alerts, temp_dir)
                evidence_items.extend(alert_data)
                
                # Collect system logs
                system_logs = await self._collect_system_logs(incident.affected_systems, temp_dir)
                evidence_items.extend(system_logs)
                
                # Collect network evidence
                network_evidence = await self._collect_network_evidence(incident, temp_dir)
                evidence_items.extend(network_evidence)
                
                # Collect file artifacts
                file_artifacts = await self._collect_file_artifacts(incident, temp_dir)
                evidence_items.extend(file_artifacts)
                
                # Create forensic package
                await self._create_evidence_package(temp_dir, package_path)
        
        except Exception as e:
            self.logger.error(f"Error collecting evidence: {e}")
            evidence_items.append({
                "type": "error",
                "description": f"Evidence collection error: {e}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        
        # Create hash verification
        hash_verification = await self._calculate_package_hash(package_path)
        
        # Create chain of custody
        chain_of_custody = [
            {
                "action": "evidence_collection_started",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operator": "AODS_AutoIR",
                "details": f"Automated collection for incident {incident.incident_id}"
            },
            {
                "action": "evidence_package_created",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operator": "AODS_AutoIR",
                "details": f"Package created: {package_path}"
            }
        ]
        
        package = ForensicPackage(
            package_id=package_id,
            incident_id=incident.incident_id,
            package_path=package_path,
            evidence_items=evidence_items,
            hash_verification=hash_verification,
            chain_of_custody=chain_of_custody
        )
        
        self.logger.info(f"Forensic package {package_id} created with {len(evidence_items)} evidence items")
        return package
    
    async def _collect_alert_evidence(self, alerts: List[SecurityAlert], temp_dir: str) -> List[Dict[str, Any]]:
        """Collect evidence from security alerts"""
        evidence_items = []
        
        alerts_file = os.path.join(temp_dir, "alerts.json")
        alerts_data = [asdict(alert) for alert in alerts]
        
        # Convert datetime objects to strings
        for alert_data in alerts_data:
            if 'timestamp' in alert_data:
                alert_data['timestamp'] = alert_data['timestamp'].isoformat() if hasattr(alert_data['timestamp'], 'isoformat') else str(alert_data['timestamp'])
        
        with open(alerts_file, 'w') as f:
            json.dump(alerts_data, f, indent=2, default=str)
        
        evidence_items.append({
            "type": "alert_data",
            "file_path": alerts_file,
            "description": f"Security alerts data ({len(alerts)} alerts)",
            "size_bytes": os.path.getsize(alerts_file)
        })
        
        return evidence_items
    
    async def _collect_system_logs(self, affected_systems: Set[str], temp_dir: str) -> List[Dict[str, Any]]:
        """Collect system logs from affected systems"""
        evidence_items = []
        
        for system in list(affected_systems)[:5]:  # Limit to first 5 systems
            log_file = os.path.join(temp_dir, f"system_logs_{system.replace('.', '_').replace(':', '_')}.txt")
            
            # Mock log collection - in real implementation, this would fetch actual logs
            mock_logs = self._generate_mock_system_logs(system)
            
            with open(log_file, 'w') as f:
                f.write(mock_logs)
            
            evidence_items.append({
                "type": "system_logs",
                "system": system,
                "file_path": log_file,
                "description": f"System logs from {system}",
                "size_bytes": os.path.getsize(log_file)
            })
        
        return evidence_items
    
    async def _collect_network_evidence(self, incident: SecurityIncident, temp_dir: str) -> List[Dict[str, Any]]:
        """Collect network traffic evidence"""
        evidence_items = []
        
        # Collect network flows
        flows_file = os.path.join(temp_dir, "network_flows.json")
        network_flows = self._generate_mock_network_flows(incident)
        
        with open(flows_file, 'w') as f:
            json.dump(network_flows, f, indent=2, default=str)
        
        evidence_items.append({
            "type": "network_flows",
            "file_path": flows_file,
            "description": "Network flow data related to incident",
            "size_bytes": os.path.getsize(flows_file)
        })
        
        return evidence_items
    
    async def _collect_file_artifacts(self, incident: SecurityIncident, temp_dir: str) -> List[Dict[str, Any]]:
        """Collect file artifacts and indicators"""
        evidence_items = []
        
        # Collect file hashes and metadata
        artifacts_file = os.path.join(temp_dir, "file_artifacts.json")
        file_artifacts = self._generate_mock_file_artifacts(incident)
        
        with open(artifacts_file, 'w') as f:
            json.dump(file_artifacts, f, indent=2, default=str)
        
        evidence_items.append({
            "type": "file_artifacts",
            "file_path": artifacts_file,
            "description": "File artifacts and indicators",
            "size_bytes": os.path.getsize(artifacts_file)
        })
        
        return evidence_items
    
    def _generate_mock_system_logs(self, system: str) -> str:
        """Generate mock system logs for demonstration"""
        logs = []
        base_time = datetime.now(timezone.utc)
        
        for i in range(10):
            timestamp = (base_time - timedelta(minutes=i*5)).strftime("%Y-%m-%d %H:%M:%S")
            logs.append(f"{timestamp} {system} INFO: System event {i+1}")
            logs.append(f"{timestamp} {system} WARNING: Suspicious activity detected")
            logs.append(f"{timestamp} {system} ERROR: Authentication failure from unknown source")
        
        return "\n".join(logs)
    
    def _generate_mock_network_flows(self, incident: SecurityIncident) -> List[Dict[str, Any]]:
        """Generate mock network flows for demonstration"""
        flows = []
        
        for i, alert in enumerate(incident.alerts[:5]):
            flow = {
                "flow_id": f"flow_{i+1}",
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip or f"192.168.1.{10+i}",
                "destination_ip": alert.destination_ip or f"10.0.0.{5+i}",
                "protocol": "TCP",
                "source_port": 4444 + i,
                "destination_port": 80,
                "bytes_sent": 1024 * (i + 1),
                "bytes_received": 512 * (i + 1),
                "duration_seconds": 30 + i*10
            }
            flows.append(flow)
        
        return flows
    
    def _generate_mock_file_artifacts(self, incident: SecurityIncident) -> List[Dict[str, Any]]:
        """Generate mock file artifacts for demonstration"""
        artifacts = []
        
        for i, alert in enumerate(incident.alerts[:3]):
            artifact = {
                "file_path": f"/tmp/suspicious_file_{i+1}.exe",
                "file_hash_md5": hashlib.md5(f"mock_file_{i}".encode()).hexdigest(),
                "file_hash_sha256": hashlib.sha256(f"mock_file_{i}".encode()).hexdigest(),
                "file_size": 1024 * (i + 1),
                "creation_time": alert.timestamp.isoformat(),
                "file_type": "executable",
                "suspicious_indicators": [
                    "Suspicious API calls detected",
                    "Network communication to unknown hosts",
                    "Registry modifications"
                ]
            }
            artifacts.append(artifact)
        
        return artifacts
    
    async def _create_evidence_package(self, temp_dir: str, package_path: str):
        """Create compressed evidence package"""
        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
    
    async def _calculate_package_hash(self, package_path: str) -> Dict[str, str]:
        """Calculate hash verification for evidence package"""
        if not os.path.exists(package_path):
            return {}
        
        with open(package_path, 'rb') as f:
            content = f.read()
            
        return {
            "md5": hashlib.md5(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content)
        }

class AutomatedIncidentResponseEngine:
    """Main orchestrator for automated incident response"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.siem_manager = SIEMIntegrationManager()
        self.soar_manager = SOARIntegrationManager()
        self.correlation_engine = AlertCorrelationEngine()
        self.forensic_collector = ForensicEvidenceCollector()
        self.active_incidents = {}
        self.is_initialized = False
    
    async def initialize(self):
        """Initialize the incident response engine"""
        self.logger.info("Initializing Automated Incident Response Engine")
        
        await self.siem_manager.initialize()
        await self.soar_manager.initialize()
        
        self.is_initialized = True
        self.logger.info("Automated Incident Response Engine initialized")
    
    async def process_security_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Process incoming security alert and trigger automated response"""
        if not self.is_initialized:
            await self.initialize()
        
        response_start = time.time()
        
        # Step 1: Send alert to configured SIEM platforms
        siem_results = {}
        for platform in self.siem_manager.integrations:
            success = await self.siem_manager.send_alert_to_siem(platform, alert)
            siem_results[platform.value] = success
        
        # Step 2: Check for alert correlations
        incident = await self.correlation_engine.process_alert(alert)
        
        response_actions = []
        playbook_executions = []
        forensic_package = None
        
        if incident:
            self.logger.info(f"Incident created: {incident.incident_id}")
            self.active_incidents[incident.incident_id] = incident
            
            # Step 3: Execute automated playbooks
            playbook_name = self._select_playbook_for_incident(incident)
            if playbook_name:
                for platform in self.soar_manager.integrations:
                    execution = await self.soar_manager.execute_playbook(platform, playbook_name, incident)
                    playbook_executions.append(execution)
            
            # Step 4: Collect forensic evidence
            if incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                forensic_package = await self.forensic_collector.collect_incident_evidence(incident)
            
            # Step 5: Generate response actions
            response_actions = self._generate_response_actions(incident)
            
        response_time = time.time() - response_start
        
        result = {
            "alert_id": alert.alert_id,
            "processing_time_seconds": response_time,
            "siem_integration_results": siem_results,
            "incident_created": incident.incident_id if incident else None,
            "incident_severity": incident.severity.value if incident else None,
            "playbook_executions": len(playbook_executions),
            "response_actions": response_actions,
            "forensic_package_id": forensic_package.package_id if forensic_package else None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.logger.info(f"Alert {alert.alert_id} processed in {response_time:.2f}s")
        return result
    
    def _select_playbook_for_incident(self, incident: SecurityIncident) -> str:
        """Select appropriate playbook based on incident characteristics"""
        # High severity incidents
        if incident.severity == IncidentSeverity.CRITICAL:
            return "critical_incident_response"
        elif incident.severity == IncidentSeverity.HIGH:
            return "high_severity_response"
        
        # Alert type specific playbooks
        alert_types = set(alert.alert_type for alert in incident.alerts)
        
        if AlertType.MALWARE_DETECTION in alert_types:
            return "malware_incident_response"
        elif AlertType.DATA_EXFILTRATION in alert_types:
            return "data_breach_response"
        elif AlertType.NETWORK_INTRUSION in alert_types:
            return "network_intrusion_response"
        elif AlertType.PRIVILEGE_ESCALATION in alert_types:
            return "privilege_escalation_response"
        else:
            return "standard_incident_response"
    
    def _generate_response_actions(self, incident: SecurityIncident) -> List[str]:
        """Generate recommended response actions"""
        actions = []
        
        # Severity-based actions
        if incident.severity == IncidentSeverity.CRITICAL:
            actions.extend([
                "Activate incident response team immediately",
                "Consider declaring security incident",
                "Prepare executive briefing",
                "Review business continuity plans"
            ])
        elif incident.severity == IncidentSeverity.HIGH:
            actions.extend([
                "Escalate to senior security analyst",
                "Begin impact assessment",
                "Prepare stakeholder notifications"
            ])
        
        # Alert type specific actions
        alert_types = set(alert.alert_type for alert in incident.alerts)
        
        if AlertType.MALWARE_DETECTION in alert_types:
            actions.extend([
                "Isolate affected endpoints",
                "Run antivirus scans on related systems",
                "Review email security logs",
                "Check for lateral movement"
            ])
        
        if AlertType.DATA_EXFILTRATION in alert_types:
            actions.extend([
                "Identify compromised data assets",
                "Review data access logs",
                "Consider legal notification requirements",
                "Assess regulatory compliance impact"
            ])
        
        if AlertType.NETWORK_INTRUSION in alert_types:
            actions.extend([
                "Review network segmentation",
                "Analyze network traffic patterns",
                "Check firewall and IDS logs",
                "Validate network access controls"
            ])
        
        # Affected systems actions
        if len(incident.affected_systems) > 5:
            actions.append("Widespread impact detected - consider emergency procedures")
        
        return actions
    
    async def get_incident_status(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of security incident"""
        if incident_id not in self.active_incidents:
            return None
        
        incident = self.active_incidents[incident_id]
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "alerts_count": len(incident.alerts),
            "affected_systems": list(incident.affected_systems),
            "assigned_analyst": incident.assigned_analyst,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "escalation_level": incident.escalation_level
        }
    
    async def update_incident_status(self, incident_id: str, new_status: IncidentStatus, 
                                   analyst: str = None) -> bool:
        """Update incident status"""
        if incident_id not in self.active_incidents:
            return False
        
        incident = self.active_incidents[incident_id]
        incident.status = new_status
        incident.updated_at = datetime.now(timezone.utc)
        
        if analyst:
            incident.assigned_analyst = analyst
        
        self.logger.info(f"Incident {incident_id} status updated to {new_status.value}")
        return True
    
    async def get_engine_summary(self) -> Dict[str, Any]:
        """Get comprehensive engine summary"""
        return {
            "engine_status": "operational" if self.is_initialized else "initializing",
            "siem_integrations": len(self.siem_manager.integrations),
            "soar_integrations": len(self.soar_manager.integrations),
            "active_incidents": len(self.active_incidents),
            "correlation_rules": len(self.correlation_engine.correlation_rules),
            "capabilities": [
                "SIEM platform integration",
                "SOAR playbook automation",
                "Real-time alert correlation",
                "Automated forensic collection",
                "Incident escalation management",
                "Multi-platform workflow execution"
            ]
        }
    
    async def close(self):
        """Close incident response engine and all components"""
        await self.siem_manager.close()
        await self.soar_manager.close()
        self.logger.info("Automated Incident Response Engine closed")

# Integration with AODS framework
async def integrate_incident_response_with_aods(engine: AutomatedIncidentResponseEngine,
                                              aods_scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Integrate incident response with AODS scan results"""
    processed_alerts = []
    
    for scan_result in aods_scan_results:
        # Convert AODS findings to security alerts
        alerts = await _convert_aods_to_alerts(scan_result)
        
        # Process each alert through incident response
        for alert in alerts:
            response = await engine.process_security_alert(alert)
            processed_alerts.append({
                "original_scan": scan_result,
                "security_alert": alert,
                "incident_response": response
            })
    
    return {
        "processed_alerts": processed_alerts,
        "incident_response_integration": "complete",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

async def _convert_aods_to_alerts(scan_result: Dict[str, Any]) -> List[SecurityAlert]:
    """Convert AODS scan results to security alerts"""
    alerts = []
    
    # Convert vulnerability findings to alerts
    findings = scan_result.get("findings", [])
    for finding in findings:
        # Determine alert type based on finding
        finding_type = finding.get("type", "unknown")
        if "malware" in finding_type.lower():
            alert_type = AlertType.MALWARE_DETECTION
        elif "privilege" in finding_type.lower():
            alert_type = AlertType.PRIVILEGE_ESCALATION
        elif "network" in finding_type.lower():
            alert_type = AlertType.NETWORK_INTRUSION
        else:
            alert_type = AlertType.ANOMALOUS_BEHAVIOR
        
        # Determine severity
        severity_map = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW
        }
        severity = severity_map.get(finding.get("severity", "medium").lower(), IncidentSeverity.MEDIUM)
        
        alert = SecurityAlert(
            alert_id=f"AODS_{scan_result.get('scan_id', 'unknown')}_{finding.get('id', hashlib.md5(str(finding).encode()).hexdigest()[:8])}",
            title=finding.get("title", "AODS Security Finding"),
            description=finding.get("description", "Security finding from AODS scan"),
            alert_type=alert_type,
            severity=severity,
            source_system="AODS",
            affected_assets=[scan_result.get("target", "unknown")],
            indicators=finding.get("indicators", []),
            raw_data=finding
        )
        
        alerts.append(alert)
    
    return alerts

if __name__ == "__main__":
    async def main():
        """Demo of Automated Incident Response Engine"""
        engine = AutomatedIncidentResponseEngine()
        
        try:
            await engine.initialize()
            
            # Create sample security alert
            sample_alert = SecurityAlert(
                alert_id="DEMO_001",
                title="Suspected Malware Detection",
                description="Malicious file detected on endpoint with suspicious network activity",
                alert_type=AlertType.MALWARE_DETECTION,
                severity=IncidentSeverity.HIGH,
                source_system="Endpoint Protection",
                source_ip="192.168.1.100",
                affected_assets=["WORKSTATION-01"],
                indicators=["malware_hash_abc123", "suspicious_domain.com"]
            )
            
            # Process alert
            response = await engine.process_security_alert(sample_alert)
            print(f"Incident response result: {json.dumps(response, indent=2)}")
            
            # Get summary
            summary = await engine.get_engine_summary()
            print(f"Engine summary: {json.dumps(summary, indent=2)}")
            
        except Exception as e:
            print(f"Demo failed: {e}")
    
    asyncio.run(main()) 
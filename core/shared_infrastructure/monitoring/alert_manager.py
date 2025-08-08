#!/usr/bin/env python3
"""
Alert Manager for AODS Monitoring Framework

Comprehensive alert management system with intelligent routing, notification
channels, alert aggregation, and escalation policies.

Features:
- Multi-channel alert notifications (email, webhook, file, console)
- Intelligent alert filtering and deduplication
- Alert severity classification and escalation
- Alert aggregation and correlation
- Rate limiting and alert fatigue prevention
- Integration with monitoring components
- Alert history and analytics

This component ensures critical issues are promptly communicated
to appropriate stakeholders through configurable channels.
"""

import time
import threading
import logging
import smtplib
import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import hashlib

from ..analysis_exceptions import MonitoringError, ContextualLogger

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class AlertType(Enum):
    """Types of alerts."""
    PERFORMANCE = "performance"
    RESOURCE = "resource"
    HEALTH = "health"
    SECURITY = "security"
    OPERATIONAL = "operational"
    SYSTEM = "system"

class AlertStatus(Enum):
    """Alert processing status."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"
    ACKNOWLEDGED = "acknowledged"

class NotificationChannel(Enum):
    """Available notification channels."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    FILE = "file"
    CONSOLE = "console"
    CUSTOM = "custom"

@dataclass
class Alert:
    """Alert data structure."""
    id: str
    title: str
    message: str
    severity: AlertSeverity
    alert_type: AlertType
    timestamp: datetime
    source: str
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: AlertStatus = AlertStatus.PENDING
    acknowledgment_time: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    escalation_level: int = 0
    related_alerts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary format."""
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'severity': self.severity.value,
            'alert_type': self.alert_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'tags': list(self.tags),
            'metadata': self.metadata,
            'status': self.status.value,
            'acknowledgment_time': self.acknowledgment_time.isoformat() if self.acknowledgment_time else None,
            'acknowledged_by': self.acknowledged_by,
            'escalation_level': self.escalation_level,
            'related_alerts': self.related_alerts
        }
    
    def get_fingerprint(self) -> str:
        """Generate fingerprint for alert deduplication."""
        fingerprint_data = f"{self.source}_{self.alert_type.value}_{self.title}_{self.severity.value}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()

@dataclass
class NotificationConfig:
    """Configuration for notification channels."""
    channel: NotificationChannel
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    severity_filter: Set[AlertSeverity] = field(default_factory=lambda: set(AlertSeverity))
    alert_type_filter: Set[AlertType] = field(default_factory=lambda: set(AlertType))
    rate_limit_seconds: float = 60.0
    last_sent: Optional[datetime] = None
    
    def should_send_alert(self, alert: Alert) -> bool:
        """Check if alert should be sent through this channel."""
        if not self.enabled:
            return False
        
        if alert.severity not in self.severity_filter:
            return False
        
        if alert.alert_type not in self.alert_type_filter:
            return False
        
        # Check rate limiting
        if self.last_sent:
            time_since_last = (datetime.now() - self.last_sent).total_seconds()
            if time_since_last < self.rate_limit_seconds:
                return False
        
        return True

class AlertRule:
    """Rule for alert processing and routing."""
    
    def __init__(self, name: str, condition: Callable[[Alert], bool],
                 actions: List[str], enabled: bool = True):
        self.name = name
        self.condition = condition
        self.actions = actions
        self.enabled = enabled
        self.matches = 0
        self.last_match = None

class AlertAggregator:
    """Alert aggregation and correlation engine."""
    
    def __init__(self, aggregation_window: timedelta = timedelta(minutes=5)):
        self.aggregation_window = aggregation_window
        self.pending_alerts: Dict[str, List[Alert]] = defaultdict(list)
        self.logger = ContextualLogger("alert_aggregator")
    
    def add_alert(self, alert: Alert) -> Optional[Alert]:
        """Add alert for aggregation, returns aggregated alert if ready."""
        fingerprint = alert.get_fingerprint()
        self.pending_alerts[fingerprint].append(alert)
        
        # Check if we should aggregate
        alerts_for_fingerprint = self.pending_alerts[fingerprint]
        if len(alerts_for_fingerprint) == 1:
            # First alert, start aggregation window
            return None
        
        # Check if aggregation window has passed
        first_alert_time = alerts_for_fingerprint[0].timestamp
        if datetime.now() - first_alert_time >= self.aggregation_window:
            # Create aggregated alert
            aggregated = self._create_aggregated_alert(alerts_for_fingerprint)
            del self.pending_alerts[fingerprint]
            return aggregated
        
        return None
    
    def _create_aggregated_alert(self, alerts: List[Alert]) -> Alert:
        """Create an aggregated alert from multiple similar alerts."""
        if not alerts:
            raise ValueError("Cannot aggregate empty alert list")
        
        base_alert = alerts[0]
        count = len(alerts)
        
        # Determine highest severity
        severities = [alert.severity for alert in alerts]
        severity_order = [AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
        highest_severity = max(severities, key=lambda s: severity_order.index(s))
        
        # Create aggregated alert
        aggregated_id = f"agg_{base_alert.get_fingerprint()}_{int(time.time())}"
        aggregated_title = f"{base_alert.title} (x{count})"
        aggregated_message = f"Aggregated {count} similar alerts:\n{base_alert.message}"
        
        # Combine tags and metadata
        all_tags = set()
        combined_metadata = {}
        for alert in alerts:
            all_tags.update(alert.tags)
            combined_metadata.update(alert.metadata)
        
        combined_metadata['aggregated_count'] = count
        combined_metadata['aggregated_alert_ids'] = [alert.id for alert in alerts]
        combined_metadata['time_range'] = {
            'start': min(alert.timestamp for alert in alerts).isoformat(),
            'end': max(alert.timestamp for alert in alerts).isoformat()
        }
        
        return Alert(
            id=aggregated_id,
            title=aggregated_title,
            message=aggregated_message,
            severity=highest_severity,
            alert_type=base_alert.alert_type,
            timestamp=base_alert.timestamp,
            source=base_alert.source,
            tags=all_tags,
            metadata=combined_metadata
        )

class NotificationSender:
    """Handles sending notifications through various channels."""
    
    def __init__(self):
        self.logger = ContextualLogger("notification_sender")
    
    def send_email(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send email notification."""
        try:
            smtp_server = config.get('smtp_server', 'localhost')
            smtp_port = config.get('smtp_port', 587)
            username = config.get('username')
            password = config.get('password')
            sender_email = config.get('sender_email', 'aods@localhost')
            recipient_emails = config.get('recipient_emails', [])
            
            if not recipient_emails:
                self.logger.warning("No recipient emails configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = f"AODS Alert: {alert.severity.value.upper()} - {alert.title}"
            
            # Create email body
            body = f"""
AODS Security Analysis Alert

Severity: {alert.severity.value.upper()}
Type: {alert.alert_type.value}
Source: {alert.source}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Message:
{alert.message}

Tags: {', '.join(alert.tags) if alert.tags else 'None'}

Alert ID: {alert.id}

---
This is an automated message from AODS Monitoring System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if username and password:
                    server.starttls()
                    server.login(username, password)
                server.send_message(msg)
            
            self.logger.info(f"Email notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return False
    
    def send_webhook(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send webhook notification."""
        try:
            url = config.get('url')
            if not url:
                self.logger.warning("No webhook URL configured")
                return False
            
            headers = config.get('headers', {})
            timeout = config.get('timeout', 10)
            
            # Prepare payload
            payload = {
                'alert': alert.to_dict(),
                'notification_time': datetime.now().isoformat(),
                'source_system': 'AODS'
            }
            
            # Add custom fields if configured
            custom_fields = config.get('custom_fields', {})
            payload.update(custom_fields)
            
            # Send webhook
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout
            )
            response.raise_for_status()
            
            self.logger.info(f"Webhook notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
            return False
    
    def send_file(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send file notification (write to file)."""
        try:
            file_path = config.get('file_path', 'alerts.log')
            format_template = config.get('format', 'json')
            
            # Prepare alert data
            if format_template == 'json':
                alert_data = json.dumps(alert.to_dict(), indent=2)
            else:
                # Simple text format
                alert_data = f"[{alert.timestamp.isoformat()}] {alert.severity.value.upper()}: {alert.title} - {alert.message}"
            
            # Write to file
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(alert_data + '\n')
            
            self.logger.debug(f"File notification written for alert {alert.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write file notification: {e}")
            return False
    
    def send_console(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send console notification (print to stdout/stderr)."""
        try:
            use_stderr = config.get('use_stderr', True)
            include_metadata = config.get('include_metadata', False)
            
            # Format message
            severity_prefix = {
                AlertSeverity.INFO: "ℹ️",
                AlertSeverity.WARNING: "⚠️",
                AlertSeverity.CRITICAL: "🚨",
                AlertSeverity.EMERGENCY: "🔥"
            }.get(alert.severity, "📢")
            
            message = f"{severity_prefix} [{alert.timestamp.strftime('%H:%M:%S')}] {alert.severity.value.upper()}: {alert.title}"
            
            if include_metadata and alert.metadata:
                message += f" | Metadata: {json.dumps(alert.metadata, indent=None, separators=(',', ':'))}"
            
            # Output to console
            if use_stderr:
                print(message, file=__import__('sys').stderr)
            else:
                print(message)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send console notification: {e}")
            return False

class AlertManager:
    """
    Comprehensive alert management system for AODS monitoring.
    
    Provides intelligent alert processing, routing, aggregation,
    and multi-channel notification capabilities.
    """
    
    def __init__(self, enable_aggregation: bool = True,
                 aggregation_window: timedelta = timedelta(minutes=5)):
        """
        Initialize alert manager.
        
        Args:
            enable_aggregation: Whether to enable alert aggregation
            aggregation_window: Time window for alert aggregation
        """
        self.enable_aggregation = enable_aggregation
        self.logger = ContextualLogger("alert_manager")
        
        # State management
        self.processing_active = False
        self.processor_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Alert storage
        self.pending_alerts: deque = deque()
        self.processed_alerts: deque = deque(maxlen=10000)
        self.acknowledged_alerts: Dict[str, Alert] = {}
        
        # Alert processing
        self.aggregator = AlertAggregator(aggregation_window) if enable_aggregation else None
        self.sender = NotificationSender()
        self.rules: List[AlertRule] = []
        
        # Notification channels
        self.notification_configs: Dict[NotificationChannel, NotificationConfig] = {}
        
        # Callbacks
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        
        # Metrics
        self.metrics = {
            'alerts_processed': 0,
            'alerts_sent': 0,
            'alerts_failed': 0,
            'alerts_suppressed': 0,
            'alerts_acknowledged': 0
        }
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Initialize default notification channels
        self._initialize_default_channels()
    
    def start_processing(self) -> None:
        """Start alert processing."""
        if self.processing_active:
            self.logger.warning("Alert processing already active")
            return
        
        self.processing_active = True
        self._shutdown_event.clear()
        
        self.processor_thread = threading.Thread(
            target=self._processing_loop,
            name="AlertManager",
            daemon=True
        )
        self.processor_thread.start()
        
        self.logger.info("Started alert processing")
    
    def stop_processing(self) -> None:
        """Stop alert processing."""
        if not self.processing_active:
            return
        
        self.processing_active = False
        self._shutdown_event.set()
        
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=10.0)
        
        self.logger.info("Stopped alert processing")
    
    def send_alert(self, title: str, message: str, severity: AlertSeverity,
                   alert_type: AlertType, source: str,
                   tags: Optional[Set[str]] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Send an alert for processing.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity level
            alert_type: Type of alert
            source: Source component that generated the alert
            tags: Optional tags for categorization
            metadata: Optional additional metadata
            
        Returns:
            Alert ID
        """
        alert_id = f"alert_{int(time.time() * 1000)}_{hash(f'{source}_{title}')}"
        
        alert = Alert(
            id=alert_id,
            title=title,
            message=message,
            severity=severity,
            alert_type=alert_type,
            timestamp=datetime.now(),
            source=source,
            tags=tags or set(),
            metadata=metadata or {}
        )
        
        with self._lock:
            self.pending_alerts.append(alert)
        
        self.logger.debug(f"Alert queued: {alert_id}")
        return alert_id
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: ID of alert to acknowledge
            acknowledged_by: Who acknowledged the alert
            
        Returns:
            True if alert was acknowledged, False if not found
        """
        with self._lock:
            # Check in processed alerts
            for alert in self.processed_alerts:
                if alert.id == alert_id:
                    alert.status = AlertStatus.ACKNOWLEDGED
                    alert.acknowledgment_time = datetime.now()
                    alert.acknowledged_by = acknowledged_by
                    self.acknowledged_alerts[alert_id] = alert
                    self.metrics['alerts_acknowledged'] += 1
                    self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                    return True
        
        return False
    
    def configure_notification_channel(self, channel: NotificationChannel,
                                     config: NotificationConfig) -> None:
        """Configure a notification channel."""
        self.notification_configs[channel] = config
        self.logger.info(f"Configured notification channel: {channel.value}")
    
    def add_alert_rule(self, rule: AlertRule) -> None:
        """Add an alert processing rule."""
        self.rules.append(rule)
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register callback for alert processing."""
        self.alert_callbacks.append(callback)
    
    def get_pending_alerts(self) -> List[Alert]:
        """Get list of pending alerts."""
        with self._lock:
            return list(self.pending_alerts)
    
    def get_alert_history(self, limit: Optional[int] = None) -> List[Alert]:
        """Get alert processing history."""
        with self._lock:
            alerts = list(self.processed_alerts)
            if limit:
                return alerts[-limit:]
            return alerts
    
    def get_alert_metrics(self) -> Dict[str, Any]:
        """Get alert processing metrics."""
        with self._lock:
            return {
                **self.metrics,
                'pending_alerts': len(self.pending_alerts),
                'processed_alerts': len(self.processed_alerts),
                'acknowledged_alerts': len(self.acknowledged_alerts),
                'active_rules': len([r for r in self.rules if r.enabled]),
                'notification_channels': len(self.notification_configs)
            }
    
    def _initialize_default_channels(self) -> None:
        """Initialize default notification channels."""
        # Console channel (always enabled for critical alerts)
        console_config = NotificationConfig(
            channel=NotificationChannel.CONSOLE,
            enabled=True,
            severity_filter={AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY},
            config={'use_stderr': True, 'include_metadata': False}
        )
        self.notification_configs[NotificationChannel.CONSOLE] = console_config
        
        # File channel (for all alerts)
        file_config = NotificationConfig(
            channel=NotificationChannel.FILE,
            enabled=True,
            severity_filter=set(AlertSeverity),
            config={'file_path': 'logs/alerts.log', 'format': 'json'}
        )
        self.notification_configs[NotificationChannel.FILE] = file_config
    
    def _processing_loop(self) -> None:
        """Main alert processing loop."""
        while self.processing_active and not self._shutdown_event.is_set():
            try:
                # Process pending alerts
                alerts_to_process = []
                with self._lock:
                    while self.pending_alerts:
                        alerts_to_process.append(self.pending_alerts.popleft())
                
                for alert in alerts_to_process:
                    self._process_alert(alert)
                
                # Process aggregated alerts if enabled
                if self.aggregator:
                    # Check for any aggregated alerts ready to send
                    pass  # Aggregation happens during alert addition
                
                # Sleep briefly
                self._shutdown_event.wait(timeout=1.0)
                
            except Exception as e:
                self.logger.error(f"Alert processing loop error: {e}")
                self._shutdown_event.wait(timeout=5.0)
    
    def _process_alert(self, alert: Alert) -> None:
        """Process a single alert."""
        try:
            self.metrics['alerts_processed'] += 1
            
            # Apply alert rules
            for rule in self.rules:
                if rule.enabled and rule.condition(alert):
                    rule.matches += 1
                    rule.last_match = datetime.now()
                    # Execute rule actions here if needed
            
            # Check for aggregation
            if self.aggregator:
                aggregated_alert = self.aggregator.add_alert(alert)
                if aggregated_alert:
                    alert = aggregated_alert  # Use aggregated alert instead
            
            # Send notifications
            alert_sent = False
            for channel, config in self.notification_configs.items():
                if config.should_send_alert(alert):
                    success = self._send_notification(alert, channel, config)
                    if success:
                        alert_sent = True
                        config.last_sent = datetime.now()
            
            # Update alert status
            if alert_sent:
                alert.status = AlertStatus.SENT
                self.metrics['alerts_sent'] += 1
            else:
                alert.status = AlertStatus.SUPPRESSED
                self.metrics['alerts_suppressed'] += 1
            
            # Store processed alert
            with self._lock:
                self.processed_alerts.append(alert)
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Alert callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Alert processing error: {e}")
            alert.status = AlertStatus.FAILED
            self.metrics['alerts_failed'] += 1
    
    def _send_notification(self, alert: Alert, channel: NotificationChannel,
                          config: NotificationConfig) -> bool:
        """Send notification through specified channel."""
        try:
            if channel == NotificationChannel.EMAIL:
                return self.sender.send_email(alert, config.config)
            elif channel == NotificationChannel.WEBHOOK:
                return self.sender.send_webhook(alert, config.config)
            elif channel == NotificationChannel.FILE:
                return self.sender.send_file(alert, config.config)
            elif channel == NotificationChannel.CONSOLE:
                return self.sender.send_console(alert, config.config)
            else:
                self.logger.warning(f"Unknown notification channel: {channel}")
                return False
                
        except Exception as e:
            self.logger.error(f"Notification sending error for {channel.value}: {e}")
            return False

# Global alert manager instance
_alert_manager: Optional[AlertManager] = None

def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager 
#!/usr/bin/env python3
"""
User Feedback Interface for AI/ML Model Training

Provides comprehensive interfaces for users to provide feedback to train and improve
the AI/ML models in AODS. Supports multiple interaction methods including command-line,
web interface, programmatic API, and batch feedback processing.

Features:
- Multiple feedback interfaces (CLI, Web, API)
- Real-time feedback collection during scans
- Batch feedback processing from reports
- Interactive feedback sessions
- Feedback validation and quality checks
- Integration with AI/ML training pipeline
- User experience optimization
- Progress tracking and analytics

"""

import logging
import json
import sys
import os
import time
import threading
import webbrowser
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import hashlib
import uuid

# Flask for web interface
try:
    from flask import Flask, render_template, request, jsonify, session, redirect, url_for
    from flask import send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Flask not available - web interface disabled")

# Rich for enhanced CLI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, TaskID
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich not available - enhanced CLI disabled")

from .ai_ml_integration_manager import AIMLIntegrationManager
from ..shared_infrastructure.user_feedback_integration import UserFeedbackIntegration, FeedbackType


class FeedbackInterface(Enum):
    """Available feedback interfaces."""
    CLI = "command_line"
    WEB = "web_interface"
    API = "programmatic_api"
    INTERACTIVE = "interactive_session"
    BATCH = "batch_processing"


@dataclass
class FeedbackSession:
    """User feedback session tracking."""
    session_id: str
    user_id: str
    interface_type: FeedbackInterface
    start_time: datetime
    feedback_count: int = 0
    findings_reviewed: int = 0
    accuracy_score: float = 0.0
    session_notes: str = ""
    end_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


class UserFeedbackInterface:
    """
    Main user feedback interface for AI/ML model training.
    """
    
    def __init__(self, ai_manager: Optional[AIMLIntegrationManager] = None):
        """
        Initialize user feedback interface.
        
        Args:
            ai_manager: AI/ML integration manager for model training
        """
        self.ai_manager = ai_manager
        self.logger = logging.getLogger(f"{__name__}.UserFeedbackInterface")
        
        # Interface components
        self.cli_interface = None
        self.web_interface = None
        self.api_interface = None
        
        # Session management
        self.active_sessions: Dict[str, FeedbackSession] = {}
        self.feedback_history: List[Dict[str, Any]] = []
        
        # Configuration
        self.web_port = 8080
        self.auto_save = True
        self.feedback_file = Path("data/user_feedback_history.json")
        self.feedback_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize feedback integration with proper error handling
        self.feedback_integration = None
        self._initialize_feedback_integration()
        
        # Initialize interfaces
        self._initialize_interfaces()
        
        self.logger.info("User feedback interface initialized")
    
    def _initialize_feedback_integration(self):
        """Initialize feedback integration with proper dependency handling."""
        try:
            from ..shared_infrastructure.pattern_reliability_database import PatternReliabilityDatabase
            from ..shared_infrastructure.learning_system import ConfidenceLearningSystem
            from ..shared_infrastructure.dependency_injection import AnalysisContext
            
            reliability_db = PatternReliabilityDatabase()
            
            # Create a minimal analysis context for feedback operations
            # Use a temporary APK path since this is just for feedback context
            import tempfile
            temp_apk = Path(tempfile.gettempdir()) / "feedback_context_dummy.apk"
            temp_apk.touch(exist_ok=True)  # Create empty file if it doesn't exist
            
            feedback_context = AnalysisContext(
                apk_path=temp_apk,
                config={
                    'confidence': {
                        'enable_learning': True, 
                        'enable_calibration': True,
                        'min_confidence': 0.1
                    }
                }
            )
            
            learning_system = ConfidenceLearningSystem(feedback_context)
            self.feedback_integration = UserFeedbackIntegration(reliability_db, learning_system)
            self.logger.info("Feedback integration initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Could not initialize feedback integration: {e}")
            self.logger.debug("Feedback will be collected but advanced integration features will be disabled")
            self.feedback_integration = None
    
    def _initialize_interfaces(self):
        """Initialize available interfaces."""
        # CLI Interface
        if RICH_AVAILABLE:
            self.cli_interface = EnhancedCLIInterface(self)
        else:
            self.cli_interface = BasicCLIInterface(self)
        
        # Web Interface
        if FLASK_AVAILABLE:
            self.web_interface = WebFeedbackInterface(self)
        
        # API Interface
        self.api_interface = ProgrammaticAPIInterface(self)
    
    def start_feedback_session(self, user_id: str, interface_type: FeedbackInterface) -> str:
        """
        Start a new feedback session.
        
        Args:
            user_id: User identifier
            interface_type: Type of interface being used
            
        Returns:
            Session ID
        """
        session_id = str(uuid.uuid4())
        
        session = FeedbackSession(
            session_id=session_id,
            user_id=user_id,
            interface_type=interface_type,
            start_time=datetime.now()
        )
        
        self.active_sessions[session_id] = session
        self.logger.info(f"Started feedback session: {session_id} for user {user_id}")
        
        return session_id
    
    def end_feedback_session(self, session_id: str) -> FeedbackSession:
        """
        End a feedback session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Completed session data
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session not found: {session_id}")
        
        session = self.active_sessions[session_id]
        session.end_time = datetime.now()
        
        # Save session to history
        self.feedback_history.append(session.to_dict())
        
        # Remove from active sessions
        del self.active_sessions[session_id]
        
        self.logger.info(f"Ended feedback session: {session_id}")
        
        if self.auto_save:
            self._save_feedback_history()
        
        return session
    
    def submit_finding_feedback(self, 
                              session_id: str,
                              finding_data: Dict[str, Any],
                              is_accurate: bool,
                              confidence: Optional[float] = None,
                              comments: str = "",
                              evidence: Dict[str, Any] = None) -> str:
        """
        Submit feedback for a specific finding.
        
        Args:
            session_id: Feedback session ID
            finding_data: Complete finding data
            is_accurate: Whether the finding is accurate
            confidence: User's confidence in the assessment
            comments: Additional comments
            evidence: Supporting evidence
            
        Returns:
            Feedback ID
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session not found: {session_id}")
        
        session = self.active_sessions[session_id]
        
        # Extract relevant information
        finding_id = finding_data.get("id", str(uuid.uuid4()))
        pattern_id = finding_data.get("pattern_id", "unknown")
        content = finding_data.get("description", "") + " " + finding_data.get("content", "")
        
        # Submit to AI/ML training
        feedback_id = None
        if self.ai_manager and self.ai_manager.ai_components_available:
            try:
                # Submit to AI/ML integration manager
                training_feedback = {
                    "type": "vulnerability_accuracy",
                    "content": content,
                    "is_vulnerability": is_accurate,
                    "notes": comments,
                    "confidence": confidence or 0.8,
                    "finding_id": finding_id,
                    "pattern_id": pattern_id
                }
                
                result = self.ai_manager.train_from_feedback([training_feedback])
                self.logger.info(f"Submitted feedback to AI/ML training: {result}")
                
            except Exception as e:
                self.logger.error(f"Failed to submit AI/ML feedback: {e}")
        
        # Submit to feedback integration system
        if self.feedback_integration:
            try:
                feedback_id = self.feedback_integration.submit_feedback(
                    expert_id=session.user_id,
                    feedback_type=FeedbackType.FINDING_VALIDATION,
                    finding_id=finding_id,
                    pattern_id=pattern_id,
                    is_accurate=is_accurate,
                    confidence_assessment=confidence,
                    comments=comments,
                    evidence=evidence
                )
            except Exception as e:
                self.logger.error(f"Failed to submit feedback integration: {e}")
        
        # Update session
        session.feedback_count += 1
        session.findings_reviewed += 1
        
        # Create feedback record
        feedback_record = {
            "feedback_id": feedback_id or str(uuid.uuid4()),
            "session_id": session_id,
            "finding_id": finding_id,
            "pattern_id": pattern_id,
            "is_accurate": is_accurate,
            "confidence": confidence,
            "comments": comments,
            "evidence": evidence or {},
            "timestamp": datetime.now().isoformat(),
            "interface_type": session.interface_type.value
        }
        
        self.feedback_history.append(feedback_record)
        
        self.logger.info(f"Submitted finding feedback: {feedback_record['feedback_id']}")
        return feedback_record['feedback_id']
    
    def submit_false_positive_feedback(self,
                                     session_id: str,
                                     finding_data: Dict[str, Any],
                                     is_false_positive: bool,
                                     reason: str = "",
                                     confidence: Optional[float] = None) -> str:
        """
        Submit false positive feedback.
        
        Args:
            session_id: Feedback session ID
            finding_data: Complete finding data
            is_false_positive: Whether this is a false positive
            reason: Reason for false positive classification
            confidence: User's confidence in the assessment
            
        Returns:
            Feedback ID
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session not found: {session_id}")
        
        session = self.active_sessions[session_id]
        content = finding_data.get("description", "") + " " + finding_data.get("content", "")
        
        # Submit to AI/ML training
        if self.ai_manager and self.ai_manager.ai_components_available:
            try:
                training_feedback = {
                    "type": "false_positive",
                    "content": content,
                    "is_false_positive": is_false_positive,
                    "notes": reason,
                    "confidence": confidence or 0.8
                }
                
                result = self.ai_manager.train_from_feedback([training_feedback])
                self.logger.info(f"Submitted FP feedback to AI/ML training: {result}")
                
            except Exception as e:
                self.logger.error(f"Failed to submit AI/ML FP feedback: {e}")
        
        # Submit to feedback integration
        feedback_id = None
        if self.feedback_integration:
            try:
                feedback_id = self.feedback_integration.submit_feedback(
                    expert_id=session.user_id,
                    feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
                    finding_id=finding_data.get("id", str(uuid.uuid4())),
                    pattern_id=finding_data.get("pattern_id", "unknown"),
                    is_accurate=not is_false_positive,
                    comments=reason,
                    confidence_assessment=confidence
                )
            except Exception as e:
                self.logger.error(f"Failed to submit FP feedback integration: {e}")
        
        # Update session
        session.feedback_count += 1
        
        feedback_record = {
            "feedback_id": feedback_id or str(uuid.uuid4()),
            "session_id": session_id,
            "type": "false_positive",
            "is_false_positive": is_false_positive,
            "reason": reason,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        
        self.feedback_history.append(feedback_record)
        return feedback_record['feedback_id']
    
    def batch_process_feedback(self, feedback_file: str) -> Dict[str, Any]:
        """
        Process feedback from a batch file.
        
        Args:
            feedback_file: Path to JSON file containing feedback data
            
        Returns:
            Processing results
        """
        try:
            with open(feedback_file, 'r') as f:
                feedback_data = json.load(f)
            
            if not isinstance(feedback_data, list):
                feedback_data = [feedback_data]
            
            results = {
                "processed": 0,
                "errors": 0,
                "feedback_ids": []
            }
            
            session_id = self.start_feedback_session("batch_processor", FeedbackInterface.BATCH)
            
            for item in feedback_data:
                try:
                    if item.get("type") == "finding_validation":
                        feedback_id = self.submit_finding_feedback(
                            session_id=session_id,
                            finding_data=item.get("finding_data", {}),
                            is_accurate=item.get("is_accurate", False),
                            confidence=item.get("confidence"),
                            comments=item.get("comments", ""),
                            evidence=item.get("evidence", {})
                        )
                        results["feedback_ids"].append(feedback_id)
                        results["processed"] += 1
                        
                    elif item.get("type") == "false_positive":
                        feedback_id = self.submit_false_positive_feedback(
                            session_id=session_id,
                            finding_data=item.get("finding_data", {}),
                            is_false_positive=item.get("is_false_positive", True),
                            reason=item.get("reason", ""),
                            confidence=item.get("confidence")
                        )
                        results["feedback_ids"].append(feedback_id)
                        results["processed"] += 1
                        
                except Exception as e:
                    self.logger.error(f"Failed to process batch feedback item: {e}")
                    results["errors"] += 1
            
            self.end_feedback_session(session_id)
            
            self.logger.info(f"Batch processed {results['processed']} feedback items with {results['errors']} errors")
            return results
            
        except Exception as e:
            self.logger.error(f"Batch feedback processing failed: {e}")
            return {"error": str(e)}
    
    def get_feedback_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics and analytics."""
        stats = {
            "total_feedback": len(self.feedback_history),
            "active_sessions": len(self.active_sessions),
            "interfaces_used": {},
            "feedback_types": {},
            "accuracy_distribution": {},
            "recent_activity": []
        }
        
        # Analyze feedback history
        for feedback in self.feedback_history:
            # Interface usage
            interface = feedback.get("interface_type", "unknown")
            stats["interfaces_used"][interface] = stats["interfaces_used"].get(interface, 0) + 1
            
            # Feedback types
            feedback_type = feedback.get("type", "finding_validation")
            stats["feedback_types"][feedback_type] = stats["feedback_types"].get(feedback_type, 0) + 1
            
            # Accuracy distribution
            is_accurate = feedback.get("is_accurate", feedback.get("is_false_positive") is False)
            accuracy_key = "accurate" if is_accurate else "inaccurate"
            stats["accuracy_distribution"][accuracy_key] = stats["accuracy_distribution"].get(accuracy_key, 0) + 1
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.now().timestamp() - 86400  # 24 hours
        for feedback in self.feedback_history:
            try:
                feedback_time = datetime.fromisoformat(feedback.get("timestamp", "")).timestamp()
                if feedback_time > recent_cutoff:
                    stats["recent_activity"].append(feedback)
            except:
                pass
        
        return stats
    
    def _save_feedback_history(self):
        """Save feedback history to file."""
        try:
            with open(self.feedback_file, 'w') as f:
                json.dump(self.feedback_history, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save feedback history: {e}")
    
    def _load_feedback_history(self):
        """Load feedback history from file."""
        try:
            if self.feedback_file.exists():
                with open(self.feedback_file, 'r') as f:
                    self.feedback_history = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load feedback history: {e}")


class EnhancedCLIInterface:
    """Enhanced command-line interface using Rich."""
    
    def __init__(self, feedback_interface: UserFeedbackInterface):
        """Initialize enhanced CLI interface."""
        self.feedback_interface = feedback_interface
        self.console = Console()
        self.current_session = None
    
    def start_interactive_session(self, user_id: str = "cli_user"):
        """Start an interactive feedback session."""
        self.console.print(Panel.fit(
            "[bold blue]AODS AI/ML Training Feedback System[/bold blue]\n"
            "Help improve vulnerability detection accuracy!",
            border_style="blue"
        ))
        
        # Start session
        session_id = self.feedback_interface.start_feedback_session(user_id, FeedbackInterface.CLI)
        self.current_session = session_id
        
        self.console.print(f"[green]Started feedback session: {session_id}[/green]")
        
        # Main feedback loop
        self._feedback_loop()
    
    def _feedback_loop(self):
        """Main feedback collection loop."""
        while True:
            self.console.print("\n[bold]What would you like to do?[/bold]")
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Option", style="cyan")
            table.add_column("Description", style="white")
            
            table.add_row("1", "Review scan findings and provide feedback")
            table.add_row("2", "Submit false positive report")
            table.add_row("3", "Batch process feedback file")
            table.add_row("4", "View feedback statistics")
            table.add_row("5", "End session")
            
            self.console.print(table)
            
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
            
            if choice == "1":
                self._review_findings()
            elif choice == "2":
                self._submit_false_positive()
            elif choice == "3":
                self._batch_process()
            elif choice == "4":
                self._show_statistics()
            elif choice == "5":
                break
        
        # End session
        session = self.feedback_interface.end_feedback_session(self.current_session)
        self.console.print(f"[green]Session completed! Provided {session.feedback_count} feedback entries.[/green]")
    
    def _review_findings(self):
        """Review findings and provide feedback."""
        self.console.print("[yellow]Please provide a scan results file to review:[/yellow]")
        results_file = Prompt.ask("Scan results file path")
        
        try:
            with open(results_file, 'r') as f:
                results_data = json.load(f)
            
            findings = results_data.get("findings", [])
            if not findings:
                self.console.print("[red]No findings found in results file[/red]")
                return
            
            self.console.print(f"[green]Found {len(findings)} findings to review[/green]")
            
            for i, finding in enumerate(findings):
                self._review_single_finding(finding, i + 1, len(findings))
                
                if i < len(findings) - 1:
                    if not Confirm.ask("Continue to next finding?"):
                        break
        
        except Exception as e:
            self.console.print(f"[red]Error loading results file: {e}[/red]")
    
    def _review_single_finding(self, finding: Dict[str, Any], current: int, total: int):
        """Review a single finding."""
        self.console.print(f"\n[bold]Finding {current} of {total}[/bold]")
        
        # Display finding details
        finding_panel = Panel(
            f"[bold]Type:[/bold] {finding.get('type', 'Unknown')}\n"
            f"[bold]Severity:[/bold] {finding.get('severity', 'Unknown')}\n"
            f"[bold]Confidence:[/bold] {finding.get('confidence', 'N/A')}\n"
            f"[bold]Description:[/bold] {finding.get('description', 'N/A')}\n"
            f"[bold]Location:[/bold] {finding.get('location', 'N/A')}",
            title="Finding Details",
            border_style="yellow"
        )
        
        self.console.print(finding_panel)
        
        # Get feedback
        is_accurate = Confirm.ask("Is this finding accurate?")
        confidence = None
        
        if Confirm.ask("Would you like to provide a confidence score?"):
            confidence = float(Prompt.ask("Confidence (0.0-1.0)", default="0.8"))
        
        comments = Prompt.ask("Additional comments (optional)", default="")
        
        # Submit feedback
        try:
            feedback_id = self.feedback_interface.submit_finding_feedback(
                session_id=self.current_session,
                finding_data=finding,
                is_accurate=is_accurate,
                confidence=confidence,
                comments=comments
            )
            
            self.console.print(f"[green]Feedback submitted: {feedback_id}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Failed to submit feedback: {e}[/red]")
    
    def _submit_false_positive(self):
        """Submit false positive feedback."""
        self.console.print("[yellow]Submit False Positive Report[/yellow]")
        
        # Get finding data
        finding_id = Prompt.ask("Finding ID")
        description = Prompt.ask("Finding description")
        content = Prompt.ask("Finding content")
        
        finding_data = {
            "id": finding_id,
            "description": description,
            "content": content
        }
        
        is_fp = Confirm.ask("Is this a false positive?", default=True)
        reason = Prompt.ask("Reason for classification")
        confidence = float(Prompt.ask("Confidence (0.0-1.0)", default="0.8"))
        
        try:
            feedback_id = self.feedback_interface.submit_false_positive_feedback(
                session_id=self.current_session,
                finding_data=finding_data,
                is_false_positive=is_fp,
                reason=reason,
                confidence=confidence
            )
            
            self.console.print(f"[green]False positive feedback submitted: {feedback_id}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Failed to submit feedback: {e}[/red]")
    
    def _batch_process(self):
        """Process batch feedback file."""
        self.console.print("[yellow]Batch Process Feedback File[/yellow]")
        
        feedback_file = Prompt.ask("Feedback file path")
        
        with self.console.status("[bold green]Processing batch feedback..."):
            results = self.feedback_interface.batch_process_feedback(feedback_file)
        
        if "error" in results:
            self.console.print(f"[red]Batch processing failed: {results['error']}[/red]")
        else:
            self.console.print(f"[green]Successfully processed {results['processed']} items "
                             f"with {results['errors']} errors[/green]")
    
    def _show_statistics(self):
        """Show feedback statistics."""
        stats = self.feedback_interface.get_feedback_statistics()
        
        # Create statistics table
        stats_table = Table(title="Feedback Statistics", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white")
        
        stats_table.add_row("Total Feedback", str(stats["total_feedback"]))
        stats_table.add_row("Active Sessions", str(stats["active_sessions"]))
        stats_table.add_row("Recent Activity (24h)", str(len(stats["recent_activity"])))
        
        self.console.print(stats_table)
        
        # Interface usage
        if stats["interfaces_used"]:
            interface_table = Table(title="Interface Usage", show_header=True)
            interface_table.add_column("Interface", style="cyan")
            interface_table.add_column("Count", style="white")
            
            for interface, count in stats["interfaces_used"].items():
                interface_table.add_row(interface, str(count))
            
            self.console.print(interface_table)


class BasicCLIInterface:
    """Basic command-line interface without Rich."""
    
    def __init__(self, feedback_interface: UserFeedbackInterface):
        """Initialize basic CLI interface."""
        self.feedback_interface = feedback_interface
        self.current_session = None
    
    def start_interactive_session(self, user_id: str = "cli_user"):
        """Start an interactive feedback session."""
        print("=" * 60)
        print("AODS AI/ML Training Feedback System")
        print("Help improve vulnerability detection accuracy!")
        print("=" * 60)
        
        # Start session
        session_id = self.feedback_interface.start_feedback_session(user_id, FeedbackInterface.CLI)
        self.current_session = session_id
        
        print(f"Started feedback session: {session_id}")
        
        # Main feedback loop
        self._feedback_loop()
    
    def _feedback_loop(self):
        """Main feedback collection loop."""
        while True:
            print("\nWhat would you like to do?")
            print("1. Review scan findings and provide feedback")
            print("2. Submit false positive report")
            print("3. Batch process feedback file")
            print("4. View feedback statistics")
            print("5. End session")
            
            choice = input("Select option (1-5): ").strip()
            
            if choice == "1":
                self._review_findings()
            elif choice == "2":
                self._submit_false_positive()
            elif choice == "3":
                self._batch_process()
            elif choice == "4":
                self._show_statistics()
            elif choice == "5":
                break
            else:
                print("Invalid choice. Please select 1-5.")
        
        # End session
        session = self.feedback_interface.end_feedback_session(self.current_session)
        print(f"Session completed! Provided {session.feedback_count} feedback entries.")
    
    def _review_findings(self):
        """Review findings and provide feedback."""
        results_file = input("Scan results file path: ")
        
        try:
            with open(results_file, 'r') as f:
                results_data = json.load(f)
            
            findings = results_data.get("findings", [])
            if not findings:
                print("No findings found in results file")
                return
            
            print(f"Found {len(findings)} findings to review")
            
            for i, finding in enumerate(findings):
                self._review_single_finding(finding, i + 1, len(findings))
                
                if i < len(findings) - 1:
                    continue_review = input("Continue to next finding? (y/n): ").lower().strip()
                    if continue_review != 'y':
                        break
        
        except Exception as e:
            print(f"Error loading results file: {e}")
    
    def _review_single_finding(self, finding: Dict[str, Any], current: int, total: int):
        """Review a single finding."""
        print(f"\nFinding {current} of {total}")
        print("-" * 40)
        print(f"Type: {finding.get('type', 'Unknown')}")
        print(f"Severity: {finding.get('severity', 'Unknown')}")
        print(f"Confidence: {finding.get('confidence', 'N/A')}")
        print(f"Description: {finding.get('description', 'N/A')}")
        print(f"Location: {finding.get('location', 'N/A')}")
        print("-" * 40)
        
        # Get feedback
        is_accurate = input("Is this finding accurate? (y/n): ").lower() == 'y'
        
        confidence = None
        provide_confidence = input("Provide confidence score? (y/n): ").lower() == 'y'
        if provide_confidence:
            try:
                confidence = float(input("Confidence (0.0-1.0): "))
            except ValueError:
                confidence = 0.8
        
        comments = input("Additional comments (optional): ")
        
        # Submit feedback
        try:
            feedback_id = self.feedback_interface.submit_finding_feedback(
                session_id=self.current_session,
                finding_data=finding,
                is_accurate=is_accurate,
                confidence=confidence,
                comments=comments
            )
            
            print(f"Feedback submitted: {feedback_id}")
            
        except Exception as e:
            print(f"Failed to submit feedback: {e}")
    
    def _submit_false_positive(self):
        """Submit false positive feedback."""
        print("Submit False Positive Report")
        print("-" * 30)
        
        # Get finding data
        finding_id = input("Finding ID: ")
        description = input("Finding description: ")
        content = input("Finding content: ")
        
        finding_data = {
            "id": finding_id,
            "description": description,
            "content": content
        }
        
        is_fp = input("Is this a false positive? (y/n): ").lower() == 'y'
        reason = input("Reason for classification: ")
        
        try:
            confidence = float(input("Confidence (0.0-1.0, default 0.8): ") or "0.8")
        except ValueError:
            confidence = 0.8
        
        try:
            feedback_id = self.feedback_interface.submit_false_positive_feedback(
                session_id=self.current_session,
                finding_data=finding_data,
                is_false_positive=is_fp,
                reason=reason,
                confidence=confidence
            )
            
            print(f"False positive feedback submitted: {feedback_id}")
            
        except Exception as e:
            print(f"Failed to submit feedback: {e}")
    
    def _batch_process(self):
        """Process batch feedback file."""
        print("Batch Process Feedback File")
        print("-" * 30)
        
        feedback_file = input("Feedback file path: ")
        
        print("Processing batch feedback...")
        results = self.feedback_interface.batch_process_feedback(feedback_file)
        
        if "error" in results:
            print(f"Batch processing failed: {results['error']}")
        else:
            print(f"Successfully processed {results['processed']} items "
                  f"with {results['errors']} errors")
    
    def _show_statistics(self):
        """Show feedback statistics."""
        stats = self.feedback_interface.get_feedback_statistics()
        
        print("\nFeedback Statistics")
        print("=" * 30)
        print(f"Total Feedback: {stats['total_feedback']}")
        print(f"Active Sessions: {stats['active_sessions']}")
        print(f"Recent Activity (24h): {len(stats['recent_activity'])}")
        
        if stats["interfaces_used"]:
            print("\nInterface Usage:")
            for interface, count in stats["interfaces_used"].items():
                print(f"  {interface}: {count}")


class WebFeedbackInterface:
    """Web-based feedback interface using Flask."""
    
    def __init__(self, feedback_interface: UserFeedbackInterface):
        """Initialize web interface."""
        self.feedback_interface = feedback_interface
        
        # Get the project root directory and setup template path
        project_root = Path(__file__).parent.parent.parent
        template_folder = project_root / "templates"
        
        # Create Flask app with proper template folder
        self.app = Flask(__name__, template_folder=str(template_folder))
        self.app.secret_key = "aods_feedback_interface"
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index():
            """Main feedback interface page."""
            # Check if template exists, if not provide a simple HTML response
            template_path = Path(self.app.template_folder) / 'feedback_interface.html'
            if template_path.exists():
                return render_template('feedback_interface.html')
            else:
                # Provide a basic HTML interface if template is missing
                return self._get_basic_html_interface()
        
        @self.app.route('/api/start_session', methods=['POST'])
        def start_session():
            """Start a new feedback session."""
            user_id = request.json.get('user_id', 'web_user')
            session_id = self.feedback_interface.start_feedback_session(user_id, FeedbackInterface.WEB)
            session['feedback_session_id'] = session_id
            return jsonify({'session_id': session_id})
        
        @self.app.route('/api/submit_feedback', methods=['POST'])
        def submit_feedback():
            """Submit finding feedback."""
            try:
                data = request.json
                feedback_id = self.feedback_interface.submit_finding_feedback(
                    session_id=session.get('feedback_session_id'),
                    finding_data=data.get('finding_data', {}),
                    is_accurate=data.get('is_accurate', False),
                    confidence=data.get('confidence'),
                    comments=data.get('comments', ''),
                    evidence=data.get('evidence', {})
                )
                return jsonify({'feedback_id': feedback_id})
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/submit_false_positive', methods=['POST'])
        def submit_false_positive():
            """Submit false positive feedback."""
            try:
                data = request.json
                feedback_id = self.feedback_interface.submit_false_positive_feedback(
                    session_id=session.get('feedback_session_id'),
                    finding_data=data.get('finding_data', {}),
                    is_false_positive=data.get('is_false_positive', True),
                    reason=data.get('reason', ''),
                    confidence=data.get('confidence')
                )
                return jsonify({'feedback_id': feedback_id})
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/statistics')
        def get_statistics():
            """Get feedback statistics."""
            stats = self.feedback_interface.get_feedback_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/end_session', methods=['POST'])
        def end_session():
            """End feedback session."""
            if 'feedback_session_id' in session:
                completed_session = self.feedback_interface.end_feedback_session(session['feedback_session_id'])
                del session['feedback_session_id']
                return jsonify(completed_session.to_dict())
            return jsonify({'error': 'No active session'})
    
    def _get_basic_html_interface(self):
        """Provide a basic HTML interface when template is not available."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AODS AI/ML Training Feedback</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; margin-bottom: 30px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #005a87; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AODS AI/ML Training Feedback</h1>
            <p>Help improve vulnerability detection accuracy through expert feedback</p>
        </div>

        <div id="alerts"></div>

        <div class="section">
            <h3>Submit Finding Feedback</h3>
            <form id="feedback-form">
                <div class="form-group">
                    <label for="finding-id">Finding ID:</label>
                    <input type="text" id="finding-id" required>
                </div>
                <div class="form-group">
                    <label for="finding-description">Description:</label>
                    <textarea id="finding-description" rows="3" required></textarea>
                </div>
                <div class="form-group">
                    <label for="is-accurate">Is this finding accurate?</label>
                    <select id="is-accurate" required>
                        <option value="">Select...</option>
                        <option value="true">Yes - This is a real vulnerability</option>
                        <option value="false">No - This is not a vulnerability</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="confidence">Confidence (0.0-1.0):</label>
                    <input type="number" id="confidence" min="0" max="1" step="0.1" value="0.8">
                </div>
                <div class="form-group">
                    <label for="comments">Comments:</label>
                    <textarea id="comments" rows="3"></textarea>
                </div>
                <button type="submit">Submit Feedback</button>
            </form>
        </div>

        <div class="section">
            <h3>Submit False Positive Report</h3>
            <form id="fp-form">
                <div class="form-group">
                    <label for="fp-finding-id">Finding ID:</label>
                    <input type="text" id="fp-finding-id" required>
                </div>
                <div class="form-group">
                    <label for="fp-description">Description:</label>
                    <textarea id="fp-description" rows="3" required></textarea>
                </div>
                <div class="form-group">
                    <label for="fp-reason">Reason for False Positive:</label>
                    <select id="fp-reason" required>
                        <option value="">Select reason...</option>
                        <option value="build_artifact">Build artifact or generated code</option>
                        <option value="test_code">Test code or mock data</option>
                        <option value="configuration">Configuration file</option>
                        <option value="documentation">Documentation or comments</option>
                        <option value="library_code">Third-party library code</option>
                        <option value="other">Other</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="fp-details">Additional Details:</label>
                    <textarea id="fp-details" rows="3"></textarea>
                </div>
                <button type="submit">Submit False Positive Report</button>
            </form>
        </div>

        <div class="section">
            <h3>Statistics</h3>
            <button onclick="loadStats()">Refresh Statistics</button>
            <div id="stats-container" class="stats">
                <div class="stat-card">
                    <h4>Total Feedback</h4>
                    <div id="total-feedback">-</div>
                </div>
                <div class="stat-card">
                    <h4>Active Sessions</h4>
                    <div id="active-sessions">-</div>
                </div>
                <div class="stat-card">
                    <h4>Recent Activity</h4>
                    <div id="recent-activity">-</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let sessionId = null;

        // Initialize session on page load
        document.addEventListener('DOMContentLoaded', function() {
            startSession();
            loadStats();
        });

        async function startSession() {
            try {
                const response = await fetch('/api/start_session', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: 'web_user_' + Date.now()})
                });
                const data = await response.json();
                sessionId = data.session_id;
                showAlert('Session started: ' + sessionId, 'success');
            } catch (error) {
                showAlert('Failed to start session: ' + error, 'error');
            }
        }

        document.getElementById('feedback-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const feedbackData = {
                finding_data: {
                    id: document.getElementById('finding-id').value,
                    description: document.getElementById('finding-description').value
                },
                is_accurate: document.getElementById('is-accurate').value === 'true',
                confidence: parseFloat(document.getElementById('confidence').value),
                comments: document.getElementById('comments').value
            };

            try {
                const response = await fetch('/api/submit_feedback', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(feedbackData)
                });
                const result = await response.json();
                
                if (result.feedback_id) {
                    showAlert('Feedback submitted: ' + result.feedback_id, 'success');
                    document.getElementById('feedback-form').reset();
                    loadStats();
                } else {
                    showAlert('Error: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showAlert('Failed to submit feedback: ' + error, 'error');
            }
        });

        document.getElementById('fp-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fpData = {
                finding_data: {
                    id: document.getElementById('fp-finding-id').value,
                    description: document.getElementById('fp-description').value
                },
                is_false_positive: true,
                reason: document.getElementById('fp-reason').value + ': ' + document.getElementById('fp-details').value
            };

            try {
                const response = await fetch('/api/submit_false_positive', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(fpData)
                });
                const result = await response.json();
                
                if (result.feedback_id) {
                    showAlert('False positive report submitted: ' + result.feedback_id, 'success');
                    document.getElementById('fp-form').reset();
                    loadStats();
                } else {
                    showAlert('Error: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showAlert('Failed to submit false positive report: ' + error, 'error');
            }
        });

        async function loadStats() {
            try {
                const response = await fetch('/api/statistics');
                const stats = await response.json();
                
                document.getElementById('total-feedback').textContent = stats.total_feedback || 0;
                document.getElementById('active-sessions').textContent = stats.active_sessions || 0;
                document.getElementById('recent-activity').textContent = (stats.recent_activity || []).length;
            } catch (error) {
                showAlert('Failed to load statistics: ' + error, 'error');
            }
        }

        function showAlert(message, type) {
            const alertsContainer = document.getElementById('alerts');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.textContent = message;
            
            alertsContainer.appendChild(alert);
            
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.parentNode.removeChild(alert);
                }
            }, 5000);
        }

        // End session when page unloads
        window.addEventListener('beforeunload', function() {
            if (sessionId) {
                fetch('/api/end_session', {method: 'POST'});
            }
        });
    </script>
</body>
</html>
        """
    
    def start_server(self, port: int = 8080, debug: bool = False):
        """Start the web server."""
        print(f"Starting web feedback interface on http://localhost:{port}")
        print("Open this URL in your browser to provide feedback.")
        
        # Check if template exists
        template_path = Path(self.app.template_folder) / 'feedback_interface.html'
        if template_path.exists():
            print(f"Using template: {template_path}")
        else:
            print("Template not found - using built-in basic interface")
        
        # Try to open browser automatically
        try:
            webbrowser.open(f"http://localhost:{port}")
        except:
            pass
        
        self.app.run(host='0.0.0.0', port=port, debug=debug)


class ProgrammaticAPIInterface:
    """Programmatic API interface for feedback submission."""
    
    def __init__(self, feedback_interface: UserFeedbackInterface):
        """Initialize API interface."""
        self.feedback_interface = feedback_interface
    
    def create_feedback_session(self, user_id: str) -> str:
        """Create a new feedback session."""
        return self.feedback_interface.start_feedback_session(user_id, FeedbackInterface.API)
    
    def submit_finding_feedback(self, session_id: str, finding_data: Dict[str, Any], 
                              is_accurate: bool, **kwargs) -> str:
        """Submit finding feedback via API."""
        return self.feedback_interface.submit_finding_feedback(
            session_id=session_id,
            finding_data=finding_data,
            is_accurate=is_accurate,
            **kwargs
        )
    
    def submit_false_positive_feedback(self, session_id: str, finding_data: Dict[str, Any],
                                     is_false_positive: bool, **kwargs) -> str:
        """Submit false positive feedback via API."""
        return self.feedback_interface.submit_false_positive_feedback(
            session_id=session_id,
            finding_data=finding_data,
            is_false_positive=is_false_positive,
            **kwargs
        )
    
    def end_session(self, session_id: str) -> Dict[str, Any]:
        """End feedback session."""
        session = self.feedback_interface.end_feedback_session(session_id)
        return session.to_dict()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        return self.feedback_interface.get_feedback_statistics()


# Convenience functions for easy usage
def start_cli_feedback(user_id: str = "cli_user", ai_manager: Optional[AIMLIntegrationManager] = None):
    """Start CLI feedback interface."""
    feedback_interface = UserFeedbackInterface(ai_manager)
    feedback_interface.cli_interface.start_interactive_session(user_id)


def start_web_feedback(port: int = 8080, ai_manager: Optional[AIMLIntegrationManager] = None):
    """Start web feedback interface."""
    if not FLASK_AVAILABLE:
        print("Flask not available - cannot start web interface")
        return
    
    feedback_interface = UserFeedbackInterface(ai_manager)
    feedback_interface.web_interface.start_server(port)


def create_api_interface(ai_manager: Optional[AIMLIntegrationManager] = None) -> ProgrammaticAPIInterface:
    """Create programmatic API interface."""
    feedback_interface = UserFeedbackInterface(ai_manager)
    return feedback_interface.api_interface


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AODS ML Training Feedback Interface")
    parser.add_argument("--interface", choices=["cli", "web", "api"], default="cli",
                      help="Interface type to start")
    parser.add_argument("--port", type=int, default=8080,
                      help="Port for web interface")
    parser.add_argument("--user-id", default="test_user",
                      help="User ID for session")
    
    args = parser.parse_args()
    
    if args.interface == "cli":
        start_cli_feedback(args.user_id)
    elif args.interface == "web":
        start_web_feedback(args.port)
    elif args.interface == "api":
        print("API interface created - use create_api_interface() in your code") 
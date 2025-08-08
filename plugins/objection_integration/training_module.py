#!/usr/bin/env python3
"""
Objection Training Module

Provides guided training scenarios using objection for hands-on mobile
security testing education and skill development.

Author: AODS Team
Date: January 2025
"""

import json
import logging
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class SkillLevel(Enum):
    """Training skill levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class FocusArea(Enum):
    """Training focus areas."""
    CRYPTO = "crypto"
    NETWORK = "network"
    STORAGE = "storage"
    AUTHENTICATION = "authentication"
    GENERAL = "general"
    QR_CODE = "qr_code"
    BIOMETRIC = "biometric"


@dataclass
class TrainingScenario:
    """A structured training scenario."""
    name: str
    skill_level: SkillLevel
    focus_area: FocusArea
    description: str
    objectives: List[str]
    prerequisites: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    expected_outcomes: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    time_estimate: int = 30  # minutes
    difficulty_rating: int = 1  # 1-10


@dataclass
class TrainingProgress:
    """Track student training progress."""
    student_id: str
    scenarios_completed: List[str] = field(default_factory=list)
    current_skill_level: SkillLevel = SkillLevel.BEGINNER
    focus_areas_mastered: List[FocusArea] = field(default_factory=list)
    total_practice_time: int = 0  # minutes
    last_training_date: Optional[str] = None


class ObjectionTrainingModule:
    """
    Interactive training module using objection for mobile security education.
    
    Provides progressive learning scenarios, guided walkthroughs, and hands-on
    practice with real mobile applications and security testing techniques.
    """
    
    def __init__(self):
        """Initialize training module."""
        self.logger = logging.getLogger(__name__)
        self.training_scenarios = self._initialize_training_scenarios()
        self.student_progress = {}
    
    def generate_training_scenario(self, skill_level: SkillLevel, focus_area: FocusArea) -> TrainingScenario:
        """
        Generate a training scenario based on skill level and focus area.
        
        Args:
            skill_level: Student's current skill level
            focus_area: Desired training focus area
            
        Returns:
            Appropriate training scenario
        """
        try:
            # Find matching scenarios
            matching_scenarios = [
                scenario for scenario in self.training_scenarios
                if scenario.skill_level == skill_level and scenario.focus_area == focus_area
            ]
            
            if not matching_scenarios:
                # Fallback to general scenarios
                matching_scenarios = [
                    scenario for scenario in self.training_scenarios
                    if scenario.skill_level == skill_level and scenario.focus_area == FocusArea.GENERAL
                ]
            
            if not matching_scenarios:
                # Create basic scenario
                return self._create_basic_scenario(skill_level, focus_area)
            
            # Select appropriate scenario (could be random or based on progress)
            selected_scenario = matching_scenarios[0]
            
            self.logger.info(f"Generated {skill_level.value} scenario for {focus_area.value}: {selected_scenario.name}")
            return selected_scenario
            
        except Exception as e:
            self.logger.error(f"Failed to generate training scenario: {e}")
            return self._create_basic_scenario(skill_level, focus_area)
    
    def create_guided_walkthrough(self, vulnerability_type: str) -> Dict[str, Any]:
        """
        Create a guided walkthrough for a specific vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability to create walkthrough for
            
        Returns:
            Structured walkthrough with steps, commands, and explanations
        """
        try:
            walkthrough_templates = {
                "insecure_logging": self._create_logging_walkthrough(),
                "shared_preferences": self._create_shared_prefs_walkthrough(),
                "certificate_pinning": self._create_cert_pinning_walkthrough(),
                "qr_code": self._create_qr_code_walkthrough(),
                "biometric_auth": self._create_biometric_walkthrough(),
                "storage_access": self._create_storage_walkthrough(),
                "network_security": self._create_network_walkthrough()
            }
            
            walkthrough = walkthrough_templates.get(
                vulnerability_type, 
                self._create_generic_walkthrough(vulnerability_type)
            )
            
            self.logger.info(f"Created guided walkthrough for {vulnerability_type}")
            return walkthrough
            
        except Exception as e:
            self.logger.error(f"Failed to create walkthrough: {e}")
            return self._create_generic_walkthrough(vulnerability_type)
    
    def start_interactive_training(self, student_id: str, scenario: TrainingScenario, 
                                  package_name: str) -> Dict[str, Any]:
        """
        Start an interactive training session.
        
        Args:
            student_id: Unique student identifier
            scenario: Training scenario to execute
            package_name: Target application package name
            
        Returns:
            Training session information and progress tracking
        """
        try:
            # Initialize or load student progress
            if student_id not in self.student_progress:
                self.student_progress[student_id] = TrainingProgress(student_id=student_id)
            
            progress = self.student_progress[student_id]
            
            # Create training session
            session_info = {
                "student_id": student_id,
                "scenario": scenario,
                "package_name": package_name,
                "session_script": self._generate_training_script(scenario, package_name),
                "progress_tracker": self._create_progress_tracker(scenario),
                "verification_checklist": self._create_verification_checklist(scenario),
                "help_resources": self._get_help_resources(scenario.focus_area)
            }
            
            self.logger.info(f"Started training session for {student_id}: {scenario.name}")
            return session_info
            
        except Exception as e:
            self.logger.error(f"Failed to start training session: {e}")
            return {"error": str(e)}
    
    def track_training_progress(self, student_id: str, scenario_name: str, 
                               completion_status: str, time_spent: int) -> TrainingProgress:
        """
        Track student training progress.
        
        Args:
            student_id: Student identifier
            scenario_name: Completed scenario name
            completion_status: SUCCESS, PARTIAL, FAILED
            time_spent: Time spent in minutes
            
        Returns:
            Updated training progress
        """
        try:
            if student_id not in self.student_progress:
                self.student_progress[student_id] = TrainingProgress(student_id=student_id)
            
            progress = self.student_progress[student_id]
            
            if completion_status == "SUCCESS":
                if scenario_name not in progress.scenarios_completed:
                    progress.scenarios_completed.append(scenario_name)
                
                # Update skill level based on completed scenarios
                progress.current_skill_level = self._calculate_skill_level(progress.scenarios_completed)
            
            progress.total_practice_time += time_spent
            progress.last_training_date = self._get_current_date()
            
            self.logger.info(f"Updated training progress for {student_id}")
            return progress
            
        except Exception as e:
            self.logger.error(f"Failed to track progress: {e}")
            return self.student_progress.get(student_id, TrainingProgress(student_id=student_id))
    
    def get_personalized_recommendations(self, student_id: str) -> Dict[str, Any]:
        """
        Get personalized training recommendations for a student.
        
        Args:
            student_id: Student identifier
            
        Returns:
            Personalized recommendations and next steps
        """
        try:
            if student_id not in self.student_progress:
                return self._get_beginner_recommendations()
            
            progress = self.student_progress[student_id]
            
            # Analyze current progress
            skill_gaps = self._identify_skill_gaps(progress)
            recommended_scenarios = self._recommend_next_scenarios(progress)
            focus_areas = self._suggest_focus_areas(progress)
            
            recommendations = {
                "current_level": progress.current_skill_level.value,
                "skill_gaps": skill_gaps,
                "recommended_scenarios": recommended_scenarios,
                "suggested_focus_areas": focus_areas,
                "estimated_time_to_next_level": self._estimate_time_to_next_level(progress),
                "achievements": self._get_achievements(progress)
            }
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            return self._get_beginner_recommendations()
    
    def _initialize_training_scenarios(self) -> List[TrainingScenario]:
        """Initialize predefined training scenarios."""
        scenarios = []
        
        # Beginner scenarios
        scenarios.extend([
            TrainingScenario(
                name="Basic Objection Setup",
                skill_level=SkillLevel.BEGINNER,
                focus_area=FocusArea.GENERAL,
                description="Learn to set up and use objection for mobile app testing",
                objectives=[
                    "Install and configure objection",
                    "Connect to target application",
                    "Navigate basic objection commands"
                ],
                commands=[
                    "objection --version",
                    "objection -g <package> explore",
                    "help",
                    "android hooking list classes",
                    "memory list modules"
                ],
                expected_outcomes=[
                    "Successful objection connection",
                    "Basic command execution",
                    "Understanding of objection interface"
                ],
                time_estimate=30,
                difficulty_rating=2
            ),
            
            TrainingScenario(
                name="Logging Analysis Fundamentals",
                skill_level=SkillLevel.BEGINNER,
                focus_area=FocusArea.GENERAL,
                description="Learn to monitor and analyze application logging",
                objectives=[
                    "Identify logging mechanisms",
                    "Hook logging methods",
                    "Extract sensitive information from logs"
                ],
                commands=[
                    "android hooking search methods android.util.Log",
                    "android hooking watch class android.util.Log --dump-args",
                    "jobs list",
                    "jobs kill <job-id>"
                ],
                expected_outcomes=[
                    "Successful method hooking",
                    "Log data extraction",
                    "Identification of sensitive data"
                ],
                time_estimate=45,
                difficulty_rating=3
            )
        ])
        
        # Intermediate scenarios
        scenarios.extend([
            TrainingScenario(
                name="SSL Pinning Bypass",
                skill_level=SkillLevel.INTERMEDIATE,
                focus_area=FocusArea.NETWORK,
                description="Learn to bypass SSL certificate pinning",
                objectives=[
                    "Identify SSL pinning implementation",
                    "Disable certificate validation",
                    "Intercept HTTPS traffic"
                ],
                prerequisites=["Basic hooking knowledge", "Network interception setup"],
                commands=[
                    "android sslpinning disable",
                    "android hooking search methods SSLContext",
                    "android hooking watch class javax.net.ssl.SSLContext",
                    "android proxy set 127.0.0.1 8080"
                ],
                expected_outcomes=[
                    "Successful SSL pinning bypass",
                    "HTTPS traffic interception",
                    "Certificate validation disabled"
                ],
                time_estimate=60,
                difficulty_rating=6
            ),
            
            TrainingScenario(
                name="Biometric Authentication Bypass",
                skill_level=SkillLevel.INTERMEDIATE,
                focus_area=FocusArea.BIOMETRIC,
                description="Learn to analyze and bypass biometric authentication",
                objectives=[
                    "Identify biometric authentication APIs",
                    "Hook authentication callbacks",
                    "Bypass authentication checks"
                ],
                prerequisites=["Method hooking", "Authentication concepts"],
                commands=[
                    "android hooking search methods BiometricPrompt",
                    "android hooking watch class androidx.biometric.BiometricPrompt",
                    "android hooking search methods FingerprintManager",
                    "android keystore list"
                ],
                expected_outcomes=[
                    "Authentication method identification",
                    "Successful callback hooking",
                    "Authentication bypass demonstration"
                ],
                time_estimate=75,
                difficulty_rating=7
            )
        ])
        
        # Advanced scenarios
        scenarios.extend([
            TrainingScenario(
                name="QR Code Security Analysis",
                skill_level=SkillLevel.ADVANCED,
                focus_area=FocusArea.QR_CODE,
                description="Advanced QR code vulnerability testing",
                objectives=[
                    "Identify QR code processing libraries",
                    "Hook QR scanning methods",
                    "Test malicious QR code injection"
                ],
                prerequisites=["Advanced hooking", "QR code security concepts"],
                commands=[
                    "android hooking search methods ZXing",
                    "android hooking watch class com.google.zxing.BarcodeReader",
                    "android intent launch_activity --action android.intent.action.VIEW",
                    "android hooking search classes QR"
                ],
                expected_outcomes=[
                    "QR library identification",
                    "Scanning method hooking",
                    "Malicious payload testing"
                ],
                time_estimate=90,
                difficulty_rating=8
            )
        ])
        
        return scenarios
    
    def _create_basic_scenario(self, skill_level: SkillLevel, focus_area: FocusArea) -> TrainingScenario:
        """Create a basic scenario for given parameters."""
        return TrainingScenario(
            name=f"Basic {focus_area.value.title()} Training",
            skill_level=skill_level,
            focus_area=focus_area,
            description=f"Introduction to {focus_area.value} security testing with objection",
            objectives=[
                f"Learn {focus_area.value} security concepts",
                "Practice basic objection commands",
                "Identify common vulnerabilities"
            ],
            commands=[
                "help",
                "android hooking list classes",
                "memory list modules"
            ],
            expected_outcomes=[
                "Basic command execution",
                "Component identification",
                "Security awareness"
            ],
            time_estimate=30,
            difficulty_rating=2
        )
    
    def _create_logging_walkthrough(self) -> Dict[str, Any]:
        """Create logging vulnerability walkthrough."""
        return {
            "title": "Insecure Logging Analysis Walkthrough",
            "description": "Step-by-step guide to analyzing application logging for sensitive data",
            "steps": [
                {
                    "step": 1,
                    "title": "Identify Logging Methods",
                    "description": "Search for logging classes and methods in the application",
                    "command": "android hooking search methods android.util.Log",
                    "explanation": "This finds all Log class methods used by the application",
                    "expected_output": "List of Log methods (d, i, w, e, v, wtf)"
                },
                {
                    "step": 2,
                    "title": "Hook Logging Methods",
                    "description": "Set up hooks to monitor logging calls",
                    "command": "android hooking watch class android.util.Log --dump-args",
                    "explanation": "This monitors all Log method calls and displays arguments",
                    "expected_output": "Real-time logging data with tag and message"
                },
                {
                    "step": 3,
                    "title": "Analyze Log Content",
                    "description": "Review captured logs for sensitive information",
                    "command": "jobs list",
                    "explanation": "Check active monitoring jobs and their output",
                    "expected_output": "List of active hooks and captured data"
                },
                {
                    "step": 4,
                    "title": "Document Findings",
                    "description": "Record sensitive data found in logs",
                    "command": "# Manual analysis step",
                    "explanation": "Look for passwords, tokens, PII, or other sensitive data",
                    "expected_output": "Evidence of insecure logging practices"
                }
            ],
            "common_issues": [
                "Passwords in debug logs",
                "API tokens in error messages",
                "User PII in log statements",
                "Database queries with sensitive data"
            ],
            "success_criteria": "Identification of sensitive data in application logs"
        }
    
    def _create_shared_prefs_walkthrough(self) -> Dict[str, Any]:
        """Create SharedPreferences walkthrough."""
        return {
            "title": "SharedPreferences Security Analysis",
            "description": "Comprehensive guide to analyzing SharedPreferences storage",
            "steps": [
                {
                    "step": 1,
                    "title": "Locate Preferences Files",
                    "description": "Find SharedPreferences files on the filesystem",
                    "command": "android filesystem find --name *.xml",
                    "explanation": "SharedPreferences are stored as XML files",
                    "expected_output": "List of XML preference files"
                },
                {
                    "step": 2,
                    "title": "Hook SharedPreferences Methods",
                    "description": "Monitor SharedPreferences access",
                    "command": "android hooking watch class android.content.SharedPreferences --dump-args",
                    "explanation": "Monitor read/write operations to preferences",
                    "expected_output": "Real-time preference access logs"
                },
                {
                    "step": 3,
                    "title": "Examine File Contents",
                    "description": "Read preference file contents",
                    "command": "android filesystem cat /data/data/<package>/shared_prefs/<file>.xml",
                    "explanation": "Direct examination of stored preference data",
                    "expected_output": "XML content with key-value pairs"
                }
            ],
            "success_criteria": "Access to sensitive data in SharedPreferences"
        }
    
    def _create_cert_pinning_walkthrough(self) -> Dict[str, Any]:
        """Create certificate pinning walkthrough."""
        return {
            "title": "SSL Certificate Pinning Bypass",
            "description": "Guide to bypassing SSL certificate pinning",
            "steps": [
                {
                    "step": 1,
                    "title": "Disable SSL Pinning",
                    "description": "Use objection's built-in SSL pinning bypass",
                    "command": "android sslpinning disable",
                    "explanation": "Automatically bypass common pinning implementations",
                    "expected_output": "SSL pinning disabled message"
                },
                {
                    "step": 2,
                    "title": "Set Up Proxy",
                    "description": "Configure proxy for traffic interception",
                    "command": "android proxy set 127.0.0.1 8080",
                    "explanation": "Route app traffic through interception proxy",
                    "expected_output": "Proxy configuration confirmed"
                },
                {
                    "step": 3,
                    "title": "Test HTTPS Traffic",
                    "description": "Generate HTTPS requests to verify bypass",
                    "command": "# Trigger app network activity",
                    "explanation": "Use app functionality that makes HTTPS requests",
                    "expected_output": "Successful HTTPS interception"
                }
            ],
            "success_criteria": "Successful HTTPS traffic interception"
        }
    
    def _create_qr_code_walkthrough(self) -> Dict[str, Any]:
        """Create QR code security walkthrough."""
        return {
            "title": "QR Code Security Testing",
            "description": "Advanced QR code vulnerability analysis",
            "steps": [
                {
                    "step": 1,
                    "title": "Identify QR Libraries",
                    "description": "Find QR code processing libraries",
                    "command": "android hooking search methods ZXing",
                    "explanation": "Locate ZXing or other QR processing libraries",
                    "expected_output": "QR code library methods"
                },
                {
                    "step": 2,
                    "title": "Hook QR Processing",
                    "description": "Monitor QR code scanning and processing",
                    "command": "android hooking watch class com.google.zxing.BarcodeReader --dump-args",
                    "explanation": "Monitor QR code decode operations",
                    "expected_output": "QR code content and processing data"
                },
                {
                    "step": 3,
                    "title": "Test Malicious QR Codes",
                    "description": "Test app with malicious QR code payloads",
                    "command": "# Generate and test malicious QR codes",
                    "explanation": "Test various attack vectors via QR codes",
                    "expected_output": "Evidence of QR code vulnerabilities"
                }
            ],
            "success_criteria": "Identification of QR code security issues"
        }
    
    def _create_biometric_walkthrough(self) -> Dict[str, Any]:
        """Create biometric authentication walkthrough."""
        return {
            "title": "Biometric Authentication Analysis",
            "description": "Comprehensive biometric security testing",
            "steps": [
                {
                    "step": 1,
                    "title": "Identify Biometric APIs",
                    "description": "Find biometric authentication implementations",
                    "command": "android hooking search methods BiometricPrompt",
                    "explanation": "Locate modern biometric API usage",
                    "expected_output": "BiometricPrompt methods and callbacks"
                },
                {
                    "step": 2,
                    "title": "Hook Authentication Callbacks",
                    "description": "Monitor authentication success/failure",
                    "command": "android hooking watch class androidx.biometric.BiometricPrompt$AuthenticationCallback",
                    "explanation": "Monitor authentication results",
                    "expected_output": "Authentication callback invocations"
                },
                {
                    "step": 3,
                    "title": "Test Authentication Bypass",
                    "description": "Attempt to bypass biometric authentication",
                    "command": "# Custom hooks for authentication bypass",
                    "explanation": "Implement custom bypass techniques",
                    "expected_output": "Successful authentication bypass"
                }
            ],
            "success_criteria": "Demonstration of biometric bypass techniques"
        }
    
    def _create_storage_walkthrough(self) -> Dict[str, Any]:
        """Create storage security walkthrough."""
        return {
            "title": "Mobile Storage Security Analysis",
            "description": "Comprehensive storage security testing",
            "steps": [
                {
                    "step": 1,
                    "title": "Explore File System",
                    "description": "Map application storage locations",
                    "command": "android filesystem list",
                    "explanation": "Identify all accessible storage areas",
                    "expected_output": "Directory structure and permissions"
                },
                {
                    "step": 2,
                    "title": "Find Sensitive Files",
                    "description": "Search for databases and sensitive files",
                    "command": "android filesystem find --name *.db",
                    "explanation": "Locate database files and other sensitive storage",
                    "expected_output": "List of database and sensitive files"
                }
            ],
            "success_criteria": "Access to sensitive application data"
        }
    
    def _create_network_walkthrough(self) -> Dict[str, Any]:
        """Create network security walkthrough."""
        return {
            "title": "Network Security Testing",
            "description": "Network communication security analysis",
            "steps": [
                {
                    "step": 1,
                    "title": "Identify Network Libraries",
                    "description": "Find HTTP/networking libraries in use",
                    "command": "android hooking search methods HttpURLConnection",
                    "explanation": "Locate network communication methods",
                    "expected_output": "Network library methods"
                },
                {
                    "step": 2,
                    "title": "Monitor Network Calls",
                    "description": "Hook network methods to monitor traffic",
                    "command": "android hooking watch class java.net.HttpURLConnection",
                    "explanation": "Monitor HTTP requests and responses",
                    "expected_output": "Network request/response data"
                }
            ],
            "success_criteria": "Successful network traffic monitoring"
        }
    
    def _create_generic_walkthrough(self, vulnerability_type: str) -> Dict[str, Any]:
        """Create generic walkthrough for unknown vulnerability types."""
        return {
            "title": f"{vulnerability_type.title()} Security Analysis",
            "description": f"General approach to analyzing {vulnerability_type} vulnerabilities",
            "steps": [
                {
                    "step": 1,
                    "title": "Reconnaissance",
                    "description": "Identify relevant classes and methods",
                    "command": "android hooking list classes",
                    "explanation": "Map application components",
                    "expected_output": "List of application classes"
                },
                {
                    "step": 2,
                    "title": "Method Analysis",
                    "description": "Search for relevant methods",
                    "command": f"android hooking search methods {vulnerability_type}",
                    "explanation": "Find methods related to the vulnerability",
                    "expected_output": "Relevant method signatures"
                }
            ],
            "success_criteria": "Understanding of vulnerability scope"
        }
    
    def _generate_training_script(self, scenario: TrainingScenario, package_name: str) -> str:
        """Generate training session script."""
        script = f"""#!/bin/bash
# AODS Training Session: {scenario.name}
# Skill Level: {scenario.skill_level.value}
# Focus Area: {scenario.focus_area.value}
# Package: {package_name}

echo "=== AODS Training Session ==="
echo "Scenario: {scenario.name}"
echo "Description: {scenario.description}"
echo ""

echo "Objectives:"
"""
        for i, objective in enumerate(scenario.objectives, 1):
            script += f'echo "{i}. {objective}"\n'
        
        script += f"""
echo ""
echo "Commands to practice:"
"""
        for i, command in enumerate(scenario.commands, 1):
            script += f'echo "{i}. {command}"\n'
        
        script += f"""
echo ""
echo "Starting objection session..."
objection -g {package_name} explore
"""
        return script
    
    def _create_progress_tracker(self, scenario: TrainingScenario) -> Dict[str, Any]:
        """Create progress tracking structure."""
        return {
            "scenario_name": scenario.name,
            "total_objectives": len(scenario.objectives),
            "completed_objectives": [],
            "verification_steps": scenario.verification_steps,
            "time_limit": scenario.time_estimate,
            "difficulty_rating": scenario.difficulty_rating
        }
    
    def _create_verification_checklist(self, scenario: TrainingScenario) -> List[Dict[str, Any]]:
        """Create verification checklist for scenario."""
        checklist = []
        
        for i, objective in enumerate(scenario.objectives, 1):
            checklist.append({
                "id": f"obj_{i}",
                "objective": objective,
                "completed": False,
                "verification_method": "manual_check",
                "evidence_required": True
            })
        
        return checklist
    
    def _get_help_resources(self, focus_area: FocusArea) -> Dict[str, List[str]]:
        """Get help resources for focus area."""
        resources = {
            FocusArea.GENERAL: [
                "Objection official documentation",
                "OWASP Mobile Testing Guide",
                "Android security fundamentals"
            ],
            FocusArea.CRYPTO: [
                "Android cryptography best practices", 
                "Mobile encryption analysis techniques",
                "Key management security"
            ],
            FocusArea.NETWORK: [
                "HTTPS and SSL/TLS security",
                "Mobile network security testing",
                "Certificate pinning bypass techniques"
            ],
            FocusArea.STORAGE: [
                "Android storage security model",
                "Database security testing",
                "File system permissions"
            ],
            FocusArea.AUTHENTICATION: [
                "Mobile authentication patterns",
                "Biometric security testing",
                "Session management security"
            ],
            FocusArea.QR_CODE: [
                "QR code security vulnerabilities",
                "Input validation testing",
                "Intent injection attacks"
            ],
            FocusArea.BIOMETRIC: [
                "Biometric authentication security",
                "Android biometric APIs",
                "Authentication bypass techniques"
            ]
        }
        
        return {
            "documentation": resources.get(focus_area, resources[FocusArea.GENERAL]),
            "tools": ["objection", "frida", "adb", "burp suite"],
            "communities": ["OWASP Mobile Security", "Android Security Forums", "Frida Community"]
        }
    
    def _calculate_skill_level(self, completed_scenarios: List[str]) -> SkillLevel:
        """Calculate skill level based on completed scenarios."""
        if len(completed_scenarios) >= 10:
            return SkillLevel.EXPERT
        elif len(completed_scenarios) >= 6:
            return SkillLevel.ADVANCED
        elif len(completed_scenarios) >= 3:
            return SkillLevel.INTERMEDIATE
        else:
            return SkillLevel.BEGINNER
    
    def _identify_skill_gaps(self, progress: TrainingProgress) -> List[str]:
        """Identify skill gaps based on progress."""
        # This is a simplified implementation
        all_focus_areas = set(FocusArea)
        mastered_areas = set(progress.focus_areas_mastered)
        
        gaps = all_focus_areas - mastered_areas
        return [area.value for area in gaps]
    
    def _recommend_next_scenarios(self, progress: TrainingProgress) -> List[str]:
        """Recommend next training scenarios."""
        # Find scenarios appropriate for current level that haven't been completed
        available_scenarios = [
            scenario.name for scenario in self.training_scenarios
            if (scenario.skill_level == progress.current_skill_level and 
                scenario.name not in progress.scenarios_completed)
        ]
        
        return available_scenarios[:3]  # Top 3 recommendations
    
    def _suggest_focus_areas(self, progress: TrainingProgress) -> List[str]:
        """Suggest focus areas for improvement."""
        gaps = self._identify_skill_gaps(progress)
        return gaps[:2]  # Top 2 suggestions
    
    def _estimate_time_to_next_level(self, progress: TrainingProgress) -> int:
        """Estimate time needed to reach next skill level (in hours)."""
        current_level_index = list(SkillLevel).index(progress.current_skill_level)
        scenarios_needed = 3  # Scenarios needed to advance
        avg_scenario_time = 45  # minutes
        
        return scenarios_needed * avg_scenario_time // 60  # Convert to hours
    
    def _get_achievements(self, progress: TrainingProgress) -> List[str]:
        """Get student achievements."""
        achievements = []
        
        if len(progress.scenarios_completed) >= 1:
            achievements.append("First Steps - Completed first training scenario")
        if len(progress.scenarios_completed) >= 5:
            achievements.append("Learning Momentum - Completed 5 scenarios")
        if progress.total_practice_time >= 180:  # 3 hours
            achievements.append("Dedicated Learner - 3+ hours of practice")
        if progress.current_skill_level == SkillLevel.ADVANCED:
            achievements.append("Advanced Practitioner - Reached advanced level")
        
        return achievements
    
    def _get_beginner_recommendations(self) -> Dict[str, Any]:
        """Get recommendations for new students."""
        return {
            "current_level": "beginner",
            "skill_gaps": ["All areas - new to mobile security testing"],
            "recommended_scenarios": ["Basic Objection Setup", "Logging Analysis Fundamentals"],
            "suggested_focus_areas": ["general", "storage"],
            "estimated_time_to_next_level": 3,
            "achievements": []
        }
    
    def _get_current_date(self) -> str:
        """Get current date string."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
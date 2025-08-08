#!/usr/bin/env python3
"""
User Feedback Integration System for AODS Learning Framework

Provides comprehensive user feedback integration allowing security experts to
validate findings, provide feedback, and contribute to continuous learning
system improvement. Supports multiple feedback types and validation methods.

Key Features:
- Expert validation and feedback collection
- Multi-level feedback types (finding validation, pattern accuracy, false positive reporting)
- Confidence adjustment based on expert feedback
- Validation tracking and learning integration
- Feedback analytics and reporting
- Real-time learning system updates
- Expert reputation and weighting system
- Collaborative validation platform

"""

import logging
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from pathlib import Path
import statistics
from collections import defaultdict, deque
from enum import Enum
import hashlib

from .analysis_exceptions import FeedbackError, ErrorContext, ContextualLogger
from .pattern_reliability_database import PatternReliabilityDatabase, ValidationRecord, create_validation_record
from .learning_system import ConfidenceLearningSystem, LearningMetrics

class FeedbackType(Enum):
    """Types of feedback that can be provided."""
    FINDING_VALIDATION = "finding_validation"
    PATTERN_ACCURACY = "pattern_accuracy"
    FALSE_POSITIVE_REPORT = "false_positive_report"
    FALSE_NEGATIVE_REPORT = "false_negative_report"
    CONFIDENCE_ASSESSMENT = "confidence_assessment"
    GENERAL_FEEDBACK = "general_feedback"

class ValidationStatus(Enum):
    """Status of validation feedback."""
    PENDING = "pending"
    VALIDATED = "validated"
    DISPUTED = "disputed"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"

class ExpertLevel(Enum):
    """Expert experience levels for feedback weighting."""
    JUNIOR = "junior"
    INTERMEDIATE = "intermediate"
    SENIOR = "senior"
    EXPERT = "expert"
    LEAD = "lead"

@dataclass
class ExpertProfile:
    """Profile of a security expert providing feedback."""
    expert_id: str
    name: str
    email: str
    expert_level: ExpertLevel
    specializations: List[str] = field(default_factory=list)
    validation_count: int = 0
    accuracy_rate: float = 0.0
    reputation_score: float = 0.0
    feedback_weight: float = 1.0
    last_active: datetime = field(default_factory=datetime.now)
    created_at: datetime = field(default_factory=datetime.now)
    
    def calculate_feedback_weight(self) -> float:
        """Calculate feedback weight based on expert profile."""
        # Base weight by level
        level_weights = {
            ExpertLevel.JUNIOR: 0.5,
            ExpertLevel.INTERMEDIATE: 0.7,
            ExpertLevel.SENIOR: 1.0,
            ExpertLevel.EXPERT: 1.3,
            ExpertLevel.LEAD: 1.5
        }
        
        base_weight = level_weights[self.expert_level]
        
        # Adjust for accuracy and reputation
        accuracy_bonus = (self.accuracy_rate - 0.5) * 0.5  # +/- 0.25
        reputation_bonus = (self.reputation_score - 0.5) * 0.3  # +/- 0.15
        
        # Adjust for experience (validation count)
        experience_bonus = min(0.2, self.validation_count / 100.0 * 0.2)
        
        final_weight = base_weight + accuracy_bonus + reputation_bonus + experience_bonus
        return max(0.1, min(2.0, final_weight))  # Clamp between 0.1 and 2.0

@dataclass
class FeedbackEntry:
    """Individual feedback entry from a security expert."""
    feedback_id: str
    expert_id: str
    feedback_type: FeedbackType
    finding_id: str
    pattern_id: str
    
    # Feedback content
    is_accurate: bool
    confidence_assessment: Optional[float] = None
    comments: str = ""
    suggested_confidence: Optional[float] = None
    
    # Metadata
    feedback_timestamp: datetime = field(default_factory=datetime.now)
    validation_method: str = "manual_review"
    evidence_provided: Dict[str, Any] = field(default_factory=dict)
    
    # Status tracking
    status: ValidationStatus = ValidationStatus.PENDING
    processed: bool = False
    processing_timestamp: Optional[datetime] = None
    
    # Quality metrics
    feedback_quality_score: float = 0.0
    agreement_with_peers: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert feedback entry to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat() if value else None
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result

@dataclass
class FeedbackSummary:
    """Summary of feedback for a specific finding or pattern."""
    target_id: str  # finding_id or pattern_id
    target_type: str  # "finding" or "pattern"
    
    total_feedback_count: int = 0
    positive_feedback_count: int = 0
    negative_feedback_count: int = 0
    
    average_confidence_assessment: float = 0.0
    consensus_level: float = 0.0
    expert_agreement: float = 0.0
    
    feedback_entries: List[FeedbackEntry] = field(default_factory=list)
    
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def positive_ratio(self) -> float:
        """Calculate positive feedback ratio."""
        if self.total_feedback_count == 0:
            return 0.0
        return self.positive_feedback_count / self.total_feedback_count
    
    @property
    def confidence_in_assessment(self) -> float:
        """Calculate confidence in the assessment based on agreement."""
        if self.total_feedback_count < 2:
            return 0.5
        
        # High consensus and agreement = high confidence
        return (self.consensus_level + self.expert_agreement) / 2

class FeedbackDatabase:
    """
    Database for storing and managing user feedback.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize feedback database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Path("data/user_feedback.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = ContextualLogger("feedback_database")
        self._lock = threading.Lock()
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Expert profiles table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS expert_profiles (
                    expert_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    expert_level TEXT NOT NULL,
                    specializations TEXT DEFAULT '[]',
                    validation_count INTEGER DEFAULT 0,
                    accuracy_rate REAL DEFAULT 0.0,
                    reputation_score REAL DEFAULT 0.0,
                    feedback_weight REAL DEFAULT 1.0,
                    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Feedback entries table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback_entries (
                    feedback_id TEXT PRIMARY KEY,
                    expert_id TEXT NOT NULL,
                    feedback_type TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    pattern_id TEXT NOT NULL,
                    is_accurate BOOLEAN NOT NULL,
                    confidence_assessment REAL,
                    comments TEXT DEFAULT '',
                    suggested_confidence REAL,
                    feedback_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    validation_method TEXT DEFAULT 'manual_review',
                    evidence_provided TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'pending',
                    processed BOOLEAN DEFAULT 0,
                    processing_timestamp TIMESTAMP,
                    feedback_quality_score REAL DEFAULT 0.0,
                    agreement_with_peers REAL DEFAULT 0.0,
                    FOREIGN KEY (expert_id) REFERENCES expert_profiles (expert_id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_expert ON feedback_entries (expert_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_finding ON feedback_entries (finding_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_pattern ON feedback_entries (pattern_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback_entries (feedback_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON feedback_entries (feedback_timestamp)")
            
            conn.commit()
        
        self.logger.info(f"Initialized feedback database: {self.db_path}")
    
    def register_expert(self, expert: ExpertProfile):
        """Register a new expert in the system."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO expert_profiles 
                (expert_id, name, email, expert_level, specializations, validation_count,
                 accuracy_rate, reputation_score, feedback_weight, last_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                expert.expert_id,
                expert.name,
                expert.email,
                expert.expert_level.value,
                json.dumps(expert.specializations),
                expert.validation_count,
                expert.accuracy_rate,
                expert.reputation_score,
                expert.feedback_weight,
                expert.last_active.isoformat(),
                expert.created_at.isoformat()
            ))
            
            conn.commit()
        
        self.logger.info(f"Registered expert: {expert.name} ({expert.expert_id})")
    
    def get_expert_profile(self, expert_id: str) -> Optional[ExpertProfile]:
        """Get expert profile by ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM expert_profiles WHERE expert_id = ?", (expert_id,))
            row = cursor.fetchone()
            
            if row:
                return ExpertProfile(
                    expert_id=row[0],
                    name=row[1],
                    email=row[2],
                    expert_level=ExpertLevel(row[3]),
                    specializations=json.loads(row[4]),
                    validation_count=row[5],
                    accuracy_rate=row[6],
                    reputation_score=row[7],
                    feedback_weight=row[8],
                    last_active=datetime.fromisoformat(row[9]),
                    created_at=datetime.fromisoformat(row[10])
                )
        
        return None
    
    def record_feedback(self, feedback: FeedbackEntry):
        """Record feedback entry in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO feedback_entries 
                (feedback_id, expert_id, feedback_type, finding_id, pattern_id,
                 is_accurate, confidence_assessment, comments, suggested_confidence,
                 feedback_timestamp, validation_method, evidence_provided, status,
                 processed, processing_timestamp, feedback_quality_score, agreement_with_peers)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                feedback.feedback_id,
                feedback.expert_id,
                feedback.feedback_type.value,
                feedback.finding_id,
                feedback.pattern_id,
                feedback.is_accurate,
                feedback.confidence_assessment,
                feedback.comments,
                feedback.suggested_confidence,
                feedback.feedback_timestamp.isoformat(),
                feedback.validation_method,
                json.dumps(feedback.evidence_provided),
                feedback.status.value,
                feedback.processed,
                feedback.processing_timestamp.isoformat() if feedback.processing_timestamp else None,
                feedback.feedback_quality_score,
                feedback.agreement_with_peers
            ))
            
            conn.commit()
        
        self.logger.debug(f"Recorded feedback: {feedback.feedback_id}")
    
    def get_feedback_for_finding(self, finding_id: str) -> List[FeedbackEntry]:
        """Get all feedback for a specific finding."""
        feedback_entries = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM feedback_entries WHERE finding_id = ?", (finding_id,))
            
            for row in cursor.fetchall():
                feedback = self._row_to_feedback_entry(row)
                feedback_entries.append(feedback)
        
        return feedback_entries
    
    def get_feedback_for_pattern(self, pattern_id: str) -> List[FeedbackEntry]:
        """Get all feedback for a specific pattern."""
        feedback_entries = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM feedback_entries WHERE pattern_id = ?", (pattern_id,))
            
            for row in cursor.fetchall():
                feedback = self._row_to_feedback_entry(row)
                feedback_entries.append(feedback)
        
        return feedback_entries
    
    def get_unprocessed_feedback(self) -> List[FeedbackEntry]:
        """Get all unprocessed feedback entries."""
        feedback_entries = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM feedback_entries WHERE processed = 0")
            
            for row in cursor.fetchall():
                feedback = self._row_to_feedback_entry(row)
                feedback_entries.append(feedback)
        
        return feedback_entries
    
    def mark_feedback_processed(self, feedback_id: str):
        """Mark feedback as processed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE feedback_entries 
                SET processed = 1, processing_timestamp = ? 
                WHERE feedback_id = ?
            """, (datetime.now().isoformat(), feedback_id))
            
            conn.commit()
    
    def update_expert_statistics(self, expert_id: str, validation_count: int, accuracy_rate: float):
        """Update expert statistics."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE expert_profiles 
                SET validation_count = ?, accuracy_rate = ?, last_active = ?
                WHERE expert_id = ?
            """, (validation_count, accuracy_rate, datetime.now().isoformat(), expert_id))
            
            conn.commit()
    
    def _row_to_feedback_entry(self, row: Tuple) -> FeedbackEntry:
        """Convert database row to FeedbackEntry."""
        return FeedbackEntry(
            feedback_id=row[0],
            expert_id=row[1],
            feedback_type=FeedbackType(row[2]),
            finding_id=row[3],
            pattern_id=row[4],
            is_accurate=row[5],
            confidence_assessment=row[6],
            comments=row[7],
            suggested_confidence=row[8],
            feedback_timestamp=datetime.fromisoformat(row[9]),
            validation_method=row[10],
            evidence_provided=json.loads(row[11]),
            status=ValidationStatus(row[12]),
            processed=row[13],
            processing_timestamp=datetime.fromisoformat(row[14]) if row[14] else None,
            feedback_quality_score=row[15],
            agreement_with_peers=row[16]
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get feedback database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_feedback,
                    COUNT(CASE WHEN processed = 1 THEN 1 END) as processed_feedback,
                    COUNT(CASE WHEN is_accurate = 1 THEN 1 END) as positive_feedback,
                    COUNT(DISTINCT expert_id) as unique_experts,
                    AVG(confidence_assessment) as avg_confidence_assessment
                FROM feedback_entries
            """)
            
            stats = cursor.fetchone()
            
            return {
                'total_feedback': stats[0],
                'processed_feedback': stats[1],
                'positive_feedback': stats[2],
                'unique_experts': stats[3],
                'avg_confidence_assessment': stats[4] or 0.0,
                'processing_rate': stats[1] / max(stats[0], 1)
            }

class FeedbackAnalyzer:
    """
    Analyzes feedback patterns and generates insights.
    """
    
    def __init__(self, feedback_db: FeedbackDatabase):
        """
        Initialize feedback analyzer.
        
        Args:
            feedback_db: Feedback database instance
        """
        self.feedback_db = feedback_db
        self.logger = ContextualLogger("feedback_analyzer")
    
    def analyze_finding_feedback(self, finding_id: str) -> FeedbackSummary:
        """Analyze feedback for a specific finding."""
        feedback_entries = self.feedback_db.get_feedback_for_finding(finding_id)
        
        if not feedback_entries:
            return FeedbackSummary(
                target_id=finding_id,
                target_type="finding"
            )
        
        # Calculate basic statistics
        total_count = len(feedback_entries)
        positive_count = sum(1 for f in feedback_entries if f.is_accurate)
        negative_count = total_count - positive_count
        
        # Calculate weighted averages
        confidence_assessments = [f.confidence_assessment for f in feedback_entries if f.confidence_assessment is not None]
        avg_confidence = statistics.mean(confidence_assessments) if confidence_assessments else 0.0
        
        # Calculate consensus level
        consensus_level = self._calculate_consensus_level(feedback_entries)
        
        # Calculate expert agreement
        expert_agreement = self._calculate_expert_agreement(feedback_entries)
        
        return FeedbackSummary(
            target_id=finding_id,
            target_type="finding",
            total_feedback_count=total_count,
            positive_feedback_count=positive_count,
            negative_feedback_count=negative_count,
            average_confidence_assessment=avg_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            feedback_entries=feedback_entries
        )
    
    def analyze_pattern_feedback(self, pattern_id: str) -> FeedbackSummary:
        """Analyze feedback for a specific pattern."""
        feedback_entries = self.feedback_db.get_feedback_for_pattern(pattern_id)
        
        if not feedback_entries:
            return FeedbackSummary(
                target_id=pattern_id,
                target_type="pattern"
            )
        
        # Calculate statistics similar to finding feedback
        total_count = len(feedback_entries)
        positive_count = sum(1 for f in feedback_entries if f.is_accurate)
        negative_count = total_count - positive_count
        
        confidence_assessments = [f.confidence_assessment for f in feedback_entries if f.confidence_assessment is not None]
        avg_confidence = statistics.mean(confidence_assessments) if confidence_assessments else 0.0
        
        consensus_level = self._calculate_consensus_level(feedback_entries)
        expert_agreement = self._calculate_expert_agreement(feedback_entries)
        
        return FeedbackSummary(
            target_id=pattern_id,
            target_type="pattern",
            total_feedback_count=total_count,
            positive_feedback_count=positive_count,
            negative_feedback_count=negative_count,
            average_confidence_assessment=avg_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            feedback_entries=feedback_entries
        )
    
    def _calculate_consensus_level(self, feedback_entries: List[FeedbackEntry]) -> float:
        """Calculate consensus level among feedback entries."""
        if len(feedback_entries) < 2:
            return 0.5
        
        # Calculate how much experts agree
        positive_count = sum(1 for f in feedback_entries if f.is_accurate)
        negative_count = len(feedback_entries) - positive_count
        
        # Consensus is high when most experts agree
        max_agreement = max(positive_count, negative_count)
        consensus = max_agreement / len(feedback_entries)
        
        return consensus
    
    def _calculate_expert_agreement(self, feedback_entries: List[FeedbackEntry]) -> float:
        """Calculate expert agreement based on their weights."""
        if len(feedback_entries) < 2:
            return 0.5
        
        # Weight feedback by expert reputation
        weighted_positive = 0.0
        weighted_negative = 0.0
        total_weight = 0.0
        
        for feedback in feedback_entries:
            expert = self.feedback_db.get_expert_profile(feedback.expert_id)
            weight = expert.feedback_weight if expert else 1.0
            
            total_weight += weight
            if feedback.is_accurate:
                weighted_positive += weight
            else:
                weighted_negative += weight
        
        if total_weight == 0:
            return 0.5
        
        # Agreement is the proportion of the stronger side
        max_weighted = max(weighted_positive, weighted_negative)
        agreement = max_weighted / total_weight
        
        return agreement
    
    def generate_feedback_insights(self) -> Dict[str, Any]:
        """Generate insights from all feedback."""
        stats = self.feedback_db.get_statistics()
        
        insights = {
            'overall_statistics': stats,
            'feedback_quality': {
                'processing_rate': stats['processing_rate'],
                'positive_feedback_rate': stats['positive_feedback'] / max(stats['total_feedback'], 1),
                'expert_engagement': stats['unique_experts']
            },
            'recommendations': []
        }
        
        # Generate recommendations
        if stats['processing_rate'] < 0.8:
            insights['recommendations'].append("Low feedback processing rate. Consider automated processing for simple cases.")
        
        if stats['positive_feedback'] / max(stats['total_feedback'], 1) < 0.6:
            insights['recommendations'].append("High negative feedback rate. Review pattern accuracy and confidence calculation.")
        
        if stats['unique_experts'] < 5:
            insights['recommendations'].append("Low expert engagement. Consider expanding expert network.")
        
        return insights

class UserFeedbackIntegration:
    """
    Main user feedback integration system.
    """
    
    def __init__(self, 
                 reliability_db: PatternReliabilityDatabase,
                 learning_system: Optional[ConfidenceLearningSystem] = None):
        """
        Initialize user feedback integration.
        
        Args:
            reliability_db: Pattern reliability database
            learning_system: Learning system for integration
        """
        self.reliability_db = reliability_db
        self.learning_system = learning_system
        self.feedback_db = FeedbackDatabase()
        self.feedback_analyzer = FeedbackAnalyzer(self.feedback_db)
        self.logger = ContextualLogger("user_feedback_integration")
        
        # Processing parameters
        self.processing_interval = timedelta(hours=1)
        self.last_processing = datetime.now()
        self.auto_processing = True
        
        # Background processing
        self._processing_thread = None
        self._stop_processing = threading.Event()
        
        # Start background processing
        self._start_background_processing()
    
    def register_expert(self, name: str, email: str, level: ExpertLevel, specializations: List[str] = None) -> str:
        """
        Register a new expert in the system.
        
        Args:
            name: Expert name
            email: Expert email
            level: Expert level
            specializations: List of specializations
            
        Returns:
            Expert ID
        """
        expert_id = self._generate_expert_id(name, email)
        
        expert = ExpertProfile(
            expert_id=expert_id,
            name=name,
            email=email,
            expert_level=level,
            specializations=specializations or [],
            feedback_weight=ExpertProfile.calculate_feedback_weight(ExpertProfile(
                expert_id="", name="", email="", expert_level=level
            ))
        )
        
        self.feedback_db.register_expert(expert)
        
        self.logger.info(f"Registered expert: {name} ({expert_id})")
        return expert_id
    
    def submit_feedback(self, 
                       expert_id: str,
                       feedback_type: FeedbackType,
                       finding_id: str,
                       pattern_id: str,
                       is_accurate: bool,
                       confidence_assessment: Optional[float] = None,
                       comments: str = "",
                       suggested_confidence: Optional[float] = None,
                       evidence: Dict[str, Any] = None) -> str:
        """
        Submit feedback from an expert.
        
        Args:
            expert_id: Expert identifier
            feedback_type: Type of feedback
            finding_id: Finding identifier
            pattern_id: Pattern identifier
            is_accurate: Whether finding is accurate
            confidence_assessment: Expert's confidence assessment
            comments: Additional comments
            suggested_confidence: Suggested confidence score
            evidence: Supporting evidence
            
        Returns:
            Feedback ID
        """
        feedback_id = self._generate_feedback_id()
        
        feedback = FeedbackEntry(
            feedback_id=feedback_id,
            expert_id=expert_id,
            feedback_type=feedback_type,
            finding_id=finding_id,
            pattern_id=pattern_id,
            is_accurate=is_accurate,
            confidence_assessment=confidence_assessment,
            comments=comments,
            suggested_confidence=suggested_confidence,
            evidence_provided=evidence or {}
        )
        
        self.feedback_db.record_feedback(feedback)
        
        # Update expert activity
        expert = self.feedback_db.get_expert_profile(expert_id)
        if expert:
            expert.last_active = datetime.now()
            self.feedback_db.register_expert(expert)
        
        self.logger.info(f"Submitted feedback: {feedback_id} from expert {expert_id}")
        return feedback_id
    
    def process_feedback(self, feedback_id: Optional[str] = None):
        """
        Process feedback and update learning system.
        
        Args:
            feedback_id: Specific feedback ID to process, or None for all unprocessed
        """
        if feedback_id:
            # Process specific feedback
            feedback_entries = [self.feedback_db.get_feedback_for_finding(feedback_id)]
        else:
            # Process all unprocessed feedback
            feedback_entries = self.feedback_db.get_unprocessed_feedback()
        
        for feedback in feedback_entries:
            if feedback:
                self._process_single_feedback(feedback)
    
    def _process_single_feedback(self, feedback: FeedbackEntry):
        """Process a single feedback entry."""
        try:
            # Create validation record for learning system
            if self.learning_system:
                self.learning_system.record_validation_result(
                    pattern_id=feedback.pattern_id,
                    finding_id=feedback.finding_id,
                    predicted_confidence=feedback.confidence_assessment or 0.5,
                    actual_vulnerability=feedback.is_accurate,
                    context={'expert_validation': True, 'expert_id': feedback.expert_id},
                    validator_id=feedback.expert_id
                )
            
            # Update pattern reliability if significant feedback
            if feedback.suggested_confidence is not None:
                self._update_pattern_reliability(feedback)
            
            # Mark as processed
            self.feedback_db.mark_feedback_processed(feedback.feedback_id)
            
            # Update expert statistics
            self._update_expert_statistics(feedback.expert_id)
            
            self.logger.debug(f"Processed feedback: {feedback.feedback_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to process feedback {feedback.feedback_id}: {e}")
    
    def _update_pattern_reliability(self, feedback: FeedbackEntry):
        """Update pattern reliability based on feedback."""
        pattern = self.reliability_db.get_pattern_reliability(feedback.pattern_id)
        
        if pattern:
            # Update pattern with expert feedback
            expert = self.feedback_db.get_expert_profile(feedback.expert_id)
            weight = expert.feedback_weight if expert else 1.0
            
            # Weighted adjustment
            adjustment_key = f"expert_feedback_{feedback.expert_id}"
            pattern.confidence_adjustments[adjustment_key] = feedback.suggested_confidence * weight
            
            # Update context factors
            pattern.context_factors['expert_validation'] = feedback.is_accurate
            pattern.context_factors['expert_confidence'] = feedback.confidence_assessment or 0.5
            
            # Save updated pattern
            self.reliability_db.save_pattern_reliability(pattern)
    
    def _update_expert_statistics(self, expert_id: str):
        """Update expert statistics based on feedback accuracy."""
        expert = self.feedback_db.get_expert_profile(expert_id)
        if not expert:
            return
        
        # Get all feedback from this expert
        all_feedback = []
        with sqlite3.connect(self.feedback_db.db_path) as conn:
            cursor = conn.execute("SELECT * FROM feedback_entries WHERE expert_id = ?", (expert_id,))
            for row in cursor.fetchall():
                all_feedback.append(self.feedback_db._row_to_feedback_entry(row))
        
        # Calculate accuracy rate
        if all_feedback:
            # This would require comparing expert predictions with actual outcomes
            # For now, use a simplified calculation
            expert.validation_count = len(all_feedback)
            expert.accuracy_rate = sum(1 for f in all_feedback if f.is_accurate) / len(all_feedback)
            expert.feedback_weight = expert.calculate_feedback_weight()
            
            # Update in database
            self.feedback_db.update_expert_statistics(
                expert_id, expert.validation_count, expert.accuracy_rate
            )
    
    def _start_background_processing(self):
        """Start background processing thread."""
        if self.auto_processing:
            self._processing_thread = threading.Thread(target=self._background_processing, daemon=True)
            self._processing_thread.start()
    
    def _background_processing(self):
        """Background processing loop."""
        while not self._stop_processing.is_set():
            try:
                # Check if it's time to process
                if datetime.now() - self.last_processing > self.processing_interval:
                    self.process_feedback()
                    self.last_processing = datetime.now()
                
                # Sleep for a short interval
                self._stop_processing.wait(timeout=300)  # 5 minutes
                
            except Exception as e:
                self.logger.error(f"Background processing error: {e}")
                self._stop_processing.wait(timeout=3600)  # 1 hour on error
    
    def stop_background_processing(self):
        """Stop background processing."""
        self._stop_processing.set()
        if self._processing_thread:
            self._processing_thread.join(timeout=10)
    
    def get_feedback_summary(self, target_id: str, target_type: str) -> FeedbackSummary:
        """Get feedback summary for a finding or pattern."""
        if target_type == "finding":
            return self.feedback_analyzer.analyze_finding_feedback(target_id)
        elif target_type == "pattern":
            return self.feedback_analyzer.analyze_pattern_feedback(target_id)
        else:
            raise ValueError(f"Invalid target type: {target_type}")
    
    def generate_feedback_report(self) -> Dict[str, Any]:
        """Generate comprehensive feedback report."""
        stats = self.feedback_db.get_statistics()
        insights = self.feedback_analyzer.generate_feedback_insights()
        
        return {
            'report_generated': datetime.now().isoformat(),
            'statistics': stats,
            'insights': insights,
            'system_status': {
                'auto_processing': self.auto_processing,
                'last_processing': self.last_processing.isoformat(),
                'processing_interval_hours': self.processing_interval.total_seconds() / 3600
            }
        }
    
    def _generate_expert_id(self, name: str, email: str) -> str:
        """Generate unique expert ID."""
        # Create hash from name and email
        hash_input = f"{name}:{email}:{datetime.now().isoformat()}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]
    
    def _generate_feedback_id(self) -> str:
        """Generate unique feedback ID."""
        return str(uuid.uuid4())

# Factory functions for integration
def create_user_feedback_integration(reliability_db: PatternReliabilityDatabase,
                                   learning_system: Optional[ConfidenceLearningSystem] = None) -> UserFeedbackIntegration:
    """Create user feedback integration system."""
    return UserFeedbackIntegration(reliability_db, learning_system)

def initialize_feedback_system(reliability_db: PatternReliabilityDatabase,
                              learning_system: Optional[ConfidenceLearningSystem] = None) -> Dict[str, Any]:
    """Initialize complete feedback system."""
    feedback_integration = create_user_feedback_integration(reliability_db, learning_system)
    
    # Register demo expert
    demo_expert_id = feedback_integration.register_expert(
        name="Demo Security Expert",
        email="demo@example.com",
        level=ExpertLevel.SENIOR,
        specializations=["mobile_security", "cryptography", "network_security"]
    )
    
    # Generate initial report
    report = feedback_integration.generate_feedback_report()
    
    return {
        'feedback_integration': feedback_integration,
        'demo_expert_id': demo_expert_id,
        'initial_report': report,
        'status': 'initialized'
    } 
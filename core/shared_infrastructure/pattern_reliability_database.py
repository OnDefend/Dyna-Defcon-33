"""
AODS Pattern Reliability Database

Provides historical accuracy tracking for all security patterns to enable
continuous improvement and evidence-based confidence calculation.

Features:
- Historical false positive/negative rate tracking
- Pattern accuracy measurement and calibration
- Context-aware reliability scoring
- Real-time confidence adjustment
- Performance trend analysis
- Machine learning integration readiness
"""

import sqlite3
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
from collections import defaultdict, deque
import pickle

from .analysis_exceptions import AODSAnalysisError, ErrorContext, ContextualLogger

logger = logging.getLogger(__name__)

@dataclass
class PatternReliability:
    """Historical reliability data for a security pattern."""
    pattern_id: str
    pattern_name: str
    pattern_category: str
    total_matches: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    context_factors: Dict[str, float] = None
    accuracy_trend: List[float] = None
    last_updated: datetime = None
    confidence_adjustments: Dict[str, float] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.context_factors is None:
            self.context_factors = {}
        if self.accuracy_trend is None:
            self.accuracy_trend = []
        if self.last_updated is None:
            self.last_updated = datetime.now()
        if self.confidence_adjustments is None:
            self.confidence_adjustments = {}
    
    @property
    def accuracy_rate(self) -> float:
        """Calculate accuracy rate (correct predictions / total predictions)."""
        total_predictions = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total_predictions == 0:
            return 0.5  # Neutral default for new patterns
        
        correct_predictions = self.true_positives + self.true_negatives
        return correct_predictions / total_predictions
    
    @property
    def precision(self) -> float:
        """Calculate precision (true positives / (true positives + false positives))."""
        if self.true_positives + self.false_positives == 0:
            return 0.5  # Neutral default
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        """Calculate recall (true positives / (true positives + false negatives))."""
        if self.true_positives + self.false_negatives == 0:
            return 0.5  # Neutral default
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        """Calculate F1 score (harmonic mean of precision and recall)."""
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)
    
    @property
    def false_positive_rate(self) -> float:
        """Calculate false positive rate."""
        if self.false_positives + self.true_negatives == 0:
            return 0.0
        return self.false_positives / (self.false_positives + self.true_negatives)
    
    @property
    def reliability_score(self) -> float:
        """
        Calculate overall reliability score based on multiple metrics.
        
        Combines accuracy, precision, recall, and considers the number of samples
        to provide a robust reliability measure.
        """
        # Base reliability from accuracy
        base_reliability = self.accuracy_rate
        
        # Adjust for precision and recall balance
        balance_factor = min(self.precision, self.recall) / max(self.precision, self.recall, 0.01)
        
        # Adjust for sample size (more samples = higher confidence)
        sample_size_factor = min(1.0, self.total_matches / 100.0)  # Plateau at 100 samples
        
        # Combine factors
        reliability = base_reliability * (0.7 + 0.2 * balance_factor + 0.1 * sample_size_factor)
        
        # Apply false positive penalty
        fp_penalty = 1.0 - (self.false_positive_rate * 0.3)  # Max 30% penalty
        
        return max(0.1, min(1.0, reliability * fp_penalty))
    
    def update_accuracy(self, correct: bool, context: Dict[str, Any] = None):
        """
        Update accuracy statistics with new validation result.
        
        Args:
            correct: Whether the pattern detection was correct
            context: Additional context for the validation
        """
        self.total_matches += 1
        
        if correct:
            self.true_positives += 1
        else:
            self.false_positives += 1
        
        # Update trend
        current_accuracy = self.accuracy_rate
        self.accuracy_trend.append(current_accuracy)
        
        # Keep only last 100 accuracy points
        if len(self.accuracy_trend) > 100:
            self.accuracy_trend = self.accuracy_trend[-100:]
        
        # Update context factors if provided
        if context:
            for key, value in context.items():
                if isinstance(value, (int, float)):
                    # Running average of context factors
                    if key in self.context_factors:
                        self.context_factors[key] = (self.context_factors[key] + value) / 2
                    else:
                        self.context_factors[key] = value
        
        self.last_updated = datetime.now()
    
    def get_confidence_adjustment(self, context: Dict[str, Any] = None) -> float:
        """
        Get confidence adjustment factor based on pattern reliability and context.
        
        Args:
            context: Current analysis context
            
        Returns:
            Confidence adjustment factor (0.1 to 1.0)
        """
        base_adjustment = self.reliability_score
        
        # Apply context-specific adjustments
        if context and self.context_factors:
            context_adjustment = 1.0
            context_matches = 0
            
            for key, expected_value in self.context_factors.items():
                if key in context:
                    actual_value = context[key]
                    if isinstance(actual_value, (int, float)) and isinstance(expected_value, (int, float)):
                        # Calculate similarity between expected and actual values
                        similarity = 1.0 - abs(actual_value - expected_value) / max(abs(expected_value), 1.0)
                        context_adjustment += similarity
                        context_matches += 1
            
            if context_matches > 0:
                context_adjustment = context_adjustment / (context_matches + 1)  # Average including base
                base_adjustment = (base_adjustment + context_adjustment) / 2
        
        return max(0.1, min(1.0, base_adjustment))

@dataclass 
class ValidationRecord:
    """Record of a validation result for learning."""
    record_id: str
    pattern_id: str
    finding_id: str
    predicted_vulnerability: bool
    actual_vulnerability: bool
    confidence_score: float
    context: Dict[str, Any]
    validation_timestamp: datetime
    validator_id: str  # Who/what validated this
    validation_method: str  # How it was validated
    
    @property
    def is_correct(self) -> bool:
        """Check if the prediction was correct."""
        return self.predicted_vulnerability == self.actual_vulnerability
    
    @property
    def is_true_positive(self) -> bool:
        """Check if this is a true positive."""
        return self.predicted_vulnerability and self.actual_vulnerability
    
    @property
    def is_false_positive(self) -> bool:
        """Check if this is a false positive."""
        return self.predicted_vulnerability and not self.actual_vulnerability
    
    @property
    def is_true_negative(self) -> bool:
        """Check if this is a true negative."""
        return not self.predicted_vulnerability and not self.actual_vulnerability
    
    @property
    def is_false_negative(self) -> bool:
        """Check if this is a false negative."""
        return not self.predicted_vulnerability and self.actual_vulnerability

class PatternReliabilityDatabase:
    """
    Database for storing and managing pattern reliability information.
    
    Provides persistent storage for pattern accuracy metrics with
    efficient queries and updates for real-time confidence calculation.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize pattern reliability database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Path("data/pattern_reliability.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._lock = threading.Lock()
        self.logger = ContextualLogger("pattern_reliability_db")
        
        # In-memory cache for frequently accessed patterns
        self.cache: Dict[str, PatternReliability] = {}
        self.cache_max_size = 1000
        self.cache_access_order = deque()
        
        # Initialize database
        self._init_database()
        self._load_cache()
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pattern_reliability (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_name TEXT NOT NULL,
                    pattern_category TEXT NOT NULL,
                    total_matches INTEGER DEFAULT 0,
                    true_positives INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    true_negatives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    context_factors TEXT DEFAULT '{}',
                    accuracy_trend TEXT DEFAULT '[]',
                    confidence_adjustments TEXT DEFAULT '{}',
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS validation_records (
                    record_id TEXT PRIMARY KEY,
                    pattern_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    predicted_vulnerability BOOLEAN NOT NULL,
                    actual_vulnerability BOOLEAN NOT NULL,
                    confidence_score REAL NOT NULL,
                    context TEXT DEFAULT '{}',
                    validation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    validator_id TEXT NOT NULL,
                    validation_method TEXT NOT NULL,
                    FOREIGN KEY (pattern_id) REFERENCES pattern_reliability (pattern_id)
                )
            """)
            
            # Create indexes for better query performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pattern_category ON pattern_reliability (pattern_category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_pattern ON validation_records (pattern_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_timestamp ON validation_records (validation_timestamp)")
            
            conn.commit()
        
        self.logger.info(f"Initialized pattern reliability database: {self.db_path}")
    
    def _load_cache(self):
        """Load frequently used patterns into cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM pattern_reliability 
                ORDER BY total_matches DESC 
                LIMIT ?
            """, (self.cache_max_size // 2,))
            
            for row in cursor.fetchall():
                pattern = self._row_to_pattern_reliability(row)
                self.cache[pattern.pattern_id] = pattern
                self.cache_access_order.append(pattern.pattern_id)
        
        self.logger.debug(f"Loaded {len(self.cache)} patterns into cache")
    
    def _row_to_pattern_reliability(self, row: Tuple) -> PatternReliability:
        """Convert database row to PatternReliability object."""
        return PatternReliability(
            pattern_id=row[0],
            pattern_name=row[1],
            pattern_category=row[2],
            total_matches=row[3],
            true_positives=row[4],
            false_positives=row[5],
            true_negatives=row[6],
            false_negatives=row[7],
            context_factors=json.loads(row[8]),
            accuracy_trend=json.loads(row[9]),
            confidence_adjustments=json.loads(row[10]),
            last_updated=datetime.fromisoformat(row[11]) if row[11] else datetime.now()
        )
    
    def _pattern_reliability_to_row(self, pattern: PatternReliability) -> Tuple:
        """Convert PatternReliability object to database row."""
        return (
            pattern.pattern_id,
            pattern.pattern_name,
            pattern.pattern_category,
            pattern.total_matches,
            pattern.true_positives,
            pattern.false_positives,
            pattern.true_negatives,
            pattern.false_negatives,
            json.dumps(pattern.context_factors),
            json.dumps(pattern.accuracy_trend),
            json.dumps(pattern.confidence_adjustments),
            pattern.last_updated.isoformat()
        )
    
    def _update_cache(self, pattern: PatternReliability):
        """Update pattern in cache with LRU eviction."""
        with self._lock:
            # Remove from access order if already exists
            if pattern.pattern_id in self.cache_access_order:
                self.cache_access_order.remove(pattern.pattern_id)
            
            # Add to end (most recent)
            self.cache_access_order.append(pattern.pattern_id)
            self.cache[pattern.pattern_id] = pattern
            
            # Evict oldest if cache is full
            while len(self.cache) > self.cache_max_size:
                oldest = self.cache_access_order.popleft()
                del self.cache[oldest]
    
    def get_pattern_reliability(self, pattern_id: str) -> Optional[PatternReliability]:
        """
        Get pattern reliability information.
        
        Args:
            pattern_id: Unique identifier for the pattern
            
        Returns:
            PatternReliability object or None if not found
        """
        # Check cache first
        if pattern_id in self.cache:
            # Update access order
            with self._lock:
                if pattern_id in self.cache_access_order:
                    self.cache_access_order.remove(pattern_id)
                self.cache_access_order.append(pattern_id)
            return self.cache[pattern_id]
        
        # Query database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM pattern_reliability WHERE pattern_id = ?", (pattern_id,))
            row = cursor.fetchone()
            
            if row:
                pattern = self._row_to_pattern_reliability(row)
                self._update_cache(pattern)
                return pattern
        
        return None
    
    def save_pattern_reliability(self, pattern: PatternReliability):
        """
        Save or update pattern reliability information.
        
        Args:
            pattern: PatternReliability object to save
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO pattern_reliability 
                (pattern_id, pattern_name, pattern_category, total_matches, 
                 true_positives, false_positives, true_negatives, false_negatives,
                 context_factors, accuracy_trend, confidence_adjustments, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, self._pattern_reliability_to_row(pattern))
            
            conn.commit()
        
        # Update cache
        self._update_cache(pattern)
        
        self.logger.debug(f"Saved pattern reliability: {pattern.pattern_id}")
    
    def record_validation(self, record: ValidationRecord):
        """
        Record a validation result for learning.
        
        Args:
            record: ValidationRecord containing the validation result
        """
        # Save validation record
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO validation_records 
                (record_id, pattern_id, finding_id, predicted_vulnerability,
                 actual_vulnerability, confidence_score, context,
                 validation_timestamp, validator_id, validation_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.record_id,
                record.pattern_id,
                record.finding_id,
                record.predicted_vulnerability,
                record.actual_vulnerability,
                record.confidence_score,
                json.dumps(record.context),
                record.validation_timestamp.isoformat(),
                record.validator_id,
                record.validation_method
            ))
            
            conn.commit()
        
        # Update pattern reliability
        pattern = self.get_pattern_reliability(record.pattern_id)
        if pattern:
            pattern.update_accuracy(record.is_correct, record.context)
            self.save_pattern_reliability(pattern)
        
        self.logger.debug(f"Recorded validation: {record.record_id}")
    
    def get_patterns_by_category(self, category: str) -> List[PatternReliability]:
        """Get all patterns in a specific category."""
        patterns = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM pattern_reliability WHERE pattern_category = ? ORDER BY reliability_score DESC",
                (category,)
            )
            
            for row in cursor.fetchall():
                patterns.append(self._row_to_pattern_reliability(row))
        
        return patterns
    
    def get_top_patterns(self, limit: int = 10) -> List[PatternReliability]:
        """Get top performing patterns by reliability score."""
        patterns = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM pattern_reliability 
                ORDER BY (CAST(true_positives + true_negatives AS REAL) / 
                         CAST(total_matches AS REAL)) DESC 
                LIMIT ?
            """, (limit,))
            
            for row in cursor.fetchall():
                patterns.append(self._row_to_pattern_reliability(row))
        
        return patterns
    
    def get_patterns_needing_improvement(self, min_samples: int = 10, max_accuracy: float = 0.7) -> List[PatternReliability]:
        """Get patterns that need improvement (low accuracy with sufficient samples)."""
        patterns = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM pattern_reliability 
                WHERE total_matches >= ? 
                AND (CAST(true_positives + true_negatives AS REAL) / CAST(total_matches AS REAL)) < ?
                ORDER BY total_matches DESC
            """, (min_samples, max_accuracy))
            
            for row in cursor.fetchall():
                patterns.append(self._row_to_pattern_reliability(row))
        
        return patterns
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_patterns,
                    AVG(CAST(true_positives + true_negatives AS REAL) / CAST(total_matches AS REAL)) as avg_accuracy,
                    SUM(total_matches) as total_validations,
                    COUNT(CASE WHEN total_matches > 0 THEN 1 END) as active_patterns
                FROM pattern_reliability
            """)
            
            stats = cursor.fetchone()
            
            # Get validation statistics
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_records,
                    COUNT(CASE WHEN predicted_vulnerability = actual_vulnerability THEN 1 END) as correct_predictions,
                    AVG(confidence_score) as avg_confidence
                FROM validation_records
                WHERE validation_timestamp > datetime('now', '-30 days')
            """)
            
            validation_stats = cursor.fetchone()
            
        return {
            'total_patterns': stats[0] or 0,
            'average_accuracy': stats[1] or 0.0,
            'total_validations': stats[2] or 0,
            'active_patterns': stats[3] or 0,
            'recent_validation_records': validation_stats[0] or 0,
            'recent_correct_predictions': validation_stats[1] or 0,
            'recent_average_confidence': validation_stats[2] or 0.0,
            'cache_size': len(self.cache),
            'cache_hit_rate': self._calculate_cache_hit_rate()
        }
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate (placeholder for now)."""
        # This would need to be tracked during actual usage
        return 0.0
    
    def cleanup_old_records(self, days_to_keep: int = 365):
        """Clean up old validation records to manage database size."""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                DELETE FROM validation_records 
                WHERE validation_timestamp < ?
            """, (cutoff_date.isoformat(),))
            
            deleted_count = cursor.rowcount
            conn.commit()
        
        self.logger.info(f"Cleaned up {deleted_count} old validation records")
    
    def export_patterns(self, output_path: Path, format: str = "json"):
        """
        Export pattern reliability data for analysis or backup.
        
        Args:
            output_path: Path to save exported data
            format: Export format ("json" or "csv")
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM pattern_reliability")
            rows = cursor.fetchall()
        
        if format == "json":
            patterns_data = []
            for row in rows:
                pattern = self._row_to_pattern_reliability(row)
                patterns_data.append(asdict(pattern))
            
            with open(output_path, 'w') as f:
                json.dump(patterns_data, f, indent=2, default=str)
        
        elif format == "csv":
            import csv
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['pattern_id', 'pattern_name', 'pattern_category', 'accuracy_rate', 
                               'precision', 'recall', 'f1_score', 'reliability_score', 'total_matches'])
                
                # Write data
                for row in rows:
                    pattern = self._row_to_pattern_reliability(row)
                    writer.writerow([
                        pattern.pattern_id, pattern.pattern_name, pattern.pattern_category,
                        pattern.accuracy_rate, pattern.precision, pattern.recall,
                        pattern.f1_score, pattern.reliability_score, pattern.total_matches
                    ])
        
        self.logger.info(f"Exported {len(rows)} patterns to {output_path}")

# Global pattern reliability database instance
_reliability_database: Optional[PatternReliabilityDatabase] = None

def get_reliability_database(db_path: Optional[Path] = None) -> PatternReliabilityDatabase:
    """Get or create global pattern reliability database."""
    global _reliability_database
    
    if _reliability_database is None:
        _reliability_database = PatternReliabilityDatabase(db_path)
    
    return _reliability_database

def create_validation_record(pattern_id: str,
                           finding_id: str,
                           predicted_vulnerability: bool,
                           actual_vulnerability: bool,
                           confidence_score: float,
                           context: Dict[str, Any] = None,
                           validator_id: str = "system",
                           validation_method: str = "automated") -> ValidationRecord:
    """
    Create a validation record for pattern learning.
    
    Args:
        pattern_id: ID of the pattern that generated the finding
        finding_id: ID of the security finding
        predicted_vulnerability: Whether a vulnerability was predicted
        actual_vulnerability: Whether a vulnerability actually exists
        confidence_score: Original confidence score
        context: Additional context information
        validator_id: Who/what validated this result
        validation_method: Method used for validation
        
    Returns:
        ValidationRecord object
    """
    record_id = f"val_{pattern_id}_{finding_id}_{int(time.time())}"
    
    return ValidationRecord(
        record_id=record_id,
        pattern_id=pattern_id,
        finding_id=finding_id,
        predicted_vulnerability=predicted_vulnerability,
        actual_vulnerability=actual_vulnerability,
        confidence_score=confidence_score,
        context=context or {},
        validation_timestamp=datetime.now(),
        validator_id=validator_id,
        validation_method=validation_method
    ) 
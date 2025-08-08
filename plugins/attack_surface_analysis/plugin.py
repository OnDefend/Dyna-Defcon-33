"""
Attack Surface Analysis Plugin

Main plugin class that orchestrates attack surface analysis using modular components
with evidence-based confidence calculation and external configuration.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import yaml

from .data_structures import (
    AttackSurfaceVulnerability,
    AttackSurfaceAnalysis,
    AttackVector,
    ComponentSurface,
    AnalysisContext,
    SeverityLevel,
    ExposureLevel,
    ComponentType,
    AttackComplexity
)
from .confidence_calculator import AttackSurfaceConfidenceCalculator
from .manifest_analyzer import ManifestAnalyzer

class AttackSurfaceAnalysisPlugin:
    """Main attack surface analysis plugin with modular architecture."""
    
    def __init__(self, apk_ctx=None):
        """Initialize the attack surface analysis plugin."""
        self.apk_ctx = apk_ctx
        self.logger = logging.getLogger(__name__)
        
        # Initialize analysis context
        self.analysis_context = self._create_analysis_context() if apk_ctx else None
        
        # Initialize components
        self.manifest_analyzer = ManifestAnalyzer(self.analysis_context or self._create_default_context(), self.logger)
        self.confidence_calculator = AttackSurfaceConfidenceCalculator()
        
        # Load external configuration
        self.patterns_config = self._load_patterns_config()
        
        # Analysis state
        self.vulnerabilities = []
        self.attack_vectors = []
    
    def _create_default_context(self) -> AnalysisContext:
        """Create default analysis context for testing."""
        return AnalysisContext(
            manifest_path="",
            apk_path="",
            package_name="",
            target_sdk=0,
            min_sdk=0,
            permissions=[],
            features=[]
        )
    
    def _load_patterns_config(self) -> Dict[str, Any]:
        """Load attack surface patterns from external configuration."""
        try:
            config_path = Path(__file__).parent / "attack_patterns_config.yaml"
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.logger.info(f"Loaded attack surface patterns from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load patterns config: {e}")
            return {}
    
    def analyze_attack_surface(self, apk_ctx=None) -> AttackSurfaceAnalysis:
        """Analyze the attack surface of the application."""
        if apk_ctx:
            self.apk_ctx = apk_ctx
            
        if not self.apk_ctx:
            self.logger.warning("No APK context provided, creating mock analysis")
            return self._create_mock_analysis()
        
        try:
            # Initialize analysis context
            self.analysis_context = self._create_analysis_context()
            
            # Perform manifest analysis
            manifest_analysis = self.manifest_analyzer.analyze_manifest(self.apk_ctx)
            
            # Analyze attack vectors
            attack_vectors = self._analyze_attack_vectors(manifest_analysis)
            
            # Analyze component surfaces
            component_surfaces = self._analyze_component_surfaces(manifest_analysis)
            
            # Create comprehensive analysis result
            analysis = AttackSurfaceAnalysis(
                total_components=len(component_surfaces),
                exported_components=len([c for c in component_surfaces if c.exported]),
                high_risk_components=len([c for c in component_surfaces if c.risk_score > 70]),
                attack_vectors=attack_vectors,
                component_surfaces=component_surfaces,
                ipc_channels=self._analyze_ipc_channels(manifest_analysis),
                deep_link_schemes=self._analyze_deep_link_schemes(manifest_analysis),
                permission_boundaries=self._analyze_permission_boundaries(manifest_analysis),
                overall_risk_score=self._calculate_overall_risk_score(component_surfaces),
                attack_complexity=self._assess_attack_complexity(attack_vectors)
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Attack surface analysis failed: {e}")
            return self._create_error_analysis(str(e))
    
    def _create_analysis_context(self) -> AnalysisContext:
        """Create analysis context from APK context."""
        return AnalysisContext(
            manifest_path=getattr(self.apk_ctx, 'manifest_path', ''),
            apk_path=getattr(self.apk_ctx, 'apk_path', ''),
            package_name=getattr(self.apk_ctx, 'package_name', ''),
            target_sdk=getattr(self.apk_ctx, 'target_sdk', 0),
            min_sdk=getattr(self.apk_ctx, 'min_sdk', 0),
            permissions=getattr(self.apk_ctx, 'permissions', []),
            features=getattr(self.apk_ctx, 'features', [])
        )
    
    def _analyze_attack_vectors(self, manifest_analysis: Dict[str, Any]) -> List[AttackVector]:
        """Analyze attack vectors from manifest data."""
        attack_vectors = []
        
        # Analyze exported components
        for component in manifest_analysis.get('exported_components', []):
            vector = self._create_attack_vector_from_component(component)
            if vector:
                attack_vectors.append(vector)
        
        # Analyze intent filters
        for intent_filter in manifest_analysis.get('intent_filters', []):
            vector = self._create_attack_vector_from_intent_filter(intent_filter)
            if vector:
                attack_vectors.append(vector)
        
        return attack_vectors
    
    def _create_attack_vector_from_component(self, component: Dict[str, Any]) -> Optional[AttackVector]:
        """Create attack vector from component data."""
        try:
            # Calculate confidence using evidence-based confidence calculator
            confidence = self.confidence_calculator.calculate_confidence({
                'component_exposure': 0.9 if component.get('exported') else 0.3,
                'permission_protection': 0.8 if component.get('permissions') else 0.2,
                'attack_complexity': 0.7,
                'validation_methods': 0.6,
                'context_relevance': 0.8
            })
            
            return AttackVector(
                vector_id=f"attack_vector_{component.get('name', 'unknown')}",
                name=f"Component Attack Vector: {component.get('name', 'Unknown')}",
                severity=self._determine_severity(component),
                confidence=confidence,
                description=f"Attack vector through {component.get('type', 'component')}: {component.get('name', 'unknown')}",
                component_type=component.get('type', 'unknown'),
                component_name=component.get('name', 'unknown'),
                entry_point=component.get('entry_point', ''),
                attack_methods=component.get('attack_methods', []),
                prerequisites=component.get('prerequisites', []),
                impact=component.get('impact', ''),
                remediation=component.get('remediation', ''),
                cwe_id=component.get('cwe_id', ''),
                masvs_refs=component.get('masvs_refs', [])
            )
        except Exception as e:
            self.logger.error(f"Failed to create attack vector from component: {e}")
            return None
    
    def _create_attack_vector_from_intent_filter(self, intent_filter: Dict[str, Any]) -> Optional[AttackVector]:
        """Create attack vector from intent filter data."""
        try:
            # Calculate confidence using evidence-based confidence calculator
            confidence = self.confidence_calculator.calculate_confidence({
                'component_exposure': 0.8,
                'permission_protection': 0.7 if intent_filter.get('protected') else 0.3,
                'attack_complexity': 0.6,
                'validation_methods': 0.5,
                'context_relevance': 0.7
            })
            
            return AttackVector(
                vector_id=f"intent_vector_{intent_filter.get('name', 'unknown')}",
                name=f"Intent Filter Attack Vector: {intent_filter.get('actions', [])}",
                severity=self._determine_intent_severity(intent_filter),
                confidence=confidence,
                description=f"Attack vector through intent filter: {intent_filter.get('actions', [])}",
                component_type=intent_filter.get('component_type', 'unknown'),
                component_name=intent_filter.get('component_name', 'unknown'),
                entry_point=str(intent_filter.get('actions', [])),
                attack_methods=['Intent manipulation', 'Deep linking attack'],
                prerequisites=[],
                impact="Unauthorized access to component functionality",
                remediation="Implement proper permission checks and input validation",
                cwe_id="CWE-749",
                masvs_refs=["MSTG-PLATFORM-11"]
            )
        except Exception as e:
            self.logger.error(f"Failed to create attack vector from intent filter: {e}")
            return None
    
    def _analyze_component_surfaces(self, manifest_analysis: Dict[str, Any]) -> List[ComponentSurface]:
        """Analyze component attack surfaces."""
        surfaces = []
        
        for component in manifest_analysis.get('all_components', []):
            try:
                surface = ComponentSurface(
                    component_name=component.get('name', 'unknown'),
                    component_type=component.get('type', 'unknown'),
                    exported=component.get('exported', False),
                    permissions=component.get('permissions', []),
                    intent_filters=component.get('intent_filters', []),
                    attack_vectors=[],  # Will be populated later
                    ipc_interfaces=component.get('ipc_interfaces', []),
                    deep_links=component.get('deep_links', []),
                    risk_score=self._calculate_component_risk_score(component),
                    exposure_level=self._determine_exposure_level(component)
                )
                surfaces.append(surface)
            except Exception as e:
                self.logger.error(f"Failed to analyze component surface: {e}")
                continue
        
        return surfaces
    
    def _analyze_ipc_channels(self, manifest_analysis: Dict[str, Any]) -> Dict[str, List[str]]:
        """Analyze IPC channels from manifest data."""
        ipc_channels = {}
        
        for component in manifest_analysis.get('all_components', []):
            if component.get('exported') and component.get('type') in ['service', 'receiver']:
                component_name = component.get('name', 'unknown')
                ipc_channels[component_name] = component.get('ipc_interfaces', [])
        
        return ipc_channels
    
    def _analyze_deep_link_schemes(self, manifest_analysis: Dict[str, Any]) -> set:
        """Analyze deep link schemes from manifest data."""
        schemes = set()
        
        for component in manifest_analysis.get('all_components', []):
            for intent_filter in component.get('intent_filters', []):
                for data_element in intent_filter.get('data', []):
                    if 'scheme' in data_element:
                        schemes.add(data_element['scheme'])
        
        return schemes
    
    def _analyze_permission_boundaries(self, manifest_analysis: Dict[str, Any]) -> Dict[str, List[str]]:
        """Analyze permission boundaries from manifest data."""
        boundaries = {}
        
        for component in manifest_analysis.get('all_components', []):
            component_name = component.get('name', 'unknown')
            permissions = component.get('permissions', [])
            if permissions:
                boundaries[component_name] = permissions
        
        return boundaries
    
    def _calculate_overall_risk_score(self, component_surfaces: List[ComponentSurface]) -> int:
        """Calculate overall risk score from component surfaces."""
        if not component_surfaces:
            return 0
        
        total_risk = sum(surface.risk_score for surface in component_surfaces)
        return min(100, total_risk // len(component_surfaces))
    
    def _assess_attack_complexity(self, attack_vectors: List[AttackVector]) -> str:
        """Assess overall attack complexity."""
        if not attack_vectors:
            return AttackComplexity.MODERATE.value
        
        exported_count = len([v for v in attack_vectors if 'exported' in v.description])
        protected_count = len([v for v in attack_vectors if 'permission' in v.description])
        
        if exported_count > 3 and protected_count == 0:
            return AttackComplexity.TRIVIAL.value
        elif exported_count > 1 and protected_count < 2:
            return AttackComplexity.SIMPLE.value
        elif exported_count > 0 or protected_count > 0:
            return AttackComplexity.MODERATE.value
        else:
            return AttackComplexity.COMPLEX.value
    
    def _determine_severity(self, component: Dict[str, Any]) -> str:
        """Determine severity level for component."""
        if component.get('exported') and not component.get('permissions'):
            return SeverityLevel.HIGH.value
        elif component.get('exported') and component.get('permissions'):
            return SeverityLevel.MEDIUM.value
        else:
            return SeverityLevel.LOW.value
    
    def _determine_intent_severity(self, intent_filter: Dict[str, Any]) -> str:
        """Determine severity level for intent filter."""
        dangerous_actions = ['android.intent.action.VIEW', 'android.intent.action.MAIN']
        
        if any(action in intent_filter.get('actions', []) for action in dangerous_actions):
            return SeverityLevel.HIGH.value
        else:
            return SeverityLevel.MEDIUM.value
    
    def _calculate_component_risk_score(self, component: Dict[str, Any]) -> int:
        """Calculate risk score for a component."""
        base_score = 30
        
        if component.get('exported'):
            base_score += 40
        
        if not component.get('permissions'):
            base_score += 20
        
        if component.get('intent_filters'):
            base_score += 10
        
        return min(100, base_score)
    
    def _determine_exposure_level(self, component: Dict[str, Any]) -> str:
        """Determine exposure level for component."""
        if component.get('exported') and not component.get('permissions'):
            return ExposureLevel.CRITICAL.value
        elif component.get('exported') and component.get('permissions'):
            return ExposureLevel.HIGH.value
        elif component.get('intent_filters'):
            return ExposureLevel.MEDIUM.value
        else:
            return ExposureLevel.LOW.value
    
    def _create_mock_analysis(self) -> AttackSurfaceAnalysis:
        """Create mock analysis for testing without APK context."""
        return AttackSurfaceAnalysis(
            total_components=0,
            exported_components=0,
            high_risk_components=0,
            attack_vectors=[],
            component_surfaces=[],
            ipc_channels={},
            deep_link_schemes=set(),
            permission_boundaries={},
            overall_risk_score=0,
            attack_complexity=AttackComplexity.MODERATE.value
        )
    
    def _create_error_analysis(self, error_msg: str) -> AttackSurfaceAnalysis:
        """Create error analysis result."""
        self.logger.error(f"Attack surface analysis error: {error_msg}")
        return self._create_mock_analysis()
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get analysis summary for compatibility."""
        analysis = self.analyze_attack_surface()
        return {
            'total_components': analysis.total_components,
            'exported_components': analysis.exported_components,
            'high_risk_components': analysis.high_risk_components,
            'attack_vectors_count': len(analysis.attack_vectors),
            'overall_risk_score': analysis.overall_risk_score,
            'attack_complexity': analysis.attack_complexity
        }

# Create factory function for plugin instantiation
def create_attack_surface_plugin(apk_ctx=None) -> AttackSurfaceAnalysisPlugin:
    """Factory function to create attack surface analysis plugin."""
    return AttackSurfaceAnalysisPlugin(apk_ctx)
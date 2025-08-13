#!/usr/bin/env python3
"""
UI Interaction Patterns

Specialized UI interaction patterns for systematic mobile app testing
and vulnerability scenario triggering during runtime analysis.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import subprocess
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class InteractionType(Enum):
    """Types of UI interactions."""
    CLICK = "click"
    LONG_CLICK = "long_click"
    TEXT_INPUT = "text_input"
    SWIPE = "swipe"
    PINCH = "pinch"
    SCROLL = "scroll"
    NAVIGATION = "navigation"


class InputDataType(Enum):
    """Types of test input data."""
    NORMAL = "normal"
    MALICIOUS = "malicious"
    BOUNDARY = "boundary"
    EMPTY = "empty"
    SPECIAL_CHARS = "special_chars"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class UIElement:
    """Represents a UI element for interaction."""
    id: str
    element_type: str
    bounds: Tuple[int, int, int, int] = (0, 0, 0, 0)  # x1, y1, x2, y2
    text: str = ""
    description: str = ""
    clickable: bool = False
    focusable: bool = False
    scrollable: bool = False
    package: str = ""


@dataclass
class InteractionPattern:
    """Defines a UI interaction pattern."""
    name: str
    description: str
    target_elements: List[str]
    interactions: List[Dict[str, Any]]
    expected_behaviors: List[str] = field(default_factory=list)
    security_relevance: str = ""


class UIInteractionPatterns:
    """
    Specialized UI interaction patterns for systematic app testing
    and vulnerability scenario triggering.
    """
    
    def __init__(self, package_name: str = None):
        """Initialize UI interaction patterns."""
        self.logger = logging.getLogger(__name__)
        self.package_name = package_name
        
        # Interaction configuration
        self.interaction_delay = 1.0  # seconds between interactions
        self.input_timeout = 5.0     # seconds for input operations
        self.scroll_distance = 500   # pixels for scroll operations
        
        # Test data collections
        self.normal_test_data = self._initialize_normal_test_data()
        self.malicious_test_data = self._initialize_malicious_test_data()
        self.boundary_test_data = self._initialize_boundary_test_data()
        
        # Predefined interaction patterns
        self.interaction_patterns = self._initialize_interaction_patterns()
        
        self.logger.info(f"🎨 UIInteractionPatterns initialized for {package_name or 'unknown'}")
    
    def _initialize_normal_test_data(self) -> Dict[str, List[str]]:
        """Initialize normal test data for different input types."""
        return {
            "username": ["testuser", "john.doe", "user123", "admin", "guest"],
            "email": ["test@example.com", "user@test.org", "admin@company.com"],
            "password": ["password123", "Test@123", "SecurePass!", "12345678"],
            "phone": ["555-123-4567", "1234567890", "+1-555-123-4567"],
            "name": ["John Doe", "Test User", "Alice Smith", "Bob Johnson"],
            "address": ["123 Main St", "456 Oak Ave", "789 Pine Rd"],
            "city": ["New York", "Los Angeles", "Chicago", "Houston"],
            "zipcode": ["12345", "90210", "60601", "77001"],
            "url": ["https://example.com", "http://test.org", "https://google.com"],
            "number": ["123", "456.78", "1000", "0", "42"],
            "date": ["01/01/2024", "12/31/2023", "06/15/2024"],
            "search": ["test query", "mobile app", "security", "example"]
        }
    
    def _initialize_malicious_test_data(self) -> Dict[str, List[str]]:
        """Initialize malicious test data for security testing."""
        return {
            "sql_injection": [
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "admin'; --",
                "' UNION SELECT password FROM users --"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'><script>alert(document.cookie)</script>"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            "command_injection": [
                "; cat /etc/passwd",
                "| whoami",
                "&& ls -la",
                "`id`"
            ],
            "format_string": [
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%n%n%n%n%n%n%n%n%n%n"
            ],
            "buffer_overflow": [
                "A" * 1000,
                "A" * 5000,
                "A" * 10000
            ]
        }
    
    def _initialize_boundary_test_data(self) -> Dict[str, List[str]]:
        """Initialize boundary test data."""
        return {
            "empty": ["", " ", "   "],
            "single_char": ["a", "1", "@", "!"],
            "max_length": ["x" * 255, "1" * 100, "test" * 50],
            "unicode": ["🔒🚀📱", "αβγδε", "测试数据", "🎯🔍⚡"],
            "special_chars": ["!@#$%^&*()", "<>?:\"{}|", "[]\\;',./"],
            "numeric_boundary": ["-1", "0", "2147483647", "-2147483648"],
            "very_long": ["A" * 10000, "1" * 50000]
        }
    
    def _initialize_interaction_patterns(self) -> List[InteractionPattern]:
        """Initialize predefined interaction patterns."""
        patterns = []
        
        # Authentication patterns
        patterns.append(InteractionPattern(
            name="login_flow",
            description="Standard login flow with username/password",
            target_elements=["username", "password", "login", "signin"],
            interactions=[
                {"type": "text_input", "target": "username", "data_type": "normal"},
                {"type": "text_input", "target": "password", "data_type": "normal"},
                {"type": "click", "target": "login"}
            ],
            expected_behaviors=["authentication", "navigation", "token_generation"],
            security_relevance="Authentication bypass, credential testing"
        ))
        
        # Registration patterns
        patterns.append(InteractionPattern(
            name="registration_flow",
            description="User registration with form submission",
            target_elements=["email", "username", "password", "confirm", "register"],
            interactions=[
                {"type": "text_input", "target": "email", "data_type": "normal"},
                {"type": "text_input", "target": "username", "data_type": "normal"},
                {"type": "text_input", "target": "password", "data_type": "normal"},
                {"type": "text_input", "target": "confirm", "data_type": "normal"},
                {"type": "click", "target": "register"}
            ],
            expected_behaviors=["validation", "data_storage", "network_request"],
            security_relevance="Input validation, data storage security"
        ))
        
        # Search patterns
        patterns.append(InteractionPattern(
            name="search_flow",
            description="Search functionality testing",
            target_elements=["search", "query", "find"],
            interactions=[
                {"type": "text_input", "target": "search", "data_type": "malicious"},
                {"type": "click", "target": "search_button"}
            ],
            expected_behaviors=["database_query", "result_display"],
            security_relevance="SQL injection, XSS in search results"
        ))
        
        # File operations patterns
        patterns.append(InteractionPattern(
            name="file_operations",
            description="File upload/download operations",
            target_elements=["upload", "download", "file", "attach"],
            interactions=[
                {"type": "click", "target": "upload"},
                {"type": "click", "target": "download"}
            ],
            expected_behaviors=["file_access", "storage_operations"],
            security_relevance="Path traversal, file upload vulnerabilities"
        ))
        
        # Settings patterns
        patterns.append(InteractionPattern(
            name="settings_modification",
            description="Application settings modification",
            target_elements=["settings", "preferences", "config"],
            interactions=[
                {"type": "click", "target": "settings"},
                {"type": "click", "target": "preference_toggle"},
                {"type": "navigation", "target": "back"}
            ],
            expected_behaviors=["preference_storage", "configuration_change"],
            security_relevance="Privilege escalation, configuration tampering"
        ))
        
        return patterns
    
    def input_test_data(self, element: UIElement, data_type: InputDataType = InputDataType.NORMAL) -> bool:
        """Input test data into form fields based on element type and data type."""
        try:
            element_id = element.id.lower()
            test_data = self._select_test_data(element_id, data_type)
            
            if not test_data:
                self.logger.warning(f"⚠️ No test data available for element: {element.id}")
                return False
            
            # Select appropriate test data
            data_value = random.choice(test_data)
            
            self.logger.debug(f"📝 Inputting {data_type.value} data into {element.id}: {data_value[:50]}...")
            
            # Clear existing text first
            self._clear_text_field(element)
            
            # Input the test data
            cmd = ['adb', 'shell', 'input', 'text', f'"{data_value}"']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.input_timeout)
            
            if result.returncode == 0:
                time.sleep(0.5)  # Allow time for input processing
                return True
            else:
                self.logger.debug(f"Text input failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.debug("Text input timeout")
            return False
        except Exception as e:
            self.logger.debug(f"Text input error: {e}")
            return False
    
    def _select_test_data(self, element_id: str, data_type: InputDataType) -> List[str]:
        """Select appropriate test data based on element ID and data type."""
        # Determine element category
        if any(keyword in element_id for keyword in ['user', 'login', 'account']):
            element_category = 'username'
        elif any(keyword in element_id for keyword in ['pass', 'pwd']):
            element_category = 'password'
        elif any(keyword in element_id for keyword in ['email', 'mail']):
            element_category = 'email'
        elif any(keyword in element_id for keyword in ['phone', 'mobile', 'tel']):
            element_category = 'phone'
        elif any(keyword in element_id for keyword in ['name', 'first', 'last']):
            element_category = 'name'
        elif any(keyword in element_id for keyword in ['search', 'query', 'find']):
            element_category = 'search'
        elif any(keyword in element_id for keyword in ['url', 'link', 'website']):
            element_category = 'url'
        elif any(keyword in element_id for keyword in ['number', 'num', 'count']):
            element_category = 'number'
        else:
            element_category = 'search'  # Default fallback
        
        # Select data based on type
        if data_type == InputDataType.NORMAL:
            return self.normal_test_data.get(element_category, ["test_data"])
        elif data_type == InputDataType.MALICIOUS:
            # Use malicious data regardless of element type for security testing
            all_malicious = []
            for malicious_list in self.malicious_test_data.values():
                all_malicious.extend(malicious_list)
            return all_malicious
        elif data_type == InputDataType.BOUNDARY:
            all_boundary = []
            for boundary_list in self.boundary_test_data.values():
                all_boundary.extend(boundary_list)
            return all_boundary
        elif data_type == InputDataType.EMPTY:
            return self.boundary_test_data.get('empty', [""])
        elif data_type == InputDataType.SPECIAL_CHARS:
            return self.boundary_test_data.get('special_chars', ["!@#$%"])
        elif data_type == InputDataType.SQL_INJECTION:
            return self.malicious_test_data.get('sql_injection', ["'; DROP TABLE users; --"])
        elif data_type == InputDataType.XSS:
            return self.malicious_test_data.get('xss', ["<script>alert('XSS')</script>"])
        elif data_type == InputDataType.PATH_TRAVERSAL:
            return self.malicious_test_data.get('path_traversal', ["../../../etc/passwd"])
        else:
            return self.normal_test_data.get(element_category, ["test_data"])
    
    def _clear_text_field(self, element: UIElement):
        """Clear existing text in a text field."""
        try:
            # Click on the element first to focus it
            center_x = (element.bounds[0] + element.bounds[2]) // 2 if element.bounds[2] > 0 else 500
            center_y = (element.bounds[1] + element.bounds[3]) // 2 if element.bounds[3] > 0 else 500
            
            cmd = ['adb', 'shell', 'input', 'tap', str(center_x), str(center_y)]
            subprocess.run(cmd, capture_output=True, timeout=3)
            time.sleep(0.5)
            
            # Select all text and delete
            cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_CTRL_A']
            subprocess.run(cmd, capture_output=True, timeout=3)
            cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_DEL']
            subprocess.run(cmd, capture_output=True, timeout=3)
            
        except Exception as e:
            self.logger.debug(f"Text clearing failed: {e}")
    
    def navigate_screens(self, navigation_pattern: str = "systematic") -> List[Dict[str, Any]]:
        """Navigate through app screens systematically."""
        navigation_results = []
        
        try:
            if navigation_pattern == "systematic":
                results = self._systematic_navigation()
            elif navigation_pattern == "random":
                results = self._random_navigation()
            elif navigation_pattern == "depth_first":
                results = self._depth_first_navigation()
            else:
                results = self._basic_navigation()
            
            navigation_results.extend(results)
            
            self.logger.info(f"✅ Completed {len(navigation_results)} navigation actions")
            return navigation_results
            
        except Exception as e:
            self.logger.error(f"❌ Navigation error: {e}")
            return navigation_results
    
    def _systematic_navigation(self) -> List[Dict[str, Any]]:
        """Perform systematic navigation through app screens."""
        actions = []
        
        # Basic navigation pattern
        navigation_sequence = [
            {"action": "swipe_left", "description": "Navigate to next screen"},
            {"action": "swipe_right", "description": "Navigate to previous screen"},
            {"action": "scroll_down", "description": "Scroll down to reveal content"},
            {"action": "scroll_up", "description": "Scroll up to top"},
            {"action": "tap_menu", "description": "Access menu options"},
            {"action": "back", "description": "Navigate back"}
        ]
        
        for nav_action in navigation_sequence:
            result = self._perform_navigation_action(nav_action["action"])
            if result:
                actions.append({
                    "action": nav_action["action"],
                    "description": nav_action["description"],
                    "timestamp": time.time(),
                    "success": True
                })
            time.sleep(self.interaction_delay)
        
        return actions
    
    def _random_navigation(self) -> List[Dict[str, Any]]:
        """Perform random navigation actions."""
        actions = []
        nav_options = ["swipe_left", "swipe_right", "scroll_down", "scroll_up", "back", "tap_center"]
        
        for _ in range(5):
            action = random.choice(nav_options)
            result = self._perform_navigation_action(action)
            
            actions.append({
                "action": action,
                "description": f"Random navigation: {action}",
                "timestamp": time.time(),
                "success": result
            })
            
            time.sleep(self.interaction_delay)
        
        return actions
    
    def _depth_first_navigation(self) -> List[Dict[str, Any]]:
        """Perform depth-first navigation exploration."""
        actions = []
        
        # Simulate depth-first exploration
        depth_actions = [
            "tap_first_item",
            "explore_content",
            "back",
            "tap_second_item", 
            "explore_content",
            "back"
        ]
        
        for action in depth_actions:
            result = self._perform_navigation_action(action)
            actions.append({
                "action": action,
                "description": f"Depth-first: {action}",
                "timestamp": time.time(),
                "success": result
            })
            time.sleep(self.interaction_delay)
        
        return actions
    
    def _basic_navigation(self) -> List[Dict[str, Any]]:
        """Perform basic navigation actions."""
        actions = []
        
        basic_actions = ["scroll_down", "scroll_up", "back"]
        
        for action in basic_actions:
            result = self._perform_navigation_action(action)
            actions.append({
                "action": action,
                "description": f"Basic navigation: {action}",
                "timestamp": time.time(),
                "success": result
            })
            time.sleep(self.interaction_delay)
        
        return actions
    
    def _perform_navigation_action(self, action: str) -> bool:
        """Perform a specific navigation action."""
        try:
            if action == "swipe_left":
                cmd = ['adb', 'shell', 'input', 'swipe', '800', '500', '200', '500']
            elif action == "swipe_right":
                cmd = ['adb', 'shell', 'input', 'swipe', '200', '500', '800', '500']
            elif action == "scroll_down":
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '300', '500', '800']
            elif action == "scroll_up":
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '800', '500', '300']
            elif action == "back":
                cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_BACK']
            elif action == "tap_center":
                cmd = ['adb', 'shell', 'input', 'tap', '500', '500']
            elif action == "tap_menu":
                cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_MENU']
            elif action == "tap_first_item":
                cmd = ['adb', 'shell', 'input', 'tap', '500', '300']
            elif action == "tap_second_item":
                cmd = ['adb', 'shell', 'input', 'tap', '500', '400']
            elif action == "explore_content":
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '600', '500', '400']
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Navigation action {action} failed: {e}")
            return False
    
    def trigger_network_requests(self) -> List[Dict[str, Any]]:
        """Trigger actions that cause network requests."""
        network_triggers = []
        
        try:
            # Common actions that trigger network requests
            network_actions = [
                {"action": "pull_to_refresh", "description": "Pull to refresh content"},
                {"action": "load_more", "description": "Load more content"},
                {"action": "sync_data", "description": "Sync data with server"},
                {"action": "search_online", "description": "Perform online search"},
                {"action": "submit_form", "description": "Submit form data"}
            ]
            
            for action_config in network_actions:
                result = self._perform_network_trigger(action_config["action"])
                
                network_triggers.append({
                    "action": action_config["action"],
                    "description": action_config["description"],
                    "timestamp": time.time(),
                    "success": result,
                    "expected_network_activity": True
                })
                
                time.sleep(self.interaction_delay * 2)  # Longer wait for network operations
            
            self.logger.info(f"✅ Triggered {len(network_triggers)} network request scenarios")
            return network_triggers
            
        except Exception as e:
            self.logger.error(f"❌ Network trigger error: {e}")
            return network_triggers
    
    def _perform_network_trigger(self, action: str) -> bool:
        """Perform specific action to trigger network requests."""
        try:
            if action == "pull_to_refresh":
                # Swipe down from top to trigger refresh
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '200', '500', '600']
            elif action == "load_more":
                # Scroll to bottom to trigger load more
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '800', '500', '200']
            elif action == "sync_data":
                # Tap sync button or menu
                cmd = ['adb', 'shell', 'input', 'tap', '600', '100']
            elif action == "search_online":
                # Perform search that might trigger online lookup
                cmd = ['adb', 'shell', 'input', 'tap', '500', '100']  # Search bar
                subprocess.run(cmd, capture_output=True, timeout=3)
                time.sleep(0.5)
                cmd = ['adb', 'shell', 'input', 'text', '"network test query"']
                subprocess.run(cmd, capture_output=True, timeout=3)
                cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_ENTER']
            elif action == "submit_form":
                # Submit form that sends data to server
                cmd = ['adb', 'shell', 'input', 'tap', '500', '700']  # Submit button
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Network trigger {action} failed: {e}")
            return False
    
    def exercise_crypto_operations(self) -> List[Dict[str, Any]]:
        """Trigger actions that use cryptographic functions."""
        crypto_exercises = []
        
        try:
            # Actions that commonly trigger crypto operations
            crypto_actions = [
                {"action": "login_attempt", "description": "Login with credentials"},
                {"action": "password_change", "description": "Change password"},
                {"action": "encrypt_data", "description": "Encrypt sensitive data"},
                {"action": "secure_storage", "description": "Store data securely"},
                {"action": "certificate_validation", "description": "Validate certificates"}
            ]
            
            for action_config in crypto_actions:
                result = self._perform_crypto_exercise(action_config["action"])
                
                crypto_exercises.append({
                    "action": action_config["action"],
                    "description": action_config["description"],
                    "timestamp": time.time(),
                    "success": result,
                    "expected_crypto_activity": True
                })
                
                time.sleep(self.interaction_delay)
            
            self.logger.info(f"✅ Triggered {len(crypto_exercises)} crypto operation scenarios")
            return crypto_exercises
            
        except Exception as e:
            self.logger.error(f"❌ Crypto exercise error: {e}")
            return crypto_exercises
    
    def _perform_crypto_exercise(self, action: str) -> bool:
        """Perform specific action to trigger crypto operations."""
        try:
            if action == "login_attempt":
                # Fill login form and submit
                self._perform_login_sequence()
                return True
            elif action == "password_change":
                # Navigate to password change and attempt change
                self._perform_password_change_sequence()
                return True
            elif action == "encrypt_data":
                # Try to save data that might be encrypted
                self._perform_data_encryption_sequence()
                return True
            elif action == "secure_storage":
                # Access secure storage features
                self._perform_secure_storage_sequence()
                return True
            elif action == "certificate_validation":
                # Trigger network requests that validate certificates
                self._perform_certificate_validation_sequence()
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.debug(f"Crypto exercise {action} failed: {e}")
            return False
    
    def _perform_login_sequence(self):
        """Perform login sequence to trigger authentication crypto."""
        # Username input
        cmd = ['adb', 'shell', 'input', 'tap', '500', '400']
        subprocess.run(cmd, capture_output=True, timeout=3)
        cmd = ['adb', 'shell', 'input', 'text', 'testuser']
        subprocess.run(cmd, capture_output=True, timeout=3)
        
        # Password input
        cmd = ['adb', 'shell', 'input', 'tap', '500', '500']
        subprocess.run(cmd, capture_output=True, timeout=3)
        cmd = ['adb', 'shell', 'input', 'text', 'TestPass123!']
        subprocess.run(cmd, capture_output=True, timeout=3)
        
        # Submit
        cmd = ['adb', 'shell', 'input', 'tap', '500', '600']
        subprocess.run(cmd, capture_output=True, timeout=3)
    
    def _perform_password_change_sequence(self):
        """Perform password change sequence."""
        # Navigate to settings/account
        cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_MENU']
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(1)
        
        # Tap settings
        cmd = ['adb', 'shell', 'input', 'tap', '500', '300']
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(1)
        
        # Try to change password
        cmd = ['adb', 'shell', 'input', 'tap', '500', '400']
        subprocess.run(cmd, capture_output=True, timeout=3)
    
    def _perform_data_encryption_sequence(self):
        """Perform data encryption sequence."""
        # Try to save sensitive data
        cmd = ['adb', 'shell', 'input', 'tap', '500', '300']
        subprocess.run(cmd, capture_output=True, timeout=3)
        cmd = ['adb', 'shell', 'input', 'text', 'sensitive_data_123']
        subprocess.run(cmd, capture_output=True, timeout=3)
        cmd = ['adb', 'shell', 'input', 'tap', '500', '600']  # Save button
        subprocess.run(cmd, capture_output=True, timeout=3)
    
    def _perform_secure_storage_sequence(self):
        """Perform secure storage sequence."""
        # Access secure notes or vault features
        cmd = ['adb', 'shell', 'input', 'tap', '400', '300']
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(1)
        cmd = ['adb', 'shell', 'input', 'tap', '500', '400']
        subprocess.run(cmd, capture_output=True, timeout=3)
    
    def _perform_certificate_validation_sequence(self):
        """Perform certificate validation sequence."""
        # Trigger HTTPS requests that validate certificates
        cmd = ['adb', 'shell', 'input', 'swipe', '500', '200', '500', '600']  # Refresh
        subprocess.run(cmd, capture_output=True, timeout=3)
    
    def execute_interaction_pattern(self, pattern_name: str) -> Dict[str, Any]:
        """Execute a predefined interaction pattern."""
        pattern = None
        for p in self.interaction_patterns:
            if p.name == pattern_name:
                pattern = p
                break
        
        if not pattern:
            self.logger.error(f"❌ Unknown interaction pattern: {pattern_name}")
            return {"error": f"Pattern {pattern_name} not found"}
        
        self.logger.info(f"🎭 Executing interaction pattern: {pattern.name}")
        
        execution_results = {
            "pattern_name": pattern.name,
            "description": pattern.description,
            "start_time": time.time(),
            "interactions_completed": 0,
            "interactions_failed": 0,
            "expected_behaviors": pattern.expected_behaviors,
            "security_relevance": pattern.security_relevance,
            "results": []
        }
        
        try:
            for interaction in pattern.interactions:
                result = self._execute_single_interaction(interaction)
                
                if result["success"]:
                    execution_results["interactions_completed"] += 1
                else:
                    execution_results["interactions_failed"] += 1
                
                execution_results["results"].append(result)
                time.sleep(self.interaction_delay)
            
            execution_results["end_time"] = time.time()
            execution_results["duration"] = execution_results["end_time"] - execution_results["start_time"]
            
            self.logger.info(f"✅ Pattern {pattern.name} completed: {execution_results['interactions_completed']} successful")
            return execution_results
            
        except Exception as e:
            self.logger.error(f"❌ Pattern execution error: {e}")
            execution_results["error"] = str(e)
            return execution_results
    
    def _execute_single_interaction(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single interaction from a pattern."""
        interaction_type = interaction.get("type", "click")
        target = interaction.get("target", "unknown")
        data_type = InputDataType(interaction.get("data_type", "normal"))
        
        result = {
            "type": interaction_type,
            "target": target,
            "timestamp": time.time(),
            "success": False,
            "details": ""
        }
        
        try:
            if interaction_type == "text_input":
                # Create mock element for text input
                mock_element = UIElement(
                    id=target,
                    element_type="text_field",
                    bounds=(400, 400, 600, 450),
                    focusable=True
                )
                result["success"] = self.input_test_data(mock_element, data_type)
                result["details"] = f"Text input with {data_type.value} data"
                
            elif interaction_type == "click":
                # Perform click action
                cmd = ['adb', 'shell', 'input', 'tap', '500', '600']
                proc_result = subprocess.run(cmd, capture_output=True, timeout=3)
                result["success"] = proc_result.returncode == 0
                result["details"] = f"Click on {target}"
                
            elif interaction_type == "navigation":
                result["success"] = self._perform_navigation_action(target)
                result["details"] = f"Navigation action: {target}"
                
            else:
                result["details"] = f"Unknown interaction type: {interaction_type}"
            
        except Exception as e:
            result["details"] = f"Interaction failed: {e}"
        
        return result
    
    def get_available_patterns(self) -> List[Dict[str, str]]:
        """Get list of available interaction patterns."""
        return [
            {
                "name": pattern.name,
                "description": pattern.description,
                "security_relevance": pattern.security_relevance
            }
            for pattern in self.interaction_patterns
        ]


# Convenience functions
def create_ui_patterns(package_name: str = None) -> UIInteractionPatterns:
    """Create UI interaction patterns instance."""
    return UIInteractionPatterns(package_name=package_name)


def execute_security_test_patterns(package_name: str) -> Dict[str, Any]:
    """Execute all security-relevant interaction patterns."""
    ui_patterns = UIInteractionPatterns(package_name)
    
    results = {
        "package_name": package_name,
        "start_time": time.time(),
        "patterns_executed": [],
        "total_interactions": 0,
        "security_tests_completed": 0
    }
    
    # Execute security-relevant patterns
    security_patterns = ["login_flow", "registration_flow", "search_flow"]
    
    for pattern_name in security_patterns:
        pattern_result = ui_patterns.execute_interaction_pattern(pattern_name)
        results["patterns_executed"].append(pattern_result)
        
        if "error" not in pattern_result:
            results["total_interactions"] += pattern_result.get("interactions_completed", 0)
            results["security_tests_completed"] += 1
    
    results["end_time"] = time.time()
    results["duration"] = results["end_time"] - results["start_time"]
    
    return results


if __name__ == "__main__":
    # Demo usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ui_patterns.py <package_name> [pattern_name]")
        sys.exit(1)
    
    package_name = sys.argv[1]
    pattern_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"🎨 UI Interaction Patterns Demo: {package_name}")
    print("=" * 50)
    
    ui_patterns = UIInteractionPatterns(package_name)
    
    if pattern_name:
        # Execute specific pattern
        result = ui_patterns.execute_interaction_pattern(pattern_name)
        print(f"Pattern Result: {result}")
    else:
        # Execute all security test patterns
        results = execute_security_test_patterns(package_name)
        print("✅ Security test patterns completed!")
        print(f"📊 Results: {results['security_tests_completed']} patterns, {results['total_interactions']} interactions")
        print(f"⏱️ Duration: {results['duration']:.1f}s")
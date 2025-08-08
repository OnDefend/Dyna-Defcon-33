#!/usr/bin/env python3
"""
DrozerHelper: Drozer connection management with error handling

This module provides a helper class for interacting with the Drozer Android security
testing framework with error handling, graceful degradation, and retry logic
to prevent incomplete analysis when Drozer is unavailable or unstable.

Features:
- Graceful degradation when Drozer is unavailable
- Retry logic for transient connection issues
- Reduced timeouts to prevent hanging
- Error handling without hard exits
- Connection state management and recovery
"""

import logging
import subprocess
import sys
import time
from enum import Enum
from typing import Optional, Tuple

class ConnectionState(Enum):
    """Drozer connection states for better state management"""

    UNKNOWN = "unknown"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"

class DrozerHelper:
    """
    Helper class to manage Drozer setup, connection, and command execution.

    This class provides interaction with the Drozer Android security testing framework
    with error handling, graceful degradation, and retry logic to ensure
    security assessments continue even when Drozer encounters issues.

    Attributes:
        package_name (str): The Android package name to target for analysis
        connection_state (ConnectionState): Current connection state
        max_retries (int): Maximum number of connection retry attempts
        command_timeout (int): Timeout for individual Drozer commands
        connection_timeout (int): Timeout for connection establishment
    """

    def __init__(
        self,
        package_name: str,
        max_retries: int = 3,
        command_timeout: int = 60,
        connection_timeout: int = 45,
    ):
        """
        Initialize the DrozerHelper with configuration.

        Args:
            package_name: The Android package name to target for analysis
            max_retries: Maximum number of retry attempts for connections (default: 3)
            command_timeout: Timeout in seconds for individual commands (default: 60s for large APKs)
            connection_timeout: Timeout in seconds for connection establishment (default: 45)
        """
        # Initialize logger attribute FIRST to fix AttributeError
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.package_name = package_name
        self.connection_state = ConnectionState.UNKNOWN
        self.max_retries = max_retries
        self.command_timeout = command_timeout
        self.connection_timeout = connection_timeout
        self.last_error = None
        self.retry_count = 0

        # ADDED: Adaptive timeout for large applications
        self._configure_adaptive_timeout(package_name)

    def _configure_adaptive_timeout(self, package_name: str) -> None:
        """
        Configure adaptive timeouts based on known large applications.

        Args:
            package_name: The Android package name to analyze
        """
        # Known large applications that require longer timeouts
        large_apps = {
            "com.zhiliaoapp.musically": 90,  # Large commercial app
            "com.facebook.katana": 75,  # Facebook - large
            "com.instagram.android": 75,  # Instagram - large
            "com.whatsapp": 75,  # WhatsApp - large
            "com.snapchat.android": 75,  # Snapchat - large
            "com.google.android.youtube": 80,  # YouTube - very large
            "com.amazon.mShop.android.shopping": 70,  # Amazon - large
        }

        original_timeout = self.command_timeout
        if package_name in large_apps:
            self.command_timeout = large_apps[package_name]
            logging.info(
                f"Adaptive timeout configured: {original_timeout}s → {self.command_timeout}s for {package_name}"
            )
        else:
            logging.debug(
                f"Using default timeout: {self.command_timeout}s for {package_name}"
            )

    def start_drozer(self) -> bool:
        """
        Start Drozer and set up port forwarding with error handling.

        Configures ADB port forwarding to connect to the Drozer agent running
        on the Android device/emulator. Uses graceful degradation instead of
        hard exits when port forwarding fails.

        Returns:
            bool: True if port forwarding was successful, False otherwise
        """
        logging.info("Starting Drozer setup...")
        self.connection_state = ConnectionState.CONNECTING

        try:
            # Clean up any existing port forwarding
            cleanup_result = subprocess.run(
                ["adb", "forward", "--remove", "tcp:31415"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            logging.debug(f"Port cleanup result: {cleanup_result.returncode}")

            # Set up new port forwarding
            result = subprocess.run(
                ["adb", "forward", "tcp:31415", "tcp:31415"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                logging.info("Port forwarding set up successfully")
                return True
            else:
                error_msg = result.stderr.strip() or "Unknown port forwarding error"
                self.last_error = f"Port forwarding failed: {error_msg}"
                logging.warning(f"Port forwarding failed: {error_msg}")
                self.connection_state = ConnectionState.FAILED
                return False

        except subprocess.TimeoutExpired:
            self.last_error = "Port forwarding setup timed out"
            logging.warning("Port forwarding setup timed out")
            self.connection_state = ConnectionState.FAILED
            return False
        except FileNotFoundError:
            self.last_error = "ADB not found - ensure Android SDK is installed"
            logging.warning("ADB not found - ensure Android SDK is installed")
            self.connection_state = ConnectionState.UNAVAILABLE
            return False
        except Exception as e:
            self.last_error = f"Unexpected error during port forwarding: {e}"
            logging.warning(f"Unexpected error during port forwarding: {e}")
            self.connection_state = ConnectionState.FAILED
            return False

    def check_connection(self) -> bool:
        """
        Check if Drozer is connected to the device with retry logic.

        Attempts to connect to the Drozer agent running on the Android device
        and verifies that it's responding properly. Includes retry logic for
        transient connection issues.

        Returns:
            bool: True if the connection is successful, False otherwise
        """
        if self.connection_state == ConnectionState.UNAVAILABLE:
            return False

        for attempt in range(self.max_retries):
            self.retry_count = attempt + 1
            logging.info(
                f"Checking Drozer connection (attempt {self.retry_count}/{self.max_retries})"
            )

            if self._attempt_connection():
                self.connection_state = ConnectionState.CONNECTED
                logging.info("Drozer connection established successfully")
                return True

            if attempt < self.max_retries - 1:
                wait_time = 2**attempt  # Exponential backoff: 1s, 2s, 4s
                logging.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)

        self.connection_state = ConnectionState.FAILED
        logging.warning(
            f"Drozer connection failed after {self.max_retries} attempts"
        )
        return False

    def _attempt_connection(self) -> bool:
        """
        Single connection attempt with improved error handling and hang prevention.

        Returns:
            bool: True if connection successful, False otherwise
        """
        test_command = "drozer console connect --command 'version'"

        try:
            # FIXED: Use subprocess.run instead of check_output to prevent hanging
            # Add shorter timeout specifically for connection checks (15s instead of 45s)
            connection_check_timeout = min(15, self.connection_timeout)

            logging.debug(
                f"Testing Drozer connection with {connection_check_timeout}s timeout..."
            )

            process = subprocess.run(
                test_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=connection_check_timeout,
                check=False,  # Don't raise exception on non-zero exit
            )

            # Check if the process completed successfully
            if process.returncode == 0:
                output = process.stdout.strip()

                # Check for connection failure indicators in output
                failure_indicators = [
                    "No devices connected",
                    "not found",
                    "Could not connect",
                    "Connection refused",
                    "No route to host",
                    "timeout",
                    "error",
                    "failed",
                ]

                output_lower = output.lower()
                if any(
                    indicator.lower() in output_lower
                    for indicator in failure_indicators
                ):
                    self.last_error = f"Drozer connection failed: {output}"
                    logging.debug(f"Connection check failed: {output}")
                    return False

                logging.debug(f"Drozer connection check successful: {output}")
                return True
            else:
                # Process failed - check both stdout and stderr
                error_output = process.stderr.strip() or process.stdout.strip()
                if not error_output:
                    error_output = f"Process exited with code {process.returncode}"

                self.last_error = f"Drozer command failed: {error_output}"
                logging.debug(f"Connection check command failed: {error_output}")
                return False

        except subprocess.TimeoutExpired:
            self.last_error = (
                f"Drozer connection timed out after {connection_check_timeout}s"
            )
            logging.debug(
                f"Connection check timed out after {connection_check_timeout}s"
            )
            return False
        except FileNotFoundError:
            self.last_error = "Drozer not found - ensure Drozer is installed"
            logging.debug("Drozer executable not found")
            self.connection_state = ConnectionState.UNAVAILABLE
            return False
        except Exception as e:
            self.last_error = f"Unexpected error during connection check: {e}"
            logging.debug(f"Unexpected connection error: {e}")
            return False

    def run_command(
        self, command: str, timeout_override: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Run a Drozer command with error handling and graceful degradation.

        Executes the specified Drozer command against the target Android device/emulator
        with improved error handling that doesn't break the overall analysis flow.

        Args:
            command: The Drozer command to execute (without the console connect part)
            timeout_override: Optional timeout override for this specific command

        Returns:
            Tuple[bool, str]: (success, output) where success indicates if the command
                            completed successfully, and output contains the result or error message
        """
        if self.connection_state == ConnectionState.UNAVAILABLE:
            return False, f"Drozer unavailable: {self.last_error}"

        if self.connection_state != ConnectionState.CONNECTED:
            return False, f"Drozer not connected: {self.last_error}"

        full_command = f"drozer console connect --command '{command}'"
        timeout = timeout_override or self.command_timeout

        # ADDED: Debug logging to identify timeout issues
        logging.debug(f"Executing Drozer command with {timeout}s timeout: {command}")
        if timeout_override:
            logging.debug(
                f"Timeout override applied: {timeout_override}s (original: {self.command_timeout}s)"
            )

        try:
            logging.debug(f"Executing Drozer command: {command}")
            process = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            if process.returncode == 0:
                output = process.stdout.strip()
                logging.debug(f"Command '{command}' completed successfully")
                return True, output
            else:
                error_output = process.stderr.strip() or process.stdout.strip()
                if not error_output:
                    error_message = (
                        f"Command failed with exit code {process.returncode}"
                    )
                else:
                    error_message = error_output

                logging.warning(f"Command '{command}' failed: {error_message}")
                return False, f"Command failed: {error_message}"

        except subprocess.TimeoutExpired:
            error_msg = f"Command '{command}' timed out after {timeout}s"
            logging.warning(error_msg)
            return False, error_msg
        except ConnectionError as e:
            # ENHANCED: Improved ConnectionError handling with proper string conversion
            error_msg = f"Connection error executing command '{command}': {str(e)}"
            logging.warning(error_msg)
            return False, error_msg
        except OSError as e:
            # ADDED: Handle OSError which can sometimes be misidentified as ConnectionError
            error_msg = f"OS error executing command '{command}': {str(e)}"
            logging.warning(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = (
                f"Error executing command '{command}': {type(e).__name__}: {str(e)}"
            )
            logging.warning(error_msg)
            return False, error_msg

    def run_command_safe(self, command: str, fallback_message: str = None) -> str:
        """
        Run a Drozer command with safe fallback for legacy compatibility.

        This method maintains compatibility with existing code while providing
        graceful degradation when Drozer is unavailable.

        Args:
            command: The Drozer command to execute
            fallback_message: Custom message to return on failure

        Returns:
            str: Command output on success, or formatted error message on failure
        """
        success, output = self.run_command(command)

        if success:
            return output
        else:
            if fallback_message:
                return fallback_message
            else:
                return f"[yellow][!] Drozer command failed: {output}[/yellow]"

    def get_connection_status(self) -> dict:
        """
        Get detailed connection status information.

        Returns:
            dict: Connection status details including state, errors, and retry count
        """
        return {
            "state": self.connection_state.value,
            "connected": self.connection_state == ConnectionState.CONNECTED,
            "available": self.connection_state != ConnectionState.UNAVAILABLE,
            "last_error": self.last_error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
        }

    def execute_command_safe(self, command: str, fallback_message: str = None) -> str:
        """
        Compatibility method for plugins expecting execute_command_safe.
        
        This method provides backward compatibility with plugins that call
        execute_command_safe instead of run_command_safe.
        
        Args:
            command: The Drozer command to execute
            fallback_message: Custom message to return on failure
            
        Returns:
            str: Command output on success, or formatted error message on failure
        """
        return self.run_command_safe(command, fallback_message)

    def execute_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """
        Compatibility method for plugins expecting execute_command.
        
        This method provides backward compatibility with plugins that call
        execute_command instead of run_command.
        
        Args:
            command: The Drozer command to execute
            timeout_override: Optional timeout override for this specific command
            
        Returns:
            Tuple[bool, str]: (success, output) where success indicates if the command
                            completed successfully, and output contains the result or error message
        """
        return self.run_command(command, timeout_override)

    def reset_connection(self) -> bool:
        """
        Reset the connection state and attempt to reconnect.

        Returns:
            bool: True if reconnection successful, False otherwise
        """
        logging.info("Resetting Drozer connection...")
        self.connection_state = ConnectionState.UNKNOWN
        self.last_error = None
        self.retry_count = 0

        if self.start_drozer():
            return self.check_connection()
        return False

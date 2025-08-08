#!/usr/bin/env python3
"""
Enhanced Window Manager for AODS Parallel Execution

This module provides enhanced terminal window management capabilities including:
- Improved terminal detection and support for more terminal types
- Better window positioning and sizing with user preferences
- Enhanced user experience with better error handling and feedback
- Improved window lifecycle management and cleanup

Advanced Terminal Window Management with Enhanced User Experience
"""

import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

logger = logging.getLogger(__name__)

class TerminalType(Enum):
    """Supported terminal types."""
    GNOME_TERMINAL = "gnome-terminal"
    XTERM = "xterm"
    KONSOLE = "konsole"
    TERMINATOR = "terminator"
    LXTERMINAL = "lxterminal"
    KITTY = "kitty"
    ALACRITTY = "alacritty"
    TMUX = "tmux"
    SCREEN = "screen"
    UNKNOWN = "unknown"

@dataclass
class WindowConfig:
    """Configuration for terminal windows."""
    title: str
    geometry: str = "120x40"
    position: Optional[Tuple[int, int]] = None
    stay_open: bool = True
    working_directory: Optional[str] = None
    font_size: Optional[int] = None
    theme: Optional[str] = None

@dataclass
class TerminalCapabilities:
    """Capabilities of a terminal emulator."""
    supports_geometry: bool = True
    supports_position: bool = True
    supports_title: bool = True
    supports_working_dir: bool = True
    supports_stay_open: bool = True
    supports_font_size: bool = False
    supports_theme: bool = False

class EnhancedWindowManager:
    """Enhanced manager for terminal windows with better UX and error handling."""
    
    def __init__(self):
        self.windows: Dict[str, subprocess.Popen] = {}
        self.window_configs: Dict[str, WindowConfig] = {}
        self.terminal_type = self._detect_terminal_advanced()
        self.terminal_capabilities = self._get_terminal_capabilities()
        self.console = Console()
        
        # Window positioning
        self.next_window_offset = 0
        self.base_x_position = 100
        self.base_y_position = 100
        self.window_offset_increment = 50
        
        logger.info(f"Enhanced Window Manager initialized with terminal: {self.terminal_type.value}")
    
    def _detect_terminal_advanced(self) -> TerminalType:
        """Advanced terminal detection with priority and fallback logic."""
        
        # Check environment variables first
        if 'KITTY_WINDOW_ID' in os.environ:
            return TerminalType.KITTY
        if 'ALACRITTY_WINDOW_ID' in os.environ:
            return TerminalType.ALACRITTY
        
        # Priority order for terminal detection
        terminal_priorities = [
            TerminalType.GNOME_TERMINAL,
            TerminalType.KITTY,
            TerminalType.ALACRITTY,
            TerminalType.TERMINATOR,
            TerminalType.KONSOLE,
            TerminalType.LXTERMINAL,
            TerminalType.XTERM,
        ]
        
        for terminal in terminal_priorities:
            if shutil.which(terminal.value):
                try:
                    # Test if terminal actually works
                    result = subprocess.run(
                        [terminal.value, '--help'], 
                        capture_output=True, 
                        timeout=2
                    )
                    if result.returncode == 0 or result.returncode == 1:  # Some terminals return 1 for --help
                        logger.info(f"Detected working terminal: {terminal.value}")
                        return terminal
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue
        
        # Fallback to tmux/screen for console environments
        if not os.environ.get('DISPLAY'):
            if shutil.which('tmux'):
                return TerminalType.TMUX
            elif shutil.which('screen'):
                return TerminalType.SCREEN
        
        logger.warning("No suitable terminal emulator detected")
        return TerminalType.UNKNOWN
    
    def _get_terminal_capabilities(self) -> TerminalCapabilities:
        """Get capabilities for the detected terminal."""
        
        capabilities_map = {
            TerminalType.GNOME_TERMINAL: TerminalCapabilities(
                supports_geometry=True,
                supports_position=True,
                supports_title=True,
                supports_working_dir=True,
                supports_stay_open=True,
                supports_font_size=False,
                supports_theme=False
            ),
            TerminalType.KITTY: TerminalCapabilities(
                supports_geometry=True,
                supports_position=True,
                supports_title=True,
                supports_working_dir=True,
                supports_stay_open=True,
                supports_font_size=True,
                supports_theme=True
            ),
            TerminalType.ALACRITTY: TerminalCapabilities(
                supports_geometry=True,
                supports_position=True,
                supports_title=True,
                supports_working_dir=True,
                supports_stay_open=True,
                supports_font_size=False,
                supports_theme=False
            ),
            TerminalType.XTERM: TerminalCapabilities(
                supports_geometry=True,
                supports_position=True,
                supports_title=True,
                supports_working_dir=False,
                supports_stay_open=True,
                supports_font_size=True,
                supports_theme=False
            ),
            TerminalType.TMUX: TerminalCapabilities(
                supports_geometry=True,
                supports_position=False,
                supports_title=True,
                supports_working_dir=True,
                supports_stay_open=True,
                supports_font_size=False,
                supports_theme=False
            ),
        }
        
        return capabilities_map.get(
            self.terminal_type, 
            TerminalCapabilities()  # Default capabilities
        )
    
    def _calculate_window_position(self, window_id: str) -> Tuple[int, int]:
        """Calculate optimal window position to avoid overlap."""
        x = self.base_x_position + (self.next_window_offset * self.window_offset_increment)
        y = self.base_y_position + (self.next_window_offset * self.window_offset_increment)
        
        # Keep windows on screen (assuming 1920x1080 minimum)
        if x > 800:
            x = self.base_x_position
        if y > 600:
            y = self.base_y_position
        
        self.next_window_offset += 1
        return x, y
    
    def create_window_config(
        self, 
        title: str, 
        geometry: str = "120x40",
        position: Optional[Tuple[int, int]] = None,
        stay_open: bool = True,
        working_directory: Optional[str] = None
    ) -> WindowConfig:
        """Create a window configuration with the specified parameters."""
        
        if position is None:
            position = self._calculate_window_position(title)
        
        return WindowConfig(
            title=title,
            geometry=geometry,
            position=position,
            stay_open=stay_open,
            working_directory=working_directory or os.getcwd()
        )
    
    def _build_terminal_command(self, config: WindowConfig, command: List[str]) -> List[str]:
        """Build the terminal command based on terminal type and configuration."""
        
        if self.terminal_type == TerminalType.GNOME_TERMINAL:
            cmd = ['gnome-terminal']
            
            if self.terminal_capabilities.supports_title:
                cmd.extend(['--title', config.title])
            
            if self.terminal_capabilities.supports_geometry:
                cmd.extend(['--geometry', config.geometry])
            
            if self.terminal_capabilities.supports_working_dir and config.working_directory:
                cmd.extend(['--working-directory', config.working_directory])
            
            # Add command
            shell_cmd = ' '.join(command)
            if config.stay_open:
                shell_cmd += '; echo "Process completed. Press Enter to close..."; read'
            
            cmd.extend(['--', 'bash', '-c', shell_cmd])
        
        elif self.terminal_type == TerminalType.KITTY:
            cmd = ['kitty']
            
            if self.terminal_capabilities.supports_title:
                cmd.extend(['--title', config.title])
            
            if self.terminal_capabilities.supports_geometry:
                # Kitty uses different geometry format
                cmd.extend(['--override', f'remember_window_size=no'])
                # Parse geometry (WIDTHxHEIGHT)
                if 'x' in config.geometry:
                    width, height = config.geometry.split('x')
                    cmd.extend(['--override', f'initial_window_width={width}c'])
                    cmd.extend(['--override', f'initial_window_height={height}c'])
            
            if self.terminal_capabilities.supports_working_dir and config.working_directory:
                cmd.extend(['--directory', config.working_directory])
            
            # Add command
            shell_cmd = ' '.join(command)
            if config.stay_open:
                shell_cmd += '; echo "Process completed. Press Enter to close..."; read'
            
            cmd.extend(['bash', '-c', shell_cmd])
        
        elif self.terminal_type == TerminalType.XTERM:
            cmd = ['xterm']
            
            if self.terminal_capabilities.supports_title:
                cmd.extend(['-title', config.title])
            
            if self.terminal_capabilities.supports_geometry:
                cmd.extend(['-geometry', config.geometry])
            
            if self.terminal_capabilities.supports_position and config.position:
                x, y = config.position
                cmd.extend(['-geometry', f'{config.geometry}+{x}+{y}'])
            
            # Add command
            shell_cmd = ' '.join(command)
            if config.stay_open:
                shell_cmd += '; echo "Process completed. Press Enter to close..."; read'
            
            cmd.extend(['-e', 'bash', '-c', shell_cmd])
        
        elif self.terminal_type == TerminalType.TMUX:
            # For tmux, create a new session
            session_name = f"aods_{config.title.lower().replace(' ', '_')}"
            
            cmd = [
                'tmux', 'new-session', '-d',
                '-s', session_name,
                '-x', '120', '-y', '40',
                ' '.join(command)
            ]
        
        else:
            # Fallback - run in background without terminal
            logger.warning(f"Unsupported terminal type: {self.terminal_type}")
            cmd = command
        
        return cmd
    
    def open_window(
        self, 
        window_id: str, 
        config: WindowConfig, 
        command: List[str]
    ) -> bool:
        """Open a new window with enhanced configuration and error handling."""
        
        try:
            self.console.print(f"[bold blue]🪟 Opening window: {config.title}[/bold blue]")
            
            # Store configuration
            self.window_configs[window_id] = config
            
            # Build terminal command
            cmd = self._build_terminal_command(config, command)
            
            # Log command for debugging
            logger.debug(f"Opening window with command: {' '.join(cmd)}")
            
            # Start process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            # Give the terminal time to start
            time.sleep(0.5)
            
            # Check if process started successfully
            if process.poll() is None or process.returncode == 0:
                self.windows[window_id] = process
                
                self.console.print(
                    f"[green]✅ Successfully opened window: {config.title}[/green]"
                )
                
                logger.info(f"Opened window '{config.title}' with ID: {window_id}")
                return True
            else:
                # Process failed to start
                stdout, stderr = process.communicate()
                error_msg = f"Terminal failed to start: {stderr.decode() if stderr else 'Unknown error'}"
                
                self.console.print(
                    f"[red]❌ Failed to open window: {config.title}[/red]"
                )
                self.console.print(f"[red]Error: {error_msg}[/red]")
                
                logger.error(f"Failed to open window '{config.title}': {error_msg}")
                return False
            
        except Exception as e:
            error_msg = f"Exception opening window '{config.title}': {e}"
            
            self.console.print(f"[red]❌ {error_msg}[/red]")
            logger.error(error_msg)
            
            # Provide helpful suggestions
            self._provide_error_suggestions(e)
            
            return False
    
    def _provide_error_suggestions(self, error: Exception):
        """Provide helpful suggestions when window opening fails."""
        
        suggestions = []
        
        if "No such file or directory" in str(error):
            suggestions.append(f"• Install {self.terminal_type.value}: sudo apt install {self.terminal_type.value}")
        
        if "DISPLAY" in str(error) or "cannot connect to display" in str(error):
            suggestions.append("• Ensure you're running in a graphical environment (X11/Wayland)")
            suggestions.append("• Try setting DISPLAY environment variable")
            suggestions.append("• Consider using --no-separate-windows for headless environments")
        
        if "Permission denied" in str(error):
            suggestions.append("• Check file permissions for the terminal executable")
            suggestions.append("• Ensure you have execute permissions")
        
        if suggestions:
            suggestion_text = Text("\nSuggestions:\n" + "\n".join(suggestions))
            panel = Panel(suggestion_text, title="Troubleshooting", border_style="yellow")
            self.console.print(panel)
    
    def close_window(self, window_id: str, graceful: bool = True):
        """Close a specific window with enhanced cleanup."""
        
        if window_id not in self.windows:
            logger.warning(f"Window {window_id} not found for closing")
            return
        
        try:
            process = self.windows[window_id]
            config = self.window_configs.get(window_id)
            
            if config:
                self.console.print(f"[yellow]🔒 Closing window: {config.title}[/yellow]")
            
            if process.poll() is None:  # Process still running
                if graceful:
                    # Try graceful shutdown first
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # Force kill if graceful shutdown failed
                        if os.name != 'nt':
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait(timeout=2)
                else:
                    # Force kill immediately
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait(timeout=2)
            
            # Clean up
            del self.windows[window_id]
            if window_id in self.window_configs:
                del self.window_configs[window_id]
            
            if config:
                self.console.print(f"[green]✅ Closed window: {config.title}[/green]")
            
            logger.info(f"Closed window: {window_id}")
            
        except Exception as e:
            logger.error(f"Error closing window {window_id}: {e}")
            
            # Force cleanup even if there was an error
            if window_id in self.windows:
                del self.windows[window_id]
            if window_id in self.window_configs:
                del self.window_configs[window_id]
    
    def close_all_windows(self, graceful: bool = True):
        """Close all managed windows with enhanced cleanup."""
        
        self.console.print("[yellow]🔒 Closing all windows...[/yellow]")
        
        window_ids = list(self.windows.keys())
        for window_id in window_ids:
            self.close_window(window_id, graceful=graceful)
        
        self.console.print("[green]✅ All windows closed[/green]")
    
    def get_window_status(self) -> Dict[str, Any]:
        """Get status of all managed windows."""
        
        status = {
            'terminal_type': self.terminal_type.value,
            'capabilities': {
                'supports_geometry': self.terminal_capabilities.supports_geometry,
                'supports_position': self.terminal_capabilities.supports_position,
                'supports_title': self.terminal_capabilities.supports_title,
            },
            'active_windows': len(self.windows),
            'windows': {}
        }
        
        for window_id, process in self.windows.items():
            config = self.window_configs.get(window_id)
            status['windows'][window_id] = {
                'title': config.title if config else 'Unknown',
                'running': process.poll() is None,
                'pid': process.pid,
                'geometry': config.geometry if config else 'Unknown'
            }
        
        return status
    
    def list_available_terminals(self) -> List[str]:
        """List all available terminal emulators on the system."""
        
        available = []
        
        for terminal_type in TerminalType:
            if terminal_type == TerminalType.UNKNOWN:
                continue
            
            if shutil.which(terminal_type.value):
                available.append(terminal_type.value)
        
        return available

def main():
    """Test the enhanced window manager capabilities."""
    print("Testing Enhanced Window Manager with Advanced Terminal Detection")
    
    # Create enhanced window manager
    window_manager = EnhancedWindowManager()
    
    # Show terminal detection results
    print(f"Detected terminal: {window_manager.terminal_type.value}")
    print(f"Available terminals: {window_manager.list_available_terminals()}")
    
    # Get status
    status = window_manager.get_window_status()
    print(f"Window manager status: {status}")
    
    print("✅ Enhanced Window Manager with Advanced Terminal Detection - COMPLETED")

if __name__ == "__main__":
    main() 
 
 
 
 
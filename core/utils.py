"""
Utility functions for colorized output and banners.

This module provides helper functions for formatting and displaying text in the
terminal with ANSI color codes, highlighting important information in scan results,
and creating visual banners for better user experience during scanning.
"""

# import os
import re

# from typing import Callable

# Constants for ANSI color codes
COLOR_RESET = "\033[0m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_BLUE = "\033[94m"
COLOR_WHITE = "\033[97m"
COLOR_CYAN = "\033[96m"

def colorize_text(text: str, color: str) -> str:
    """
    Wrap text in ANSI color codes for terminal display.

    Args:
        text: The text string to colorize
        color: The ANSI color code to apply (use the COLOR_* constants)

    Returns:
        str: The text wrapped with the specified color code and reset code
    """
    return f"{color}{text}{COLOR_RESET}"

def colorize_section_titles(output: str) -> str:
    """
    Apply color to section titles and vulnerability patterns in output.

    Scans the provided text for specific patterns (like section titles,
    field names, package information) and highlights them with yellow color
    to improve readability of Drozer and other tool outputs.

    Args:
        output: The text output from a tool or command to enhance with colors

    Returns:
        str: The output string with colorized section titles and patterns
    """
    section_patterns = [
        r"Shared User ID:",
        r"Uses Permissions:",
        r"Defines Permissions:",
        r"Application Label:",
        r"Process Name:",
        r"Version:",
        r"Data Directory:",
        r"APK Path:",
        r"UID:",
        r"GID:",
        r"Shared Libraries:",
        r"Authority:",
        r"Read Permission:",
        r"Write Permission:",
        r"Content Provider:",
        r"Multiprocess Allowed:",
        r"Grant Uri Permissions:",
        r"Uri Permission Patterns:",
        r"Path Permissions:",
        r"Selecting .* \([^\)]+\)",
        r"Attempting to run shell module",
        r"Package: .*",
    ]
    for pattern in section_patterns:
        output = re.sub(
            pattern, lambda m: colorize_text(m.group(0), COLOR_YELLOW), output
        )
    return output

def print_banner(text: str) -> None:
    """
    Print a banner with the given text, highlighted and with decorative borders.

    Creates a visually distinct section header by surrounding the text with
    equals signs (=) and applying yellow color, useful for separating different
    test sections or phases in the scan output.

    Args:
        text: The text to display in the banner
    """
    banner_length = len(text) + 4
    print(f"{COLOR_YELLOW}{'=' * banner_length}{COLOR_RESET}")
    print(f"{COLOR_YELLOW}  {text}  {COLOR_RESET}")
    print(f"{COLOR_YELLOW}{'=' * banner_length}{COLOR_RESET}")

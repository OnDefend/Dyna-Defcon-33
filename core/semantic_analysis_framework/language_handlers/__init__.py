"""
Language Handlers for Semantic Analysis Framework

This package provides language-specific handlers for semantic analysis.
"""

# Import handlers from separate modules
try:
    from .java_handler import JavaSemanticHandler
except ImportError:
    # Fallback implementation
    class JavaSemanticHandler:
        def __init__(self):
            self.language = "java"

try:
    from .kotlin_handler import KotlinSemanticHandler
except ImportError:
    # Fallback implementation
    class KotlinSemanticHandler:
        def __init__(self):
            self.language = "kotlin"

try:
    from .javascript_handler import JavaScriptSemanticHandler
except ImportError:
    # Fallback implementation
    class JavaScriptSemanticHandler:
        def __init__(self):
            self.language = "javascript"

try:
    from .smali_handler import SmaliSemanticHandler
except ImportError:
    # Fallback implementation
    class SmaliSemanticHandler:
        def __init__(self):
            self.language = "smali"

__all__ = [
    'JavaSemanticHandler',
    'KotlinSemanticHandler', 
    'JavaScriptSemanticHandler',
    'SmaliSemanticHandler'
]

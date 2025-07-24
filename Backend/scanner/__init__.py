# Backend/scanner/__init__.py
"""
SecureThread Scanner Package

A comprehensive security vulnerability scanner for GitHub repositories.
Supports multiple programming languages and scanning tools.
"""

__version__ = "1.0.0"
__author__ = "SecureThread Team"

from .core.repository import GitHubRepository
from .scanners.python_scanner import PythonScanner
from .scanners.javascript_scanner import JavaScriptScanner
from .utils.language_detector import LanguageDetector
from .models.scan_result import ScanResult, ScanStatus

__all__ = [
    "GitHubRepository",
    "PythonScanner", 
    "JavaScriptScanner",
    "LanguageDetector",
    "ScanResult",
    "ScanStatus"
]
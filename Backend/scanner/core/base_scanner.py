# Backend/scanner/core/base_scanner.py
"""
Abstract base class for all security scanners.
"""

import time
import os
import sys
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from scanner.models.scan_result import ToolScanResult, ScanStatus, SecurityIssue
from config.scanner_config import config


class BaseSecurityScanner(ABC):
    """Abstract base class for all security scanning tools."""
    
    def __init__(self, name: str, supported_languages: List[str]):
        """
        Initialize the base scanner.
        
        Args:
            name: Name of the scanning tool
            supported_languages: List of supported programming languages
        """
        self.name = name
        self.supported_languages = supported_languages
        self.execution_time = 0.0
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanning tool is available and properly configured.
        
        Returns:
            True if the tool is available
        """
        pass
    
    @abstractmethod
    def scan_directory(self, directory_path: str, file_list: List[str]) -> ToolScanResult:
        """
        Scan the specified directory for security issues.
        
        Args:
            directory_path: Path to the directory to scan
            file_list: List of files to scan (relative to directory_path)
            
        Returns:
            ToolScanResult containing scan results
        """
        pass
    
    def scan_with_timing(self, directory_path: str, file_list: List[str]) -> ToolScanResult:
        """
        Scan directory with execution time tracking.
        
        Args:
            directory_path: Path to the directory to scan
            file_list: List of files to scan
            
        Returns:
            ToolScanResult with execution time included
        """
        print(f"🔍 Starting {self.name} scan...")
        start_time = time.time()
        
        try:
            if not self.is_available():
                return ToolScanResult(
                    tool_name=self.name,
                    status=ScanStatus.SKIPPED,
                    issues_found=0,
                    execution_time_seconds=0.0,
                    error_message=f"{self.name} is not available"
                )
            
            if not file_list:
                print(f"⚠️ No files to scan for {self.name}")
                return ToolScanResult(
                    tool_name=self.name,
                    status=ScanStatus.COMPLETED,
                    issues_found=0,
                    execution_time_seconds=0.0
                )
            
            result = self.scan_directory(directory_path, file_list)
            
        except Exception as e:
            print(f"❌ {self.name} scan failed: {str(e)}")
            result = ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.FAILED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message=str(e)
            )
        
        # Update execution time
        end_time = time.time()
        self.execution_time = end_time - start_time
        result.execution_time_seconds = self.execution_time
        
        # Log results
        if result.status == ScanStatus.COMPLETED:
            if result.issues_found > 0:
                print(f"⚠️ {self.name} found {result.issues_found} issues")
            else:
                print(f"✅ {self.name} found no issues")
        
        print(f"⏱️ {self.name} scan completed in {self.execution_time:.2f}s")
        
        return result
    
    def supports_language(self, language: str) -> bool:
        """
        Check if this scanner supports the given language.
        
        Args:
            language: Programming language name
            
        Returns:
            True if language is supported
        """
        return language.lower() in [lang.lower() for lang in self.supported_languages]
    
    def _create_security_issue(
        self,
        file_path: str,
        line_number: Optional[int],
        rule_id: str,
        message: str,
        severity: str,
        confidence: str,
        category: Optional[str] = None,
        cwe_id: Optional[str] = None,
        more_info_url: Optional[str] = None
    ) -> SecurityIssue:
        """
        Create a standardized SecurityIssue object.
        
        Args:
            file_path: Path to the file with the issue
            line_number: Line number where issue occurs
            rule_id: Identifier for the rule that detected the issue
            message: Description of the security issue
            severity: Severity level (low, medium, high, critical)
            confidence: Confidence level of the detection
            category: Category of the security issue
            cwe_id: Common Weakness Enumeration ID
            more_info_url: URL with more information about the issue
            
        Returns:
            SecurityIssue object
        """
        from ..models.scan_result import SeverityLevel
        
        # Map severity strings to enum values
        severity_mapping = {
            'low': SeverityLevel.LOW,
            'medium': SeverityLevel.MEDIUM,
            'high': SeverityLevel.HIGH,
            'critical': SeverityLevel.CRITICAL
        }
        
        severity_enum = severity_mapping.get(
            severity.lower(), 
            SeverityLevel.MEDIUM
        )
        
        return SecurityIssue(
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            message=message,
            severity=severity_enum,
            confidence=confidence,
            tool=self.name,
            category=category,
            cwe_id=cwe_id,
            more_info_url=more_info_url
        )
    
    def _truncate_output(self, output: str) -> str:
        """
        Truncate output to configured maximum size.
        
        Args:
            output: Raw output string
            
        Returns:
            Truncated output if necessary
        """
        if len(output) <= config.max_output_size_chars:
            return output
        
        truncated = output[:config.max_output_size_chars]
        truncated += f"\n\n... [Output truncated after {config.max_output_size_chars} characters]"
        return truncated
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """
        Get information about this scanner.
        
        Returns:
            Dictionary with scanner information
        """
        return {
            "name": self.name,
            "supported_languages": self.supported_languages,
            "available": self.is_available(),
            "last_execution_time": self.execution_time
        }
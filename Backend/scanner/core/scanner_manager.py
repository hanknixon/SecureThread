# Backend/scanner/core/scanner_manager.py
"""
Main scanner orchestrator that coordinates all security scanning operations.
"""

import uuid
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from scanner.core.repository import GitHubRepository
from scanner.core.base_scanner import BaseSecurityScanner
from scanner.scanners.python_scanner import PythonScanner
from scanner.scanners.javascript_scanner import JavaScriptScanner
from scanner.utils.language_detector import LanguageDetector
from scanner.utils.file_utils import FileManager
from scanner.models.scan_result import ScanResult, ScanStatus
from config.scanner_config import config


class SecurityScannerManager:
    """Main orchestrator for security scanning operations."""
    
    def __init__(self):
        """Initialize the scanner manager with available scanners."""
        self.scanners: Dict[str, BaseSecurityScanner] = {
            "python": PythonScanner(),
            "javascript": JavaScriptScanner(),
            "typescript": JavaScriptScanner()  # TypeScript uses same scanner as JavaScript
        }
    
    def scan_repository(self, repository_url: str) -> ScanResult:
        """
        Perform a complete security scan of a GitHub repository.
        
        Args:
            repository_url: GitHub repository URL to scan
            
        Returns:
            ScanResult containing all scan results
        """
        scan_id = str(uuid.uuid4())
        scan_start_time = datetime.now()
        
        print(f"🚀 Starting security scan for: {repository_url}")
        print(f"📋 Scan ID: {scan_id}")
        print("=" * 60)
        
        # Initialize scan result
        scan_result = ScanResult(
            repository_url=repository_url,
            scan_id=scan_id,
            scan_timestamp=scan_start_time,
            total_duration_seconds=0.0,
            detected_languages={},
            status=ScanStatus.RUNNING
        )
        
        try:
            # Step 1: Clone repository
            repository = GitHubRepository(repository_url)
            
            with FileManager.temporary_directory() as temp_dir:
                if not repository.clone(temp_dir):
                    scan_result.status = ScanStatus.FAILED
                    return scan_result
                
                # Check repository size limits
                if not repository.check_size_limits():
                    scan_result.status = ScanStatus.FAILED
                    return scan_result
                
                # Step 2: Detect languages
                language_detector = LanguageDetector(temp_dir)
                detected_languages = language_detector.detect_languages()
                scan_result.detected_languages = detected_languages
                
                self._log_detected_languages(detected_languages)
                
                if not detected_languages:
                    print("⚠️ No supported languages detected in repository")
                    scan_result.status = ScanStatus.COMPLETED
                    return scan_result
                
                # Step 3: Run appropriate scanners
                self._run_scanners(temp_dir, detected_languages, scan_result)
            
            # Step 4: Finalize results
            scan_result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            print(f"❌ Scan failed with error: {str(e)}")
            scan_result.status = ScanStatus.FAILED
        
        # Calculate total duration
        scan_end_time = datetime.now()
        scan_result.total_duration_seconds = (scan_end_time - scan_start_time).total_seconds()
        
        self._log_scan_summary(scan_result)
        
        return scan_result
    
    def _run_scanners(
        self, 
        temp_dir: str, 
        detected_languages: Dict[str, List[str]], 
        scan_result: ScanResult
    ) -> None:
        """
        Run appropriate scanners based on detected languages.
        
        Args:
            temp_dir: Temporary directory containing repository
            detected_languages: Dictionary of detected languages and their files
            scan_result: ScanResult object to update with results
        """
        for language, file_list in detected_languages.items():
            if language in self.scanners:
                scanner = self.scanners[language]
                
                if scanner.supports_language(language):
                    print(f"\n🔍 Scanning {language} files ({len(file_list)} files)...")
                    
                    tool_result = scanner.scan_with_timing(temp_dir, file_list)
                    scan_result.tool_results[language] = tool_result
                else:
                    print(f"⚠️ No scanner available for {language}")
            else:
                print(f"⚠️ Unsupported language: {language}")
    
    def _log_detected_languages(self, detected_languages: Dict[str, List[str]]) -> None:
        """
        Log information about detected languages.
        
        Args:
            detected_languages: Dictionary of detected languages
        """
        if detected_languages:
            print(f"🔍 Detected languages: {list(detected_languages.keys())}")
            for lang, files in detected_languages.items():
                print(f"  - {lang}: {len(files)} files")
        else:
            print("⚠️ No supported languages detected")
    
    def _log_scan_summary(self, scan_result: ScanResult) -> None:
        """
        Log a summary of the scan results.
        
        Args:
            scan_result: Completed scan result
        """
        print("\n" + "=" * 60)
        print("📊 SCAN RESULTS SUMMARY")
        print("=" * 60)
        
        print(f"Repository: {scan_result.repository_url}")
        print(f"Scan ID: {scan_result.scan_id}")
        print(f"Status: {scan_result.status.value}")
        print(f"Duration: {scan_result.total_duration_seconds:.2f} seconds")
        print(f"Total Issues: {scan_result.total_issues}")
        
        if scan_result.detected_languages:
            print(f"Languages: {', '.join(scan_result.detected_languages.keys())}")
            for lang, files in scan_result.detected_languages.items():
                print(f"  - {lang}: {len(files)} files")
        
        if scan_result.tool_results:
            print("\n🔍 Tool Results:")
            for tool_name, tool_result in scan_result.tool_results.items():
                status_emoji = "✅" if tool_result.issues_found == 0 else "⚠️"
                print(f"  {status_emoji} {tool_result.tool_name.upper()}: "
                      f"{tool_result.issues_found} issues "
                      f"({tool_result.status.value}, {tool_result.execution_time_seconds:.2f}s)")
        
        # Show severity breakdown
        severity_breakdown = scan_result.get_issues_by_severity()
        if any(count > 0 for count in severity_breakdown.values()):
            print("\n📈 Issues by Severity:")
            for severity, count in severity_breakdown.items():
                if count > 0:
                    emoji = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "⚫"}.get(severity.value, "🔵")
                    print(f"  {emoji} {severity.value.upper()}: {count}")
        
        if scan_result.has_high_severity_issues:
            print("\n⚠️ HIGH SEVERITY ISSUES DETECTED - Immediate attention required!")
        
        print("=" * 60)
    
    def get_available_scanners(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about available scanners.
        
        Returns:
            Dictionary with scanner information
        """
        scanner_info = {}
        
        for lang, scanner in self.scanners.items():
            scanner_info[lang] = scanner.get_scanner_info()
        
        return scanner_info
    
    def add_scanner(self, language: str, scanner: BaseSecurityScanner) -> None:
        """
        Add a new scanner for a specific language.
        
        Args:
            language: Programming language name
            scanner: Scanner instance
        """
        self.scanners[language] = scanner
        print(f"✅ Added {scanner.name} scanner for {language}")
    
    def remove_scanner(self, language: str) -> bool:
        """
        Remove a scanner for a specific language.
        
        Args:
            language: Programming language name
            
        Returns:
            True if scanner was removed
        """
        if language in self.scanners:
            removed_scanner = self.scanners.pop(language)
            print(f"🗑️ Removed {removed_scanner.name} scanner for {language}")
            return True
        
        return False
    
    def validate_repository_url(self, url: str) -> bool:
        """
        Validate if a URL is a valid GitHub repository URL.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid
        """
        return GitHubRepository.is_valid_github_url(url)
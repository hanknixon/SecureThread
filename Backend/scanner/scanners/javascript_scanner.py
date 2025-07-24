# Backend/scanner/scanners/javascript_scanner.py
"""
JavaScript security scanner using ESLint.
"""

import json
import subprocess
import platform
import os
import sys
from typing import List, Dict, Any, Optional

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from scanner.core.base_scanner import BaseSecurityScanner
from scanner.models.scan_result import ToolScanResult, ScanStatus, SecurityIssue
from scanner.utils.file_utils import FileManager
from config.scanner_config import config


class JavaScriptScanner(BaseSecurityScanner):
    """Security scanner for JavaScript/TypeScript code using ESLint."""
    
    def __init__(self):
        """Initialize the JavaScript scanner."""
        super().__init__(
            name="eslint",
            supported_languages=["javascript", "typescript"]
        )
        
        # Set platform-specific commands
        if platform.system() == "Windows":
            self.npm_cmd = "npm.cmd"
            self.npx_cmd = "npx.cmd"
        else:
            self.npm_cmd = "npm"
            self.npx_cmd = "npx"
    
    def is_available(self) -> bool:
        """
        Check if npm/npx is available for running ESLint.
        
        Returns:
            True if npm is available
        """
        try:
            result = subprocess.run(
                [self.npm_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )  # nosec B603
            
            if result.returncode == 0:
                print(f"✅ Found npm version: {result.stdout.strip()}")
                return True
            
            return False
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_directory(self, directory_path: str, file_list: List[str]) -> ToolScanResult:
        """
        Scan JavaScript/TypeScript files using ESLint.
        
        Args:
            directory_path: Path to the directory containing files
            file_list: List of JavaScript/TypeScript files to scan
            
        Returns:
            ToolScanResult containing scan results
        """
        try:
            # Ensure package.json exists
            self._ensure_package_json(directory_path)
            
            # Install ESLint
            if not self._install_eslint(directory_path):
                return ToolScanResult(
                    tool_name=self.name,
                    status=ScanStatus.FAILED,
                    issues_found=0,
                    execution_time_seconds=0.0,
                    error_message="Failed to install ESLint"
                )
            
            # Run ESLint scan
            return self._run_eslint_scan(directory_path)
            
        except subprocess.TimeoutExpired:
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.FAILED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message="ESLint scan timed out"
            )
        except Exception as e:
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.FAILED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message=f"ESLint scan failed: {str(e)}"
            )
    
    def _ensure_package_json(self, directory_path: str) -> None:
        """
        Ensure package.json exists in the directory.
        
        Args:
            directory_path: Directory to check/create package.json in
        """
        package_json_path = os.path.join(directory_path, "package.json")
        
        if not os.path.exists(package_json_path):
            print("📦 Creating temporary package.json...")
            FileManager.create_package_json(directory_path)
    
    def _install_eslint(self, directory_path: str) -> bool:
        """
        Install ESLint in the target directory.
        
        Args:
            directory_path: Directory to install ESLint in
            
        Returns:
            True if installation was successful
        """
        try:
            print("📦 Installing ESLint...")
            
            install_cmd = [
                self.npm_cmd, "install", "eslint", 
                "--no-save", "--silent", "--no-audit", "--no-fund"
            ]
            
            result = subprocess.run(
                install_cmd,
                cwd=directory_path,
                capture_output=True,
                text=True,
                timeout=config.npm_install_timeout
            )  # nosec B603
            
            if result.returncode == 0:
                print("✅ ESLint installed successfully")
                return True
            else:
                print(f"❌ ESLint installation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ ESLint installation timed out")
            return False
        except Exception as e:
            print(f"❌ ESLint installation error: {str(e)}")
            return False
    
    def _run_eslint_scan(self, directory_path: str) -> ToolScanResult:
        """
        Execute ESLint scan with security-focused rules.
        
        Args:
            directory_path: Directory to scan
            
        Returns:
            ToolScanResult with scan results
        """
        eslint_cmd = self._build_eslint_command()
        
        print(f"🔍 Running ESLint scan...")
        
        result = subprocess.run(
            eslint_cmd,
            cwd=directory_path,
            capture_output=True,
            text=True,
            timeout=config.tool_execution_timeout
        )  # nosec B603
        
        return self._parse_eslint_output(result)
    
    def _build_eslint_command(self) -> List[str]:
        """
        Build the ESLint command with security-focused rules.
        
        Returns:
            List of command arguments
        """
        return [
            self.npx_cmd, "eslint", ".",
            "--format", "json",
            # Removed --no-eslintrc as it's incompatible with newer ESLint versions
            "--env", "browser,node,es6",
            "--parser-options", "ecmaVersion:2021,sourceType:module",
            
            # Security rules
            "--rule", "no-eval:error",
            "--rule", "no-implied-eval:error",
            "--rule", "no-new-func:error",
            "--rule", "no-script-url:error",
            
            # Code quality rules that can prevent security issues
            "--rule", "no-unused-vars:warn",
            "--rule", "no-undef:error",
            "--rule", "no-console:warn",
            "--rule", "no-debugger:error",
            "--rule", "eqeqeq:error",
            "--rule", "no-alert:warn",
            "--rule", "no-var:warn",
            "--rule", "prefer-const:warn",
            
            # Error prevention
            "--rule", "no-unreachable:error",
            "--rule", "no-duplicate-case:error",
            "--rule", "no-empty:warn",
            "--rule", "no-extra-semi:warn",
            "--rule", "no-func-assign:error",
            "--rule", "no-irregular-whitespace:warn",
            "--rule", "no-sparse-arrays:warn",
            "--rule", "use-isnan:error",
            "--rule", "valid-typeof:error",
            
            # Additional security-related rules
            "--rule", "no-with:error",
            "--rule", "no-caller:error",
            "--rule", "no-extend-native:error",
            "--rule", "no-global-assign:error",
            "--rule", "no-implicit-globals:error",
            "--rule", "no-new-wrappers:error",
            "--rule", "no-proto:error",
            "--rule", "no-return-assign:error",
            "--rule", "no-self-compare:error",
            "--rule", "no-sequences:error",
            "--rule", "no-throw-literal:error",
            "--rule", "no-unmodified-loop-condition:error",
            "--rule", "no-useless-call:error",
            "--rule", "no-void:error"
        ]
    
    def _parse_eslint_output(self, result: subprocess.CompletedProcess) -> ToolScanResult:
        """
        Parse ESLint output and convert to ToolScanResult.
        
        Args:
            result: Subprocess result from ESLint execution
            
        Returns:
            ToolScanResult with parsed issues
        """
        issues = []
        raw_output = None
        
        try:
            # ESLint returns non-zero exit code when issues are found, which is normal
            if result.stdout:
                eslint_results = json.loads(result.stdout)
                raw_output = eslint_results if config.save_raw_output else None
                
                # Parse each file's results
                for file_result in eslint_results:
                    file_path = file_result.get("filePath", "unknown")
                    
                    # Convert absolute path to relative
                    if os.path.isabs(file_path):
                        file_path = os.path.basename(file_path)
                    
                    # Parse messages (issues) for this file
                    for message in file_result.get("messages", []):
                        issue = self._parse_eslint_message(file_path, message)
                        if issue:
                            issues.append(issue)
                
                # Apply maximum warnings limit
                if len(issues) > config.eslint_max_warnings:
                    print(f"⚠️ ESLint found {len(issues)} issues, limiting to {config.eslint_max_warnings}")
                    issues = issues[:config.eslint_max_warnings]
                
                print(f"🔍 ESLint found {len(issues)} issues")
                
                return ToolScanResult(
                    tool_name=self.name,
                    status=ScanStatus.COMPLETED,
                    issues_found=len(issues),
                    execution_time_seconds=0.0,  # Will be set by base class
                    issues=issues,
                    raw_output=raw_output
                )
            else:
                # No output
                if result.returncode == 0:
                    print("✅ ESLint found no issues")
                    return ToolScanResult(
                        tool_name=self.name,
                        status=ScanStatus.COMPLETED,
                        issues_found=0,
                        execution_time_seconds=0.0
                    )
                else:
                    return ToolScanResult(
                        tool_name=self.name,
                        status=ScanStatus.FAILED,
                        issues_found=0,
                        execution_time_seconds=0.0,
                        error_message=f"ESLint failed with code {result.returncode}: {result.stderr}"
                    )
        
        except json.JSONDecodeError:
            print("⚠️ Could not parse ESLint JSON output")
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.COMPLETED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message="Could not parse ESLint output",
                raw_output={"stdout": result.stdout, "stderr": result.stderr} if config.save_raw_output else None
            )
    
    def _parse_eslint_message(self, file_path: str, message: Dict[str, Any]) -> Optional[SecurityIssue]:
        """
        Parse a single ESLint message/issue.
        
        Args:
            file_path: Path to the file with the issue
            message: ESLint message object
            
        Returns:
            SecurityIssue object or None if parsing fails
        """
        try:
            rule_id = message.get("ruleId", "unknown")
            message_text = message.get("message", "No description")
            line_number = message.get("line")
            severity_level = message.get("severity", 1)
            
            # Map ESLint severity to our severity levels
            severity_mapping = {
                0: "low",     # off
                1: "low",     # warn
                2: "medium"   # error
            }
            
            # Determine if this is a security-related rule
            security_rules = {
                "no-eval", "no-implied-eval", "no-new-func", "no-script-url",
                "no-with", "no-caller", "no-global-assign", "no-proto"
            }
            
            severity = "high" if rule_id in security_rules else severity_mapping.get(severity_level, "low")
            
            # Determine confidence based on rule type
            confidence = "high" if rule_id in security_rules else "medium"
            
            # Categorize the issue
            category = self._categorize_eslint_rule(rule_id)
            
            # Get more info URL
            more_info_url = f"https://eslint.org/docs/rules/{rule_id}" if rule_id != "unknown" else None
            
            return self._create_security_issue(
                file_path=file_path,
                line_number=line_number,
                rule_id=rule_id,
                message=message_text,
                severity=severity,
                confidence=confidence,
                category=category,
                more_info_url=more_info_url
            )
            
        except Exception as e:
            print(f"⚠️ Could not parse ESLint message: {str(e)}")
            return None
    
    def _categorize_eslint_rule(self, rule_id: str) -> str:
        """
        Categorize ESLint rules by type.
        
        Args:
            rule_id: ESLint rule identifier
            
        Returns:
            Category string
        """
        security_rules = {
            "no-eval", "no-implied-eval", "no-new-func", "no-script-url",
            "no-with", "no-caller", "no-global-assign", "no-proto"
        }
        
        quality_rules = {
            "no-unused-vars", "no-undef", "prefer-const", "no-var",
            "eqeqeq", "no-duplicate-case", "no-unreachable"
        }
        
        debug_rules = {
            "no-console", "no-debugger", "no-alert"
        }
        
        if rule_id in security_rules:
            return "security"
        elif rule_id in quality_rules:
            return "quality"
        elif rule_id in debug_rules:
            return "debug"
        else:
            return "general"
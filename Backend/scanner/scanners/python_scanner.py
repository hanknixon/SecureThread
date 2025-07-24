# Backend/scanner/scanners/python_scanner.py
"""
Python security scanner using Bandit.
"""

import json
import os
import sys
import subprocess
from typing import List, Dict, Any, Optional

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from scanner.core.base_scanner import BaseSecurityScanner
from scanner.models.scan_result import ToolScanResult, ScanStatus, SecurityIssue
from config.scanner_config import config


class PythonScanner(BaseSecurityScanner):
    """Security scanner for Python code using Bandit."""
    
    def __init__(self):
        """Initialize the Python scanner."""
        super().__init__(
            name="bandit",
            supported_languages=["python"]
        )
    
    def is_available(self) -> bool:
        """
        Check if Bandit is available.
        
        Returns:
            True if Bandit is installed and accessible
        """
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )  # nosec B603 B607
            
            return result.returncode == 0
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_directory(self, directory_path: str, file_list: List[str]) -> ToolScanResult:
        """
        Scan Python files using Bandit.
        
        Args:
            directory_path: Path to the directory containing files
            file_list: List of Python files to scan
            
        Returns:
            ToolScanResult containing scan results
        """
        try:
            # Build Bandit command
            bandit_cmd = [
                "bandit",
                "-r", directory_path,
                "-f", "json",
                f"-{config.bandit_confidence_level[0]}l",  # -ll, -ml, or -hl
                "-i"  # Show confidence levels
            ]
            
            # Add configuration file if it exists
            bandit_config_path = self._find_bandit_config(directory_path)
            if bandit_config_path:
                bandit_cmd.extend(["-c", bandit_config_path])
            
            print(f"🐍 Running Bandit with command: {' '.join(bandit_cmd)}")
            
            # Execute Bandit
            result = subprocess.run(
                bandit_cmd,
                capture_output=True,
                text=True,
                cwd=directory_path,
                timeout=config.tool_execution_timeout
            )  # nosec B603 B607
            
            # Parse results
            return self._parse_bandit_output(result)
            
        except subprocess.TimeoutExpired:
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.FAILED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message="Bandit scan timed out"
            )
        except Exception as e:
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.FAILED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message=f"Bandit scan failed: {str(e)}"
            )
    
    def _parse_bandit_output(self, result: subprocess.CompletedProcess) -> ToolScanResult:
        """
        Parse Bandit output and convert to ToolScanResult.
        
        Args:
            result: Subprocess result from Bandit execution
            
        Returns:
            ToolScanResult with parsed issues
        """
        issues = []
        raw_output = None
        
        try:
            if result.stdout:
                bandit_results = json.loads(result.stdout)
                raw_output = bandit_results if config.save_raw_output else None
                
                # Parse each issue
                for issue_data in bandit_results.get("results", []):
                    issue = self._parse_bandit_issue(issue_data)
                    if issue:
                        issues.append(issue)
                
                print(f"🔍 Bandit found {len(issues)} security issues")
                
                return ToolScanResult(
                    tool_name=self.name,
                    status=ScanStatus.COMPLETED,
                    issues_found=len(issues),
                    execution_time_seconds=0.0,  # Will be set by base class
                    issues=issues,
                    raw_output=raw_output
                )
            else:
                # No output - either no issues or error
                if result.returncode == 0:
                    print("✅ Bandit found no security issues")
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
                        error_message=f"Bandit failed with code {result.returncode}: {result.stderr}"
                    )
        
        except json.JSONDecodeError:
            print("⚠️ Could not parse Bandit JSON output")
            return ToolScanResult(
                tool_name=self.name,
                status=ScanStatus.COMPLETED,
                issues_found=0,
                execution_time_seconds=0.0,
                error_message="Could not parse Bandit output",
                raw_output={"stdout": result.stdout, "stderr": result.stderr} if config.save_raw_output else None
            )
    
    def _parse_bandit_issue(self, issue_data: Dict[str, Any]) -> Optional[SecurityIssue]:
        """
        Parse a single Bandit issue.
        
        Args:
            issue_data: Raw issue data from Bandit
            
        Returns:
            SecurityIssue object or None if parsing fails
        """
        try:
            # Map Bandit severity to our severity levels
            severity_mapping = {
                "LOW": "low",
                "MEDIUM": "medium", 
                "HIGH": "high"
            }
            
            # Map Bandit confidence to readable string
            confidence_mapping = {
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high"
            }
            
            filename = issue_data.get("filename", "unknown")
            line_number = issue_data.get("line_number")
            test_id = issue_data.get("test_id", "unknown")
            issue_text = issue_data.get("issue_text", "No description")
            
            # Extract severity and confidence
            severity = severity_mapping.get(
                issue_data.get("issue_severity", "MEDIUM").upper(),
                "medium"
            )
            
            confidence = confidence_mapping.get(
                issue_data.get("issue_confidence", "MEDIUM").upper(),
                "medium" 
            )
            
            # Extract additional information
            more_info = issue_data.get("more_info")
            
            # Map test_id to CWE if available
            cwe_mapping = {
                "B102": "CWE-78",   # exec_used
                "B103": "CWE-732",  # set_bad_file_permissions
                "B104": "CWE-78",   # hardcoded_bind_all_interfaces
                "B105": "CWE-798",  # hardcoded_password_string
                "B106": "CWE-798",  # hardcoded_password_funcarg
                "B107": "CWE-798",  # hardcoded_password_default
                "B108": "CWE-377",  # hardcoded_tmp_directory
                "B110": "CWE-703",  # try_except_pass
                "B112": "CWE-703",  # try_except_continue
                "B201": "CWE-78",   # flask_debug_true
                "B301": "CWE-502",  # pickle
                "B302": "CWE-502",  # marshal
                "B303": "CWE-327",  # md5
                "B304": "CWE-327",  # md4
                "B305": "CWE-327",  # sha1
                "B306": "CWE-327",  # mktemp_q
                "B307": "CWE-94",   # eval
                "B308": "CWE-327",  # mark_safe
                "B309": "CWE-330",  # httpsconnection
                "B310": "CWE-330", # urllib_urlopen
                "B311": "CWE-330", # random
                "B312": "CWE-330", # telnetlib
                "B313": "CWE-91",  # xml_bad_cElementTree
                "B314": "CWE-91",  # xml_bad_ElementTree
                "B315": "CWE-91",  # xml_bad_expatreader
                "B316": "CWE-91",  # xml_bad_expatbuilder
                "B317": "CWE-91",  # xml_bad_sax
                "B318": "CWE-91",  # xml_bad_minidom
                "B319": "CWE-91",  # xml_bad_pulldom
                "B320": "CWE-91",  # xml_bad_etree
                "B321": "CWE-78",  # ftplib
                "B322": "CWE-295", # input
                "B323": "CWE-330", # unverified_context
                "B324": "CWE-327", # hashlib_new_insecure_functions
                "B325": "CWE-377", # tempnam
                "B401": "CWE-78",  # import_telnetlib
                "B402": "CWE-78",  # import_ftplib
                "B403": "CWE-502", # import_pickle
                "B404": "CWE-78",  # import_subprocess
                "B405": "CWE-91",  # import_xml_etree
                "B406": "CWE-91",  # import_xml_sax
                "B407": "CWE-91",  # import_xml_expat
                "B408": "CWE-91",  # import_xml_minidom
                "B409": "CWE-91",  # import_xml_pulldom
                "B410": "CWE-91",  # import_lxml
                "B411": "CWE-91",  # import_xmlrpclib
                "B412": "CWE-327", # import_httpoxy
                "B501": "CWE-295", # request_with_no_cert_validation
                "B502": "CWE-295", # ssl_with_bad_version
                "B503": "CWE-295", # ssl_with_bad_defaults
                "B504": "CWE-295", # ssl_with_no_version
                "B505": "CWE-326", # weak_cryptographic_key
                "B506": "CWE-295", # yaml_load
                "B507": "CWE-295", # ssh_no_host_key_verification
                "B601": "CWE-78",  # paramiko_calls
                "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
                "B603": "CWE-78",  # subprocess_without_shell_equals_true
                "B604": "CWE-78",  # any_other_function_with_shell_equals_true
                "B605": "CWE-78",  # start_process_with_a_shell
                "B606": "CWE-78",  # start_process_with_no_shell
                "B607": "CWE-78",  # start_process_with_partial_path
                "B608": "CWE-89",  # hardcoded_sql_expressions
                "B609": "CWE-78",  # linux_commands_wildcard_injection
                "B610": "CWE-295", # django_extra_used
                "B611": "CWE-295", # django_rawsql_used
                "B701": "CWE-20",  # jinja2_autoescape_false
                "B702": "CWE-79",  # use_of_mako_templates
                "B703": "CWE-295"  # django_mark_safe
            }
            
            cwe_id = cwe_mapping.get(test_id)
            
            return self._create_security_issue(
                file_path=filename,
                line_number=line_number,
                rule_id=test_id,
                message=issue_text,
                severity=severity,
                confidence=confidence,
                category="security",
                cwe_id=cwe_id,
                more_info_url=more_info
            )
            
        except Exception as e:
            print(f"⚠️ Could not parse Bandit issue: {str(e)}")
            return None
    
    def _find_bandit_config(self, directory_path: str) -> Optional[str]:
        """
        Find Bandit configuration file in the directory hierarchy.
        
        Args:
            directory_path: Directory to search from
            
        Returns:
            Path to .bandit file or None if not found
        """
        import os
        from pathlib import Path
        
        current_dir = Path(directory_path)
        
        # Search up the directory tree
        for parent in [current_dir] + list(current_dir.parents):
            bandit_config = parent / ".bandit"
            if bandit_config.exists():
                return str(bandit_config)
        
        return None
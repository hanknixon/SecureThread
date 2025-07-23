# Backend/repo_scanner.py
import os
import subprocess  # nosec B404 - subprocess is needed for security tools
import tempfile
import shutil
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import yara

class GitHubRepoScanner:
    """
    A class to fetch GitHub repositories and scan them for security vulnerabilities.
    
    This mimics what tools like SonarQube do when they import external repositories.
    We clone the repo temporarily, run security scans, and return results.
    """
    
    def __init__(self):
        self.temp_dir = None
        self.scan_results = {}
    
    def fetch_repository(self, repo_url: str) -> bool:
        """
        Clone a GitHub repository to a temporary directory.
        
        Args:
            repo_url: GitHub repository URL (e.g., https://github.com/user/repo)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create a temporary directory for the repository
            self.temp_dir = tempfile.mkdtemp(prefix="securethread_")
            print(f"📂 Created temporary directory: {self.temp_dir}")
            
            # First check if git is available
            try:
                git_check = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10)  # nosec B603 B607
                if git_check.returncode != 0:
                    print("❌ Git is not installed or not accessible")
                    return False
                print(f"✅ Found git: {git_check.stdout.strip()}")
            except FileNotFoundError:
                print("❌ Git command not found. Please install Git first.")
                return False
            except subprocess.TimeoutExpired:
                print("❌ Git version check timed out")
                return False
            
            # Clone the repository (shallow clone for efficiency)
            print(f"🔄 Cloning repository: {repo_url}")
            print(f"📁 Target directory: {self.temp_dir}")
            
            result = subprocess.run([  # nosec B603 B607
                "git", "clone", "--depth=1", repo_url, self.temp_dir
            ], capture_output=True, text=True, timeout=120)
            
            print(f"🔍 Git clone return code: {result.returncode}")
            if result.stdout:
                print(f"📝 Git stdout: {result.stdout}")
            if result.stderr:
                print(f"⚠️ Git stderr: {result.stderr}")
            
            if result.returncode == 0:
                # Verify that files were actually cloned
                try:
                    files_in_dir = os.listdir(self.temp_dir)
                    if not files_in_dir:
                        print("❌ Repository cloned but directory is empty")
                        return False
                    print(f"✅ Repository cloned successfully! Found {len(files_in_dir)} items")
                    return True
                except Exception as e:
                    print(f"❌ Error checking cloned files: {str(e)}")
                    return False
            else:
                print(f"❌ Failed to clone repository")
                print(f"   Return code: {result.returncode}")
                print(f"   Error output: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Repository cloning timed out (120 seconds)")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during repository fetch: {str(e)}")
            print(f"   Error type: {type(e).__name__}")
            return False
    
    def detect_languages(self) -> Dict[str, List[str]]:
        """
        Detect programming languages in the repository by file extensions.
        
        Returns:
            Dict with language names as keys and file lists as values
        """
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return {}
        
        languages = {
            "python": [],
            "javascript": [],
            "typescript": [],
            "java": [],
            "go": []
        }
        
        # File extension mappings
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go"
        }
        
        # Walk through all files in the repository
        for root, dirs, files in os.walk(self.temp_dir):
            # Skip hidden directories and common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for file in files:
                file_path = os.path.join(root, file)
                _, extension = os.path.splitext(file)
                
                if extension in extension_map:
                    lang = extension_map[extension]
                    relative_path = os.path.relpath(file_path, self.temp_dir)
                    languages[lang].append(relative_path)
        
        # Filter out empty language categories
        detected = {lang: files for lang, files in languages.items() if files}
        
        print(f"🔍 Detected languages: {list(detected.keys())}")
        for lang, files in detected.items():
            print(f"  - {lang}: {len(files)} files")
        
        return detected
    
    def scan_python_files(self) -> Dict:
        """
        Scan Python files using Bandit security scanner.
        
        Returns:
            Dict containing scan results
        """
        if not self.temp_dir:
            return {"error": "No repository loaded"}
        
        try:
            print("🐍 Running Bandit scan on Python files...")
            
            # Run Bandit with more comprehensive security checks
            result = subprocess.run([  # nosec B603 B607
                "bandit", "-r", self.temp_dir, "-f", "json", 
                "-ll",  # Low level and above (more sensitive)
                "-i"    # Show confidence levels
            ], capture_output=True, text=True, cwd=self.temp_dir)
            
            if result.stdout:
                try:
                    bandit_results = json.loads(result.stdout)
                    issues_count = len(bandit_results.get("results", []))
                    print(f"🔍 Bandit found {issues_count} potential security issues")
                    return {
                        "tool": "bandit",
                        "status": "completed",
                        "issues_found": issues_count,
                        "results": bandit_results
                    }
                except json.JSONDecodeError:
                    print("⚠️ Bandit output was not valid JSON")
                    return {
                        "tool": "bandit",
                        "status": "completed",
                        "raw_output": result.stdout,
                        "stderr": result.stderr
                    }
            else:
                print("✅ Bandit scan completed - no issues found")
                return {
                    "tool": "bandit",
                    "status": "completed",
                    "issues_found": 0,
                    "message": "No security issues detected"
                }
                
        except Exception as e:
            print(f"❌ Error running Bandit scan: {str(e)}")
            return {"error": f"Bandit scan failed: {str(e)}"}
    
    def scan_javascript_files(self) -> Dict:
        """
        Scan JavaScript files using ESLint with security rules.
        
        Returns:
            Dict containing scan results
        """
        if not self.temp_dir:
            return {"error": "No repository loaded"}
        
        try:
            print("🟨 Running ESLint scan on JavaScript files...")
            
            # Check if npm is available with better Windows support
            import platform
            if platform.system() == "Windows":
                npm_cmd = "npm.cmd"
                npx_cmd = "npx.cmd"
            else:
                npm_cmd = "npm"
                npx_cmd = "npx"
            
            try:
                npm_check = subprocess.run([npm_cmd, "--version"], capture_output=True, text=True, timeout=10)  # nosec B603
                if npm_check.returncode != 0:
                    print("⚠️ npm not found. Skipping JavaScript scan.")
                    return {
                        "tool": "eslint",
                        "status": "skipped",
                        "error": "npm not available",
                        "message": "JavaScript scanning requires Node.js and npm to be installed"
                    }
                print(f"✅ Found npm version: {npm_check.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                print(f"⚠️ npm not accessible: {str(e)}")
                return {
                    "tool": "eslint",
                    "status": "skipped",
                    "error": "npm not accessible",
                    "message": f"Could not run npm: {str(e)}"
                }
            
            # First, check if package.json exists, if not create a minimal one
            package_json_path = os.path.join(self.temp_dir, "package.json")
            if not os.path.exists(package_json_path):
                minimal_package = {
                    "name": "securethread-scan",
                    "version": "1.0.0",
                    "description": "Temporary package for security scanning"
                }
                with open(package_json_path, 'w') as f:
                    json.dump(minimal_package, f, indent=2)
            
            print("📦 Installing ESLint...")
            # Install ESLint in the temp directory with error handling
            install_result = subprocess.run([  # nosec B603
                npm_cmd, "install", "eslint", "--no-save", "--silent"
            ], cwd=self.temp_dir, capture_output=True, text=True, timeout=120)
            
            if install_result.returncode != 0:
                print(f"⚠️ Failed to install ESLint: {install_result.stderr}")
                return {
                    "tool": "eslint",
                    "status": "failed",
                    "error": "Failed to install ESLint",
                    "details": install_result.stderr
                }
            
            print("🔍 Running ESLint analysis...")
            # Run ESLint with comprehensive security and quality rules
            eslint_command = [
                npx_cmd, "eslint", ".", 
                "--format", "json",
                "--no-eslintrc",
                "--env", "browser,node,es6",
                "--parser-options", "ecmaVersion:2021,sourceType:module",
                "--rule", "no-eval:error",
                "--rule", "no-implied-eval:error", 
                "--rule", "no-new-func:error",
                "--rule", "no-script-url:error",
                "--rule", "no-unsafe-innerhtml:off",
                "--rule", "no-unused-vars:warn",
                "--rule", "no-undef:error",
                "--rule", "no-console:warn",
                "--rule", "no-debugger:error",
                "--rule", "eqeqeq:error",
                "--rule", "no-alert:warn",
                "--rule", "no-var:warn",
                "--rule", "prefer-const:warn",
                "--rule", "no-unreachable:error",
                "--rule", "no-duplicate-case:error",
                "--rule", "no-empty:warn",
                "--rule", "no-extra-semi:warn",
                "--rule", "no-func-assign:error",
                "--rule", "no-irregular-whitespace:warn",
                "--rule", "no-sparse-arrays:warn",
                "--rule", "use-isnan:error",
                "--rule", "valid-typeof:error"
            ]
            
            result = subprocess.run(  # nosec B603
                eslint_command,
                capture_output=True, 
                text=True, 
                cwd=self.temp_dir,
                timeout=60
            )
            
            # ESLint returns non-zero exit code when it finds issues, which is normal
            if result.stdout:
                try:
                    eslint_results = json.loads(result.stdout)
                    total_issues = sum(len(file_result.get("messages", [])) for file_result in eslint_results)
                    print(f"🔍 ESLint found {total_issues} potential issues")
                    return {
                        "tool": "eslint",
                        "status": "completed",
                        "issues_found": total_issues,
                        "results": eslint_results
                    }
                except json.JSONDecodeError:
                    print("⚠️ ESLint output was not valid JSON")
                    return {
                        "tool": "eslint",
                        "status": "completed_with_warnings",
                        "raw_output": result.stdout[:1000],  # Limit output size
                        "stderr": result.stderr[:1000] if result.stderr else None
                    }
            else:
                print("✅ ESLint scan completed - no issues found")
                return {
                    "tool": "eslint",
                    "status": "completed",
                    "issues_found": 0,
                    "message": "No issues detected"
                }
                
        except subprocess.TimeoutExpired:
            print("⚠️ ESLint scan timed out")
            return {"error": "ESLint scan timed out"}
        except FileNotFoundError as e:
            print(f"⚠️ Command not found: {str(e)}")
            return {
                "tool": "eslint",
                "status": "skipped",
                "error": "Command not found",
                "message": f"Could not find required command: {str(e)}"
            }
        except Exception as e:
            print(f"❌ Error running ESLint scan: {str(e)}")
            return {"error": f"ESLint scan failed: {str(e)}"}
    
    def scan_with_yara_rules(self) -> Dict:
        """
        Scan files using custom YARA rules for advanced threat detection.
        
        Returns:
            Dict containing YARA scan results
        """
        if not self.temp_dir:
            return {"error": "No repository loaded"}
        
        try:
            print("🔍 Running YARA pattern matching scan...")
            
            # Path to YARA rules file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            yara_rules_path = os.path.join(current_dir, "yara_rules", "security_rules.yar")
            
            if not os.path.exists(yara_rules_path):
                print("⚠️ YARA rules file not found, skipping YARA scan")
                return {
                    "tool": "yara",
                    "status": "skipped",
                    "error": "Rules file not found",
                    "message": f"YARA rules file not found at: {yara_rules_path}"
                }
            
            # Compile YARA rules
            try:
                rules = yara.compile(filepath=yara_rules_path)
                print("✅ YARA rules compiled successfully")
            except yara.SyntaxError as e:
                print(f"❌ YARA rules syntax error: {str(e)}")
                return {
                    "tool": "yara",
                    "status": "failed",
                    "error": "Rules syntax error",
                    "details": str(e)
                }
            
            # Scan all files in the repository
            yara_matches = []
            files_scanned = 0
            
            for root, dirs, files in os.walk(self.temp_dir):
                # Skip hidden directories and common non-source directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist', '.git']]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, self.temp_dir)
                    
                    # Only scan text files (skip binaries, images, etc.)
                    if self._is_text_file(file_path):
                        try:
                            matches = rules.match(file_path)
                            files_scanned += 1
                            
                            if matches:
                                for match in matches:
                                    match_info = {
                                        "file": relative_path,
                                        "rule": match.rule,
                                        "category": match.meta.get("category", "unknown"),
                                        "severity": match.meta.get("severity", "MEDIUM"),
                                        "description": match.meta.get("description", "No description"),
                                        "strings": []
                                    }
                                    
                                    # Add matched strings with context
                                    for string_match in match.strings:
                                        match_info["strings"].append({
                                            "identifier": string_match.identifier,
                                            "offset": string_match.instances[0].offset,
                                            "matched_data": string_match.instances[0].matched_data.decode('utf-8', errors='ignore')[:100]
                                        })
                                    
                                    yara_matches.append(match_info)
                        
                        except (IOError, OSError, UnicodeDecodeError) as e:
                            # Skip files that can't be read (specific exception handling)
                            print(f"⚠️ Skipping file {relative_path}: {str(e)}")
                            continue
            
            issues_found = len(yara_matches)
            print(f"🔍 YARA scanned {files_scanned} files and found {issues_found} potential issues")
            
            # Group results by severity for summary
            severity_counts = {}
            for match in yara_matches:
                severity = match["severity"]
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity_counts:
                print("📊 Issues by severity:")
                for severity, count in severity_counts.items():
                    print(f"  - {severity}: {count} issues")
            
            return {
                "tool": "yara",
                "status": "completed",
                "files_scanned": files_scanned,
                "issues_found": issues_found,
                "severity_breakdown": severity_counts,
                "matches": yara_matches
            }
            
        except Exception as e:
            print(f"❌ Error running YARA scan: {str(e)}")
            return {"error": f"YARA scan failed: {str(e)}"}
    
    def _is_text_file(self, file_path: str) -> bool:
        """
        Check if a file is a text file that should be scanned.
        
        Args:
            file_path: Path to the file
            
        Returns:
            bool: True if file should be scanned
        """
        # Skip binary file extensions
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.tar', '.gz', '.7z', '.rar',
            '.woff', '.woff2', '.ttf', '.otf', '.eot'
        }
        
        _, ext = os.path.splitext(file_path.lower())
        if ext in binary_extensions:
            return False
        
        try:
            # Try to read first few bytes to check if it's text
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:  # Null bytes indicate binary file
                    return False
            return True
        except:
            return False
        
    
    def run_full_scan(self, repo_url: str) -> Dict:
        """
        Perform a complete security scan of a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Dict containing complete scan results
        """
        scan_start_time = datetime.now()
        
        print(f"🚀 Starting security scan for: {repo_url}")
        print("=" * 60)
        
        # Step 1: Fetch the repository
        if not self.fetch_repository(repo_url):
            return {
                "status": "failed",
                "error": "Failed to fetch repository",
                "timestamp": scan_start_time.isoformat()
            }
        
        # Step 2: Detect languages
        detected_languages = self.detect_languages()
        
        if not detected_languages:
            print("⚠️ No supported languages detected in repository")
        
        # Step 3: Run appropriate scans based on detected languages
        scan_results = {
            "repository_url": repo_url,
            "scan_timestamp": scan_start_time.isoformat(),
            "detected_languages": detected_languages,
            "scans": {}
        }
        
        # Scan Python files if found
        if "python" in detected_languages:
            scan_results["scans"]["python"] = self.scan_python_files()
        
        # Scan JavaScript files if found
        if "javascript" in detected_languages or "typescript" in detected_languages:
            scan_results["scans"]["javascript"] = self.scan_javascript_files()
        
        # Run YARA pattern matching on all files
        scan_results["scans"]["yara"] = self.scan_with_yara_rules()
        
        # Calculate scan duration
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        scan_results["scan_duration_seconds"] = scan_duration
        
        print("=" * 60)
        print(f"✅ Scan completed in {scan_duration:.2f} seconds")
        
        # Cleanup
        self.cleanup()
        
        return scan_results
    
    def cleanup(self):
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                # On Windows, we might need to handle file locking issues
                import time
                import platform
                
                if platform.system() == "Windows":
                    # Try to make files writable on Windows (more secure permissions)
                    for root, dirs, files in os.walk(self.temp_dir):
                        for file in files:
                            try:
                                # Use more restrictive permissions (owner read/write only)
                                os.chmod(os.path.join(root, file), 0o600)  # nosec B103
                            except OSError:
                                # Specific exception handling instead of bare except
                                continue
                    # Small delay to let file handles close
                    time.sleep(0.1)
                
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                print(f"🧹 Cleaned up temporary directory")
            except Exception as e:
                print(f"⚠️ Warning: Could not clean up temp directory: {str(e)}")
                print(f"📁 Temporary files left at: {self.temp_dir}")
            finally:
                self.temp_dir = None


def main():
    """
    CLI interface for the GitHub repository scanner.
    This allows you to test the scanner from the command line.
    """
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python repo_scanner.py <github_repo_url>")
        print("Example: python repo_scanner.py https://github.com/octocat/Hello-World")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    
    # Validate that it's a GitHub URL
    if not repo_url.startswith("https://github.com/"):
        print("❌ Please provide a valid GitHub repository URL")
        print("Example: https://github.com/user/repository")
        sys.exit(1)
    
    # Create scanner and run scan
    scanner = GitHubRepoScanner()
    
    try:
        results = scanner.run_full_scan(repo_url)
        
        # Pretty print results
        print("\n" + "=" * 60)
        print("📊 SCAN RESULTS SUMMARY")
        print("=" * 60)
        
        print(f"Repository: {results.get('repository_url', 'N/A')}")
        print(f"Scan Time: {results.get('scan_timestamp', 'N/A')}")
        print(f"Duration: {results.get('scan_duration_seconds', 0):.2f} seconds")
        
        detected_langs = results.get('detected_languages', {})
        if detected_langs:
            print(f"Languages: {', '.join(detected_langs.keys())}")
            for lang, files in detected_langs.items():
                print(f"  - {lang}: {len(files)} files")
        
        scans = results.get('scans', {})
        if scans:
            print("\n🔍 Security Scan Results:")
            for scan_type, scan_result in scans.items():
                tool = scan_result.get('tool', scan_type)
                issues = scan_result.get('issues_found', 0)
                status = scan_result.get('status', 'unknown')
                print(f"  - {tool.upper()}: {issues} issues found ({status})")
        
        # Optionally save results to file
        output_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Detailed results saved to: {output_file}")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        scanner.cleanup()
    except Exception as e:
        print(f"\n❌ Scan failed with error: {str(e)}")
        scanner.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()
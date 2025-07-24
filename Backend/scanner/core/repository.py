# Backend/scanner/core/repository.py
"""
Repository management for cloning and handling GitHub repositories.
"""

import os
import sys
import subprocess
import uuid
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from pathlib import Path

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from scanner.models.scan_result import RepositoryInfo
from scanner.utils.file_utils import FileManager
from config.scanner_config import config


class GitHubRepository:
    """Manages GitHub repository operations for security scanning."""
    
    def __init__(self, url: str):
        """
        Initialize the repository manager.
        
        Args:
            url: GitHub repository URL
        """
        self.url = url
        self.local_path: Optional[str] = None
        self.repo_info: Optional[RepositoryInfo] = None
        self._validate_url()
    
    def _validate_url(self) -> None:
        """
        Validate that the URL is a valid GitHub repository URL.
        
        Raises:
            ValueError: If URL is not a valid GitHub repository URL
        """
        try:
            parsed = urlparse(self.url)
            if parsed.netloc.lower() not in ['github.com', 'www.github.com']:
                raise ValueError("URL must be a GitHub repository")
            
            # Extract owner and repo name
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) < 2:
                raise ValueError("Invalid GitHub repository URL format")
            
            self.owner = path_parts[0]
            self.repo_name = path_parts[1].replace('.git', '')
            
        except Exception as e:
            raise ValueError(f"Invalid GitHub repository URL: {str(e)}")
    
    def clone(self, target_directory: str) -> bool:
        """
        Clone the repository to the specified directory.
        
        Args:
            target_directory: Directory to clone the repository into
            
        Returns:
            True if cloning was successful
        """
        try:
            # Check if git is available
            if not self._is_git_available():
                raise RuntimeError("Git is not available")
            
            print(f"🔄 Cloning repository: {self.url}")
            print(f"📁 Target directory: {target_directory}")
            
            # Perform git clone
            result = subprocess.run([  # nosec B603 B607
                "git", "clone", 
                f"--depth={config.clone_depth}",
                self.url, 
                target_directory
            ], 
            capture_output=True, 
            text=True, 
            timeout=config.git_clone_timeout
            )
            
            if result.returncode == 0:
                self.local_path = target_directory
                self._extract_repo_info()
                print(f"✅ Repository cloned successfully!")
                return True
            else:
                print(f"❌ Failed to clone repository")
                print(f"   Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ Repository cloning timed out ({config.git_clone_timeout}s)")
            return False
        except Exception as e:
            print(f"❌ Error during repository clone: {str(e)}")
            return False
    
    def _is_git_available(self) -> bool:
        """
        Check if git command is available.
        
        Returns:
            True if git is available
        """
        try:
            result = subprocess.run(
                ["git", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )  # nosec B603 B607
            
            if result.returncode == 0:
                print(f"✅ Found git: {result.stdout.strip()}")
                return True
            else:
                print("❌ Git is not accessible")
                return False
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("❌ Git command not found")
            return False
    
    def _extract_repo_info(self) -> None:
        """Extract repository information after cloning."""
        if not self.local_path:
            return
        
        try:
            # Count files
            file_count = 0
            for root, dirs, files in os.walk(self.local_path):
                file_count += len(files)
            
            # Calculate size
            size_mb = FileManager.get_directory_size_mb(self.local_path)
            
            # Get commit hash
            commit_hash = self._get_current_commit_hash()
            
            self.repo_info = RepositoryInfo(
                url=self.url,
                name=self.repo_name,
                owner=self.owner,
                commit_hash=commit_hash,
                size_mb=size_mb,
                file_count=file_count
            )
            
            print(f"📊 Repository info: {file_count} files, {size_mb:.2f} MB")
            
        except Exception as e:
            print(f"⚠️ Could not extract repository info: {str(e)}")
    
    def _get_current_commit_hash(self) -> Optional[str]:
        """
        Get the current commit hash of the cloned repository.
        
        Returns:
            Commit hash or None if not available
        """
        if not self.local_path:
            return None
        
        try:
            result = subprocess.run([
                "git", "rev-parse", "HEAD"
            ], 
            capture_output=True, 
            text=True, 
            cwd=self.local_path,
            timeout=10
            )  # nosec B603 B607
            
            if result.returncode == 0:
                return result.stdout.strip()
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def get_branch_name(self) -> Optional[str]:
        """
        Get the current branch name.
        
        Returns:
            Branch name or None if not available
        """
        if not self.local_path:
            return None
        
        try:
            result = subprocess.run([
                "git", "branch", "--show-current"
            ], 
            capture_output=True, 
            text=True, 
            cwd=self.local_path,
            timeout=10
            )  # nosec B603 B607
            
            if result.returncode == 0:
                return result.stdout.strip()
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def check_size_limits(self) -> bool:
        """
        Check if repository size is within configured limits.
        
        Returns:
            True if repository size is acceptable
        """
        if not self.repo_info:
            return True  # Allow if we can't determine size
        
        if self.repo_info.size_mb and self.repo_info.size_mb > config.max_repo_size_mb:
            print(f"⚠️ Repository size ({self.repo_info.size_mb:.2f} MB) "
                  f"exceeds limit ({config.max_repo_size_mb} MB)")
            return False
        
        return True
    
    def get_repository_metadata(self) -> Dict[str, Any]:
        """
        Get repository metadata for reporting.
        
        Returns:
            Dictionary containing repository metadata
        """
        metadata = {
            "url": self.url,
            "owner": self.owner,
            "name": self.repo_name,
            "local_path": self.local_path,
            "cloned": self.local_path is not None
        }
        
        if self.repo_info:
            metadata.update({
                "commit_hash": self.repo_info.commit_hash,
                "size_mb": self.repo_info.size_mb,
                "file_count": self.repo_info.file_count,
                "branch": self.get_branch_name()
            })
        
        return metadata
    
    @staticmethod
    def is_valid_github_url(url: str) -> bool:
        """
        Check if a URL is a valid GitHub repository URL.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid
        """
        try:
            GitHubRepository(url)
            return True
        except ValueError:
            return False
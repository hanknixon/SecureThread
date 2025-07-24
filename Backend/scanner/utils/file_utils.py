# Backend/scanner/utils/file_utils.py
"""
File utility functions for the scanner.
"""

import os
import tempfile
import shutil
import platform
import time
from pathlib import Path
from typing import Optional, List
from contextlib import contextmanager

# Use absolute import to avoid relative import issues
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.scanner_config import config


class FileManager:
    """Manages temporary files and directories for scanning operations."""
    
    @staticmethod
    @contextmanager
    def temporary_directory(prefix: str = "securethread_"):
        """
        Context manager for creating and cleaning up temporary directories.
        
        Args:
            prefix: Prefix for the temporary directory name
            
        Yields:
            Path to the temporary directory
        """
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp(prefix=prefix)
            yield temp_dir
        finally:
            if temp_dir and os.path.exists(temp_dir):
                FileManager._cleanup_directory(temp_dir)
    
    @staticmethod
    def _cleanup_directory(directory_path: str) -> bool:
        """
        Clean up a directory, handling Windows file locking issues.
        
        Args:
            directory_path: Path to the directory to clean up
            
        Returns:
            True if cleanup was successful
        """
        try:
            if platform.system() == "Windows":
                # Handle Windows file locking issues
                FileManager._make_files_writable(directory_path)
                time.sleep(0.1)  # Small delay to let file handles close
            
            shutil.rmtree(directory_path, ignore_errors=True)
            return True
            
        except Exception as e:
            print(f"⚠️ Warning: Could not clean up directory {directory_path}: {str(e)}")
            return False
    
    @staticmethod
    def _make_files_writable(directory_path: str):
        """
        Make all files in a directory writable (Windows-specific).
        
        Args:
            directory_path: Path to the directory
        """
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    # Use more restrictive permissions (owner read/write only)
                    os.chmod(file_path, 0o600)  # nosec B103
                except OSError:
                    # Continue if we can't change permissions
                    continue
    
    @staticmethod
    def is_text_file(file_path: str, max_check_bytes: int = 1024) -> bool:
        """
        Check if a file is a text file by examining its content.
        
        Args:
            file_path: Path to the file
            max_check_bytes: Maximum number of bytes to check
            
        Returns:
            True if the file appears to be text
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(max_check_bytes)
                
            # If file is empty, consider it text
            if not chunk:
                return True
            
            # Check for null bytes (binary indicator)
            if b'\x00' in chunk:
                return False
            
            # Check for high ratio of printable characters
            try:
                chunk.decode('utf-8')
                return True
            except UnicodeDecodeError:
                # Try other common encodings
                for encoding in ['latin1', 'cp1252', 'iso-8859-1']:
                    try:
                        chunk.decode(encoding)
                        return True
                    except UnicodeDecodeError:
                        continue
                
                return False
                
        except (OSError, IOError):
            return False
    
    @staticmethod
    def get_file_size_mb(file_path: str) -> Optional[float]:
        """
        Get file size in megabytes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File size in MB or None if file doesn't exist
        """
        try:
            size_bytes = os.path.getsize(file_path)
            return size_bytes / (1024 * 1024)
        except (OSError, FileNotFoundError):
            return None
    
    @staticmethod
    def get_directory_size_mb(directory_path: str) -> float:
        """
        Get total size of a directory in megabytes.
        
        Args:
            directory_path: Path to the directory
            
        Returns:
            Directory size in MB
        """
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(directory_path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if d not in config.excluded_directories]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (OSError, FileNotFoundError):
                        continue
        except (OSError, FileNotFoundError):
            pass
        
        return total_size / (1024 * 1024)
    
    @staticmethod
    def find_files_by_extension(directory_path: str, extensions: List[str]) -> List[str]:
        """
        Find all files with specified extensions in a directory.
        
        Args:
            directory_path: Path to search in
            extensions: List of file extensions (e.g., ['.py', '.js'])
            
        Returns:
            List of file paths relative to the directory
        """
        found_files = []
        extensions_lower = [ext.lower() for ext in extensions]
        
        for root, dirs, files in os.walk(directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in config.excluded_directories]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in extensions_lower:
                    relative_path = file_path.relative_to(directory_path)
                    found_files.append(str(relative_path))
        
        return found_files
    
    @staticmethod
    def count_lines_of_code(file_path: str) -> int:
        """
        Count lines of code in a file (excluding empty lines and comments).
        
        Args:
            file_path: Path to the file
            
        Returns:
            Number of lines of code
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            loc = 0
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments (basic detection)
                if line and not line.startswith(('#', '//', '/*', '*', '--')):
                    loc += 1
            
            return loc
            
        except (OSError, IOError, UnicodeDecodeError):
            return 0
    
    @staticmethod
    def create_package_json(directory_path: str, package_name: str = "securethread-scan") -> str:
        """
        Create a minimal package.json file for JavaScript scanning.
        
        Args:
            directory_path: Directory to create package.json in
            package_name: Name for the package
            
        Returns:
            Path to the created package.json file
        """
        package_json_content = {
            "name": package_name,
            "version": "1.0.0",
            "description": "Temporary package for SecureThread security scanning",
            "private": True,
            "scripts": {
                "test": "echo \"No tests specified\""
            }
        }
        
        package_json_path = os.path.join(directory_path, "package.json")
        
        try:
            import json
            with open(package_json_path, 'w') as f:
                json.dump(package_json_content, f, indent=2)
            return package_json_path
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to create package.json: {str(e)}")
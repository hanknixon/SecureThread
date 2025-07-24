# Backend/config/scanner_config.py
"""
Configuration settings for the SecureThread scanner.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ScannerConfig:
    """Configuration for the security scanner."""
    
    # Timeout settings (in seconds)
    git_clone_timeout: int = 120
    tool_execution_timeout: int = 300
    npm_install_timeout: int = 120
    
    # Repository settings
    clone_depth: int = 1  # Shallow clone depth
    max_repo_size_mb: int = 500  # Maximum repository size to scan
    
    # Tool settings
    bandit_confidence_level: str = "low"  # low, medium, high
    eslint_max_warnings: int = 100
    
    # File filtering
    excluded_directories: List[str] = None
    excluded_file_extensions: List[str] = None
    max_file_size_mb: int = 10
    
    # Language detection
    supported_languages: List[str] = None
    
    # Output settings
    save_raw_output: bool = True
    max_output_size_chars: int = 50000
    
    def __post_init__(self):
        """Set default values for mutable fields."""
        if self.excluded_directories is None:
            self.excluded_directories = [
                '.git', 'node_modules', '__pycache__', '.pytest_cache',
                'build', 'dist', '.venv', 'venv', '.idea', '.vscode',
                'coverage', '.coverage', '.nyc_output'
            ]
        
        if self.excluded_file_extensions is None:
            self.excluded_file_extensions = [
                '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                '.zip', '.tar', '.gz', '.7z', '.rar', '.deb', '.rpm',
                '.woff', '.woff2', '.ttf', '.otf', '.eot'
            ]
        
        if self.supported_languages is None:
            self.supported_languages = [
                'python', 'javascript', 'typescript', 'java', 'go', 'rust', 'php'
            ]
    
    @classmethod
    def from_environment(cls) -> 'ScannerConfig':
        """Create configuration from environment variables."""
        return cls(
            git_clone_timeout=int(os.getenv('SCANNER_GIT_TIMEOUT', '120')),
            tool_execution_timeout=int(os.getenv('SCANNER_TOOL_TIMEOUT', '300')),
            npm_install_timeout=int(os.getenv('SCANNER_NPM_TIMEOUT', '120')),
            clone_depth=int(os.getenv('SCANNER_CLONE_DEPTH', '1')),
            max_repo_size_mb=int(os.getenv('SCANNER_MAX_REPO_SIZE_MB', '500')),
            bandit_confidence_level=os.getenv('SCANNER_BANDIT_CONFIDENCE', 'low'),
            eslint_max_warnings=int(os.getenv('SCANNER_ESLINT_MAX_WARNINGS', '100')),
            max_file_size_mb=int(os.getenv('SCANNER_MAX_FILE_SIZE_MB', '10')),
            save_raw_output=os.getenv('SCANNER_SAVE_RAW_OUTPUT', 'true').lower() == 'true',
            max_output_size_chars=int(os.getenv('SCANNER_MAX_OUTPUT_SIZE', '50000'))
        )


# Global configuration instance
config = ScannerConfig.from_environment()
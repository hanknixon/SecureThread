# Backend/scanner/utils/language_detector.py
"""
Language detection utility for analyzing repository contents.
"""

import os
import sys
from typing import Dict, List, Set
from pathlib import Path

# Use absolute import to avoid relative import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.scanner_config import config


class LanguageDetector:
    """Detects programming languages in a repository based on file extensions."""
    
    # Mapping of file extensions to programming languages
    LANGUAGE_EXTENSIONS = {
        'python': {'.py', '.pyw', '.pyi'},
        'javascript': {'.js', '.jsx', '.mjs', '.cjs'},
        'typescript': {'.ts', '.tsx', '.d.ts'},
        'java': {'.java'},
        'go': {'.go'},
        'rust': {'.rs'},
        'php': {'.php', '.phtml', '.php3', '.php4', '.php5'},
        'ruby': {'.rb', '.rbw'},
        'csharp': {'.cs'},
        'cpp': {'.cpp', '.cxx', '.cc', '.c++', '.hpp', '.hxx', '.h++'},
        'c': {'.c', '.h'},
        'swift': {'.swift'},
        'kotlin': {'.kt', '.kts'},
        'scala': {'.scala', '.sc'},
        'shell': {'.sh', '.bash', '.zsh', '.fish'},
        'powershell': {'.ps1', '.psm1', '.psd1'},
        'yaml': {'.yml', '.yaml'},
        'json': {'.json'},
        'xml': {'.xml', '.xsd', '.xsl'},
        'html': {'.html', '.htm'},
        'css': {'.css', '.scss', '.sass', '.less'},
        'sql': {'.sql'},
        'dockerfile': {'Dockerfile', '.dockerfile'},
        'markdown': {'.md', '.markdown'},
    }
    
    def __init__(self, repo_path: str):
        """
        Initialize the language detector.
        
        Args:
            repo_path: Path to the repository directory
        """
        self.repo_path = Path(repo_path)
        self._file_cache: Dict[str, List[str]] = {}
    
    def detect_languages(self) -> Dict[str, List[str]]:
        """
        Detect programming languages in the repository.
        
        Returns:
            Dictionary mapping language names to lists of file paths
        """
        if self._file_cache:
            return self._file_cache
        
        languages: Dict[str, List[str]] = {
            lang: [] for lang in config.supported_languages
        }
        
        # Walk through all files in the repository
        for root, dirs, files in os.walk(self.repo_path):
            # Filter out excluded directories
            dirs[:] = [
                d for d in dirs 
                if not d.startswith('.') and d not in config.excluded_directories
            ]
            
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(self.repo_path)
                
                # Skip excluded files
                if self._should_exclude_file(file_path):
                    continue
                
                # Detect language based on file extension
                detected_lang = self._detect_file_language(file_path)
                if detected_lang and detected_lang in languages:
                    languages[detected_lang].append(str(relative_path))
        
        # Filter out languages with no files
        self._file_cache = {
            lang: files for lang, files in languages.items() if files
        }
        
        return self._file_cache
    
    def _detect_file_language(self, file_path: Path) -> str:
        """
        Detect the programming language of a single file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Detected language name or None
        """
        # Handle special files (Dockerfile, etc.)
        if file_path.name in ['Dockerfile', 'Dockerfile.dev', 'Dockerfile.prod']:
            return 'dockerfile'
        
        # Check file extension
        suffix = file_path.suffix.lower()
        if not suffix:
            return None
        
        # Special case for TypeScript definition files
        if file_path.name.endswith('.d.ts'):
            return 'typescript'
        
        # Find language by extension
        for language, extensions in self.LANGUAGE_EXTENSIONS.items():
            if suffix in extensions:
                return language
        
        return None
    
    def _should_exclude_file(self, file_path: Path) -> bool:
        """
        Check if a file should be excluded from scanning.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be excluded
        """
        # Check file extension
        if file_path.suffix.lower() in config.excluded_file_extensions:
            return True
        
        # Check file size
        try:
            if file_path.stat().st_size > config.max_file_size_mb * 1024 * 1024:
                return True
        except (OSError, FileNotFoundError):
            # If we can't get file stats, exclude it
            return True
        
        # Check if file is in excluded directory
        for part in file_path.parts:
            if part in config.excluded_directories:
                return True
        
        return False
    
    def get_language_stats(self) -> Dict[str, Dict[str, int]]:
        """
        Get statistics about detected languages.
        
        Returns:
            Dictionary with language statistics
        """
        languages = self.detect_languages()
        stats = {}
        
        for language, files in languages.items():
            total_size = 0
            for file_path in files:
                full_path = self.repo_path / file_path
                try:
                    total_size += full_path.stat().st_size
                except (OSError, FileNotFoundError):
                    continue
            
            stats[language] = {
                'file_count': len(files),
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'percentage': 0  # Will be calculated below
            }
        
        # Calculate percentages
        total_files = sum(stat['file_count'] for stat in stats.values())
        if total_files > 0:
            for stat in stats.values():
                stat['percentage'] = round(
                    (stat['file_count'] / total_files) * 100, 1
                )
        
        return stats
    
    def get_primary_language(self) -> str:
        """
        Get the primary (most common) language in the repository.
        
        Returns:
            Primary language name or 'unknown'
        """
        languages = self.detect_languages()
        if not languages:
            return 'unknown'
        
        # Find language with most files
        primary = max(languages.items(), key=lambda x: len(x[1]))
        return primary[0]
# Backend/tests/test_scanner.py
"""
Test suite for the SecureThread scanner.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from scanner.core.scanner_manager import SecurityScannerManager
from scanner.core.repository import GitHubRepository
from scanner.utils.language_detector import LanguageDetector
from scanner.models.scan_result import ScanStatus, SeverityLevel


class TestSecurityScannerManager(unittest.TestCase):
    """Test cases for SecurityScannerManager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner_manager = SecurityScannerManager()
    
    def test_validate_repository_url_valid(self):
        """Test URL validation with valid GitHub URLs."""
        valid_urls = [
            "https://github.com/user/repo",
            "https://github.com/user/repo.git",
            "https://github.com/org-name/repo-name"
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(
                    self.scanner_manager.validate_repository_url(url),
                    f"URL should be valid: {url}"
                )
    
    def test_validate_repository_url_invalid(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            "https://gitlab.com/user/repo",
            "https://github.com",
            "https://github.com/user",
            "not-a-url",
            ""
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(
                    self.scanner_manager.validate_repository_url(url),
                    f"URL should be invalid: {url}"
                )
    
    def test_get_available_scanners(self):
        """Test getting available scanners information."""
        scanners = self.scanner_manager.get_available_scanners()
        
        self.assertIsInstance(scanners, dict)
        self.assertIn("python", scanners)
        self.assertIn("javascript", scanners)
        
        # Check scanner info structure
        for lang, info in scanners.items():
            self.assertIn("name", info)
            self.assertIn("supported_languages", info)
            self.assertIn("available", info)


class TestGitHubRepository(unittest.TestCase):
    """Test cases for GitHubRepository."""
    
    def test_url_validation(self):
        """Test GitHub URL validation."""
        # Valid URL
        valid_repo = GitHubRepository("https://github.com/user/repo")
        self.assertEqual(valid_repo.owner, "user")
        self.assertEqual(valid_repo.repo_name, "repo")
        
        # Valid URL with .git suffix
        valid_repo_git = GitHubRepository("https://github.com/user/repo.git")
        self.assertEqual(valid_repo_git.repo_name, "repo")
        
        # Invalid URLs should raise ValueError
        invalid_urls = [
            "https://gitlab.com/user/repo",
            "https://github.com",
            "not-a-url"
        ]
        
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    GitHubRepository(url)
    
    def test_is_valid_github_url(self):
        """Test static URL validation method."""
        self.assertTrue(GitHubRepository.is_valid_github_url("https://github.com/user/repo"))
        self.assertFalse(GitHubRepository.is_valid_github_url("https://gitlab.com/user/repo"))


class TestLanguageDetector(unittest.TestCase):
    """Test cases for LanguageDetector."""
    
    def setUp(self):
        """Set up test fixtures with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.language_detector = LanguageDetector(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_detect_python_files(self):
        """Test detection of Python files."""
        # Create test Python files
        python_files = ["main.py", "utils.py", "test.pyw"]
        
        for filename in python_files:
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write("# Python code\nprint('Hello, World!')")
        
        detected = self.language_detector.detect_languages()
        
        self.assertIn("python", detected)
        self.assertEqual(len(detected["python"]), 3)
        
        # Check that all files are detected
        detected_basenames = [os.path.basename(f) for f in detected["python"]]
        for filename in python_files:
            self.assertIn(filename, detected_basenames)
    
    def test_detect_javascript_files(self):
        """Test detection of JavaScript files."""
        # Create test JavaScript files
        js_files = ["app.js", "component.jsx", "utils.mjs"]
        
        for filename in js_files:
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write("// JavaScript code\nconsole.log('Hello, World!');")
        
        detected = self.language_detector.detect_languages()
        
        self.assertIn("javascript", detected)
        self.assertEqual(len(detected["javascript"]), 3)
    
    def test_detect_mixed_languages(self):
        """Test detection of multiple languages."""
        # Create files for different languages
        test_files = {
            "main.py": "print('Python')",
            "app.js": "console.log('JavaScript');",
            "Component.tsx": "// TypeScript React",
            "Main.java": "// Java code",
            "main.go": "// Go code"
        }
        
        for filename, content in test_files.items():
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
        
        detected = self.language_detector.detect_languages()
        
        expected_languages = ["python", "javascript", "typescript", "java", "go"]
        for lang in expected_languages:
            self.assertIn(lang, detected)
            self.assertEqual(len(detected[lang]), 1)
    
    def test_exclude_directories(self):
        """Test that excluded directories are ignored."""
        # Create files in excluded directories
        excluded_dirs = ["node_modules", "__pycache__", ".git"]
        
        for dirname in excluded_dirs:
            dir_path = os.path.join(self.temp_dir, dirname)
            os.makedirs(dir_path)
            
            # Create a Python file in the excluded directory
            file_path = os.path.join(dir_path, "test.py")
            with open(file_path, 'w') as f:
                f.write("print('This should be excluded')")
        
        # Create a valid Python file in the root
        valid_file = os.path.join(self.temp_dir, "main.py")
        with open(valid_file, 'w') as f:
            f.write("print('This should be included')")
        
        detected = self.language_detector.detect_languages()
        
        # Should only detect the valid file
        self.assertIn("python", detected)
        self.assertEqual(len(detected["python"]), 1)
        self.assertTrue(detected["python"][0].endswith("main.py"))
    
    def test_get_primary_language(self):
        """Test getting the primary language."""
        # Create more Python files than JavaScript files
        for i in range(3):
            file_path = os.path.join(self.temp_dir, f"python_{i}.py")
            with open(file_path, 'w') as f:
                f.write("print('Python')")
        
        file_path = os.path.join(self.temp_dir, "app.js")
        with open(file_path, 'w') as f:
            f.write("console.log('JavaScript');")
        
        primary = self.language_detector.get_primary_language()
        self.assertEqual(primary, "python")
    
    def test_empty_directory(self):
        """Test behavior with empty directory."""
        detected = self.language_detector.detect_languages()
        self.assertEqual(detected, {})
        
        primary = self.language_detector.get_primary_language()
        self.assertEqual(primary, "unknown")


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete scanner."""
    
    @patch('scanner.core.repository.GitHubRepository.clone')
    @patch('scanner.scanners.python_scanner.PythonScanner.scan_directory')
    def test_scan_workflow(self, mock_scan, mock_clone):
        """Test the complete scan workflow with mocked components."""
        # Mock successful repository clone
        mock_clone.return_value = True
        
        # Mock scan results
        from scanner.models.scan_result import ToolScanResult, ScanStatus
        mock_scan.return_value = ToolScanResult(
            tool_name="bandit",
            status=ScanStatus.COMPLETED,
            issues_found=2,
            execution_time_seconds=1.5
        )
        
        # Create scanner manager
        scanner_manager = SecurityScannerManager()
        
        # Mock the temporary directory and language detection
        with patch('scanner.utils.file_utils.FileManager.temporary_directory') as mock_temp_dir:
            with patch('scanner.utils.language_detector.LanguageDetector.detect_languages') as mock_detect:
                mock_temp_dir.return_value.__enter__.return_value = "/tmp/test"
                mock_detect.return_value = {"python": ["main.py", "utils.py"]}
                
                # Run scan
                result = scanner_manager.scan_repository("https://github.com/user/repo")
                
                # Verify results
                self.assertEqual(result.status, ScanStatus.COMPLETED)
                self.assertEqual(result.repository_url, "https://github.com/user/repo")
                self.assertIn("python", result.tool_results)
                self.assertEqual(result.tool_results["python"].issues_found, 2)


def run_comprehensive_tests():
    """Run all tests and generate a test report."""
    print("🧪 Running SecureThread Scanner Test Suite")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestSecurityScannerManager,
        TestGitHubRepository,
        TestLanguageDetector,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, stream=open(os.devnull, 'w'))
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n📊 Test Results Summary:")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print(f"\n💥 Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Error:')[-1].strip()}")
    
    if result.wasSuccessful():
        print(f"\n✅ All tests passed!")
        return True
    else:
        print(f"\n❌ Some tests failed!")
        return False


if __name__ == "__main__":
    # Run tests when script is executed directly
    success = run_comprehensive_tests()
    exit(0 if success else 1)
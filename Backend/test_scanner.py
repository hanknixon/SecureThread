# Backend/test_scanner.py
"""
Test script to demonstrate the GitHub repository scanner functionality.
This script tests the scanner with some known repositories.
"""

from repo_scanner import GitHubRepoScanner
import json
from datetime import datetime

def test_repository_scanner():
    """Test the scanner with various types of repositories."""
    
    # Test repositories - these are public repos with different languages
    test_repos = [
        {
            "name": "Simple Python Project",
            "url": "https://github.com/octocat/Hello-World",
            "description": "GitHub's Hello World repository"
        },
        {
            "name": "Vulnerable Python App (for testing)",
            "url": "https://github.com/bridgecrewio/example_vulnerable_app",
            "description": "Intentionally vulnerable Python app for security testing"
        }
    ]
    
    print("🧪 Testing GitHub Repository Scanner")
    print("=" * 60)
    
    scanner = GitHubRepoScanner()
    
    for i, repo in enumerate(test_repos, 1):
        print(f"\n📋 Test {i}: {repo['name']}")
        print(f"📖 Description: {repo['description']}")
        print(f"🔗 URL: {repo['url']}")
        print("-" * 40)
        
        try:
            # Run the scan
            results = scanner.run_full_scan(repo['url'])
            
            # Display summary
            if results.get('status') == 'failed':
                print(f"❌ Scan failed: {results.get('error', 'Unknown error')}")
                continue
            
            print(f"✅ Scan completed successfully!")
            
            # Show detected languages
            detected_langs = results.get('detected_languages', {})
            if detected_langs:
                print(f"🔍 Detected languages:")
                for lang, files in detected_langs.items():
                    print(f"  - {lang.title()}: {len(files)} files")
            
            # Show scan results summary
            scans = results.get('scans', {})
            if scans:
                print(f"🛡️ Security scan results:")
                total_issues = 0
                for scan_type, scan_result in scans.items():
                    tool = scan_result.get('tool', scan_type)
                    issues = scan_result.get('issues_found', 0)
                    total_issues += issues
                    status = scan_result.get('status', 'unknown')
                    
                    if issues > 0:
                        print(f"  - {tool.upper()}: ⚠️ {issues} issues found")
                    else:
                        print(f"  - {tool.upper()}: ✅ No issues found")
                
                print(f"📊 Total security issues found: {total_issues}")
            
            # Save detailed results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            repo_name = repo['url'].split('/')[-1]
            output_file = f"test_results_{repo_name}_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"💾 Detailed results saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Test failed with error: {str(e)}")
        
        print("\n" + "=" * 60)

def quick_test():
    """Quick test with a single small repository."""
    print("🚀 Quick Test - Scanning GitHub's Hello World repository")
    print("=" * 60)
    
    scanner = GitHubRepoScanner()
    results = scanner.run_full_scan("https://github.com/octocat/Hello-World")
    
    print("\n📊 Quick Test Results:")
    print(f"Status: {'✅ Success' if results.get('status') != 'failed' else '❌ Failed'}")
    
    if results.get('detected_languages'):
        print(f"Languages detected: {len(results['detected_languages'])}")
    
    if results.get('scans'):
        total_issues = sum(scan.get('issues_found', 0) for scan in results['scans'].values())
        print(f"Total security issues: {total_issues}")

if __name__ == "__main__":
    print("Choose a test option:")
    print("1. Quick test (single repository)")
    print("2. Full test suite (multiple repositories)")
    
    choice = input("\nEnter your choice (1 or 2): ").strip()
    
    if choice == "1":
        quick_test()
    elif choice == "2":
        test_repository_scanner()
    else:
        print("Invalid choice. Running quick test...")
        quick_test()
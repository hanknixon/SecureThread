# Backend/cli/main.py
"""
Command Line Interface for SecureThread Scanner.
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path so we can import scanner modules
sys.path.append(str(Path(__file__).parent.parent))

from scanner.core.scanner_manager import SecurityScannerManager
from scanner.models.scan_result import ScanStatus
from config.scanner_config import config


def main():
    """Main CLI entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    if args.command == "scan":
        handle_scan_command(args)
    elif args.command == "info":
        handle_info_command(args)
    elif args.command == "validate":
        handle_validate_command(args)
    else:
        parser.print_help()


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser for the CLI.
    
    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="SecureThread - Security Scanner for GitHub Repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan https://github.com/user/repo
  %(prog)s scan https://github.com/user/repo --output results.json
  %(prog)s scan https://github.com/user/repo --format summary
  %(prog)s info
  %(prog)s validate https://github.com/user/repo
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a GitHub repository")
    scan_parser.add_argument(
        "repository_url",
        help="GitHub repository URL to scan"
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file path for scan results (JSON format)"
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["full", "summary", "json"],
        default="full",
        help="Output format (default: full)"
    )
    scan_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save results to file automatically"
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=config.tool_execution_timeout,
        help=f"Tool execution timeout in seconds (default: {config.tool_execution_timeout})"
    )
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show scanner information")
    info_parser.add_argument(
        "--scanners",
        action="store_true",
        help="Show available scanners"
    )
    info_parser.add_argument(
        "--config",
        action="store_true", 
        help="Show current configuration"
    )
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a GitHub repository URL")
    validate_parser.add_argument(
        "repository_url",
        help="GitHub repository URL to validate"
    )
    
    return parser


def handle_scan_command(args) -> None:
    """
    Handle the scan command.
    
    Args:
        args: Parsed command line arguments
    """
    try:
        # Validate URL
        if not SecurityScannerManager().validate_repository_url(args.repository_url):
            print("❌ Invalid GitHub repository URL")
            print("Example: https://github.com/user/repository")
            sys.exit(1)
        
        # Update configuration if timeout specified
        if args.timeout != config.tool_execution_timeout:
            config.tool_execution_timeout = args.timeout
            print(f"🔧 Using custom timeout: {args.timeout}s")
        
        # Run scan
        scanner_manager = SecurityScannerManager()
        scan_result = scanner_manager.scan_repository(args.repository_url)
        
        # Display results
        display_scan_results(scan_result, args.format)
        
        # Save results
        if not args.no_save:
            output_file = args.output or generate_output_filename(scan_result)
            save_scan_results(scan_result, output_file)
            print(f"\n💾 Detailed results saved to: {output_file}")
        
        # Exit with appropriate code
        if scan_result.status == ScanStatus.FAILED:
            sys.exit(1)
        elif scan_result.has_high_severity_issues:
            sys.exit(2)  # High severity issues found
        else:
            sys.exit(0)  # Success
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Scan failed with error: {str(e)}")
        sys.exit(1)


def handle_info_command(args) -> None:
    """
    Handle the info command.
    
    Args:
        args: Parsed command line arguments
    """
    print("🔍 SecureThread Scanner Information")
    print("=" * 40)
    
    if args.scanners or not (args.config or args.scanners):
        print("\n📋 Available Scanners:")
        scanner_manager = SecurityScannerManager()
        scanners_info = scanner_manager.get_available_scanners()
        
        for lang, info in scanners_info.items():
            status = "✅ Available" if info["available"] else "❌ Not Available"
            print(f"  {lang.title()}: {info['name']} - {status}")
            print(f"    Supported languages: {', '.join(info['supported_languages'])}")
    
    if args.config or not (args.config or args.scanners):
        print("\n⚙️ Current Configuration:")
        print(f"  Git clone timeout: {config.git_clone_timeout}s")
        print(f"  Tool execution timeout: {config.tool_execution_timeout}s")
        print(f"  Max repository size: {config.max_repo_size_mb} MB")
        print(f"  Clone depth: {config.clone_depth}")
        print(f"  Bandit confidence level: {config.bandit_confidence_level}")
        print(f"  ESLint max warnings: {config.eslint_max_warnings}")
        print(f"  Save raw output: {config.save_raw_output}")


def handle_validate_command(args) -> None:
    """
    Handle the validate command.
    
    Args:
        args: Parsed command line arguments
    """
    print(f"🔍 Validating repository URL: {args.repository_url}")
    
    if SecurityScannerManager().validate_repository_url(args.repository_url):
        print("✅ Valid GitHub repository URL")
        sys.exit(0)
    else:
        print("❌ Invalid GitHub repository URL")
        print("Must be in format: https://github.com/owner/repository")
        sys.exit(1)


def display_scan_results(scan_result, format_type: str) -> None:
    """
    Display scan results in the specified format.
    
    Args:
        scan_result: ScanResult object
        format_type: Output format (full, summary, json)
    """
    if format_type == "json":
        print(json.dumps(scan_result.to_dict(), indent=2))
    elif format_type == "summary":
        display_summary_results(scan_result)
    else:  # full
        display_full_results(scan_result)


def display_summary_results(scan_result) -> None:
    """
    Display a summary of scan results.
    
    Args:
        scan_result: ScanResult object
    """
    print("\n" + "=" * 50)
    print("📊 SCAN SUMMARY")
    print("=" * 50)
    
    print(f"Repository: {scan_result.repository_url}")
    print(f"Status: {scan_result.status.value}")
    print(f"Total Issues: {scan_result.total_issues}")
    print(f"Duration: {scan_result.total_duration_seconds:.2f}s")
    
    if scan_result.tool_results:
        print(f"\nTools Run: {len(scan_result.tool_results)}")
        for tool_name, result in scan_result.tool_results.items():
            print(f"  - {result.tool_name}: {result.issues_found} issues")
    
    severity_breakdown = scan_result.get_issues_by_severity()
    if any(count > 0 for count in severity_breakdown.values()):
        print("\nSeverity Breakdown:")
        for severity, count in severity_breakdown.items():
            if count > 0:
                print(f"  - {severity.value.upper()}: {count}")


def display_full_results(scan_result) -> None:
    """
    Display full detailed scan results.
    
    Args:
        scan_result: ScanResult object
    """
    print("\n" + "=" * 60)
    print("📊 DETAILED SCAN RESULTS")
    print("=" * 60)
    
    print(f"Repository: {scan_result.repository_url}")
    print(f"Scan ID: {scan_result.scan_id}")
    print(f"Timestamp: {scan_result.scan_timestamp}")
    print(f"Status: {scan_result.status.value}")
    print(f"Duration: {scan_result.total_duration_seconds:.2f} seconds")
    print(f"Total Issues: {scan_result.total_issues}")
    
    # Language detection results
    if scan_result.detected_languages:
        print(f"\n🔍 Detected Languages:")
        for lang, files in scan_result.detected_languages.items():
            print(f"  - {lang}: {len(files)} files")
    
    # Tool results
    if scan_result.tool_results:
        print(f"\n🛠️ Tool Results:")
        for tool_name, result in scan_result.tool_results.items():
            print(f"\n  📋 {result.tool_name.upper()}:")
            print(f"     Status: {result.status.value}")
            print(f"     Issues Found: {result.issues_found}")
            print(f"     Execution Time: {result.execution_time_seconds:.2f}s")
            
            if result.error_message:
                print(f"     Error: {result.error_message}")
            
            # Show first few issues as examples
            if result.issues and len(result.issues) > 0:
                print(f"     Sample Issues:")
                for i, issue in enumerate(result.issues[:3]):  # Show first 3 issues
                    print(f"       {i+1}. {issue.file_path}:{issue.line_number or '?'}")
                    print(f"          Rule: {issue.rule_id}")
                    print(f"          Severity: {issue.severity.value}")
                    print(f"          Message: {issue.message[:80]}...")
                
                if len(result.issues) > 3:
                    print(f"       ... and {len(result.issues) - 3} more issues")
    
    # Severity breakdown
    severity_breakdown = scan_result.get_issues_by_severity()
    if any(count > 0 for count in severity_breakdown.values()):
        print(f"\n📈 Issues by Severity:")
        for severity, count in severity_breakdown.items():
            if count > 0:
                emoji = {
                    "low": "🟡", 
                    "medium": "🟠", 
                    "high": "🔴", 
                    "critical": "⚫"
                }.get(severity.value, "🔵")
                print(f"  {emoji} {severity.value.upper()}: {count}")
    
    # Recommendations
    if scan_result.has_high_severity_issues:
        print(f"\n⚠️ RECOMMENDATIONS:")
        print(f"  - High severity security issues detected")
        print(f"  - Review and fix critical vulnerabilities immediately")
        print(f"  - Consider running additional security tools")
    elif scan_result.total_issues > 0:
        print(f"\n💡 RECOMMENDATIONS:")
        print(f"  - Review identified issues for potential improvements")
        print(f"  - Consider implementing automated security checks in CI/CD")
    else:
        print(f"\n✅ EXCELLENT:")
        print(f"  - No security issues detected by automated scans")
        print(f"  - Continue following security best practices")


def save_scan_results(scan_result, output_file: str) -> None:
    """
    Save scan results to a JSON file.
    
    Args:
        scan_result: ScanResult object
        output_file: Path to output file
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(scan_result.to_dict(), f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Warning: Could not save results to {output_file}: {str(e)}")


def generate_output_filename(scan_result) -> str:
    """
    Generate an output filename based on scan results.
    
    Args:
        scan_result: ScanResult object
        
    Returns:
        Generated filename
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Extract repository name from URL
    repo_name = "unknown"
    try:
        repo_name = scan_result.repository_url.split('/')[-1].replace('.git', '')
    except (AttributeError, IndexError):
        # Handle cases where URL is malformed or None
        repo_name = "unknown"
    
    return f"scan_results_{repo_name}_{timestamp}.json"


if __name__ == "__main__":
    main()
# Backend/scanner/models/scan_result.py
"""
Data models for scan results and related structures.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime


class ScanStatus(Enum):
    """Enumeration of possible scan statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class SeverityLevel(Enum):
    """Enumeration of security issue severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityIssue:
    """Represents a single security issue found during scanning."""
    
    file_path: str
    line_number: Optional[int]
    rule_id: str
    message: str
    severity: SeverityLevel
    confidence: str
    tool: str
    category: Optional[str] = None
    cwe_id: Optional[str] = None
    more_info_url: Optional[str] = None


@dataclass
class ToolScanResult:
    """Represents the result from a single scanning tool."""
    
    tool_name: str
    status: ScanStatus
    issues_found: int
    execution_time_seconds: float
    issues: List[SecurityIssue] = field(default_factory=list)
    error_message: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """Complete scan result for a repository."""
    
    repository_url: str
    scan_id: str
    scan_timestamp: datetime
    total_duration_seconds: float
    detected_languages: Dict[str, List[str]]
    tool_results: Dict[str, ToolScanResult] = field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    
    @property
    def total_issues(self) -> int:
        """Calculate total number of issues across all tools."""
        return sum(result.issues_found for result in self.tool_results.values())
    
    @property
    def has_high_severity_issues(self) -> bool:
        """Check if any high or critical severity issues were found."""
        for tool_result in self.tool_results.values():
            for issue in tool_result.issues:
                if issue.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                    return True
        return False
    
    def get_issues_by_severity(self) -> Dict[SeverityLevel, int]:
        """Group issues by severity level."""
        severity_counts = {level: 0 for level in SeverityLevel}
        
        for tool_result in self.tool_results.values():
            for issue in tool_result.issues:
                severity_counts[issue.severity] += 1
        
        return severity_counts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary for JSON serialization."""
        return {
            "repository_url": self.repository_url,
            "scan_id": self.scan_id,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "total_duration_seconds": self.total_duration_seconds,
            "detected_languages": self.detected_languages,
            "status": self.status.value,
            "total_issues": self.total_issues,
            "severity_breakdown": {
                level.value: count 
                for level, count in self.get_issues_by_severity().items()
            },
            "tool_results": {
                tool_name: {
                    "tool_name": result.tool_name,
                    "status": result.status.value,
                    "issues_found": result.issues_found,
                    "execution_time_seconds": result.execution_time_seconds,
                    "error_message": result.error_message,
                    "issues": [
                        {
                            "file_path": issue.file_path,
                            "line_number": issue.line_number,
                            "rule_id": issue.rule_id,
                            "message": issue.message,
                            "severity": issue.severity.value,
                            "confidence": issue.confidence,
                            "tool": issue.tool,
                            "category": issue.category,
                            "cwe_id": issue.cwe_id,
                            "more_info_url": issue.more_info_url
                        }
                        for issue in result.issues
                    ]
                }
                for tool_name, result in self.tool_results.items()
            }
        }


@dataclass
class RepositoryInfo:
    """Information about a scanned repository."""
    
    url: str
    name: str
    owner: str
    branch: str = "main"
    commit_hash: Optional[str] = None
    size_mb: Optional[float] = None
    file_count: Optional[int] = None
from pydantic import BaseModel
from typing import List, Optional
from enum import Enum

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LogEntry(BaseModel):
    line_number: int
    timestamp: Optional[str] = None
    raw_line: str
    log_type: str

class Alert(BaseModel):
    severity: SeverityLevel
    title: str
    description: str
    affected_lines: List[int]
    recommendation: str

class AnalysisResult(BaseModel):
    total_lines: int
    suspicious_lines: int
    alerts: List[Alert]
    summary: str
    log_type: str
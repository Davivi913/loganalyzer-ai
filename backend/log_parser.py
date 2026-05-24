import re
from typing import List, Tuple
from models import LogEntry

LOG_PATTERNS = {
    "auth": [
        r"Failed password",
        r"Invalid user",
        r"authentication failure",
        r"FAILED LOGIN",
        r"sudo:.*FAILED",
        r"pam_unix.*failure",
    ],
    "nginx": [
        r'" 4\d{2} ',
        r'" 5\d{2} ',
        r'sql|select|union|insert|drop',
        r'\.\./\.\.',
        r'<script|javascript:',
        r'etc/passwd',
    ],
    "syslog": [
        r"error",
        r"critical",
        r"segfault",
        r"out of memory",
        r"oom",
        r"killed process",
        r"failed",
        r"corrupt",
        r"CVE-",
        r"flood",
        r"vulnerability",
    ],
}

def detect_log_type(content: str) -> str:
    lines = content.lower()
    if "failed password" in lines or "sshd" in lines or "pam_unix" in lines:
        return "auth"
    if '"get ' in lines or '"post ' in lines or "nginx" in lines or "http/1" in lines:
        return "nginx"
    return "syslog"

def extract_timestamp(line: str):
    patterns = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
    ]
    for p in patterns:
        m = re.search(p, line)
        if m:
            return m.group()
    return None

def parse_logs(content: str) -> Tuple[List[LogEntry], str, List[str]]:
    log_type = detect_log_type(content)
    patterns = LOG_PATTERNS.get(log_type, LOG_PATTERNS["syslog"])
    entries = []
    suspicious_lines = []
    for i, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        entry = LogEntry(
            line_number=i,
            timestamp=extract_timestamp(line),
            raw_line=line.strip(),
            log_type=log_type
        )
        entries.append(entry)
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                suspicious_lines.append(line.strip())
                break
    return entries, log_type, suspicious_lines
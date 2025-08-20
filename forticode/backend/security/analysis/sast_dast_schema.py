"""
SAST/DAST 결과 통합 스키마
FortiCode에서 다양한 보안 도구의 결과를 통합하기 위한 표준 스키마
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import hashlib
import json

class Severity(Enum):
    """보안 취약점 심각도"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ToolType(Enum):
    """보안 도구 유형"""
    SAST = "sast"      # 정적 분석
    DAST = "dast"      # 동적 분석
    SCA = "sca"        # 소프트웨어 구성 분석
    IAST = "iast"      # 상호작용 분석

class Language(Enum):
    """프로그래밍 언어"""
    PYTHON = "python"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    CSHARP = "csharp"
    WEB = "web"        # HTML/CSS/JS 통합

@dataclass
class SecurityFinding:
    """보안 취약점 발견 결과"""
    finding_id: str                    # 고유 식별자
    source: str                        # 도구명 (bandit, spotbugs, zap 등)
    tool: ToolType                     # 도구 유형
    rule_id: str                       # 규칙 ID
    cwe: Optional[str]                 # CWE ID (예: CWE-89)
    severity: Severity                 # 심각도
    language: Language                 # 프로그래밍 언어
    file_path: Optional[str]           # 파일 경로
    line_number: Optional[int]         # 라인 번호
    endpoint: Optional[str]            # API 엔드포인트 (웹용)
    message: str                       # 취약점 설명
    evidence: str                      # 취약한 코드 스니펫
    secure_coding_guide: Optional[str] = None  # 보안 코딩 가이드
    links: List[str] = field(default_factory=list)  # 관련 링크
    metadata: Dict[str, Any] = field(default_factory=dict)  # 추가 메타데이터
    
    def __post_init__(self):
        """finding_id 자동 생성"""
        if not self.finding_id:
            # 파일경로+라인+룰ID+메시지 해시로 중복제거
            content = f"{self.file_path}:{self.line_number}:{self.rule_id}:{self.message}"
            self.finding_id = hashlib.md5(content.encode()).hexdigest()[:8]
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "tool": self.tool.value,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity.value,
            "language": self.language.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "endpoint": self.endpoint,
            "message": self.message,
            "evidence": self.evidence,
            "secure_coding_guide": self.secure_coding_guide,
            "links": self.links,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """딕셔너리에서 생성"""
        return cls(
            finding_id=data.get('finding_id'),
            source=data['source'],
            tool=ToolType(data['tool']),
            rule_id=data['rule_id'],
            cwe=data.get('cwe'),
            severity=Severity(data['severity']),
            language=Language(data['language']),
            file_path=data.get('file_path'),
            line_number=data.get('line_number'),
            endpoint=data.get('endpoint'),
            message=data['message'],
            evidence=data['evidence'],
            secure_coding_guide=data.get('secure_coding_guide'),
            links=data.get('links', []),
            metadata=data.get('metadata', {})
        )

@dataclass
class ScanResult:
    """스캔 결과 집계"""
    scan_id: str                       # 스캔 세션 ID
    timestamp: str                     # 스캔 시작 시간
    tool_results: List[SecurityFinding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: SecurityFinding):
        """발견 결과 추가"""
        self.tool_results.append(finding)
    
    def get_findings_by_severity(self, severity: Severity) -> List[SecurityFinding]:
        """심각도별 결과 필터링"""
        return [f for f in self.tool_results if f.severity == severity]
    
    def get_findings_by_cwe(self, cwe: str) -> List[SecurityFinding]:
        """CWE별 결과 필터링"""
        return [f for f in self.tool_results if f.cwe == cwe]
    
    def get_findings_by_language(self, language: Language) -> List[SecurityFinding]:
        """언어별 결과 필터링"""
        return [f for f in self.tool_results if f.language == language]
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "tool_results": [f.to_dict() for f in self.tool_results],
            "summary": {
                "total_findings": len(self.tool_results),
                "by_severity": {
                    sev.value: len(self.get_findings_by_severity(sev))
                    for sev in Severity
                },
                "by_language": {
                    lang.value: len(self.get_findings_by_language(lang))
                    for lang in Language
                },
                "by_cwe": {
                    cwe: len(self.get_findings_by_cwe(cwe))
                    for cwe in set(f.cwe for f in self.tool_results if f.cwe)
                }
            }
        }

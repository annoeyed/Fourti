"""
LLM 기반 보안 분석기
기존 SAST/DAST 도구 대신 LLM을 사용하여 코드 보안을 분석하는 모듈
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import re

from langchain.chat_models import ChatOpenAI, ChatAnthropic
from langchain.schema import HumanMessage, SystemMessage
from langchain.prompts import ChatPromptTemplate

from ..cwe.cwe_database import CWEDatabase, CWEItem

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """보안 수준을 나타내는 열거형"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityIssue:
    """보안 이슈를 나타내는 데이터 클래스"""
    cwe_id: str
    severity: SecurityLevel
    description: str
    line_number: Optional[int]
    code_snippet: str
    risk_score: float
    mitigation: str
    confidence: float

@dataclass
class SecurityAnalysisResult:
    """보안 분석 결과를 나타내는 데이터 클래스"""
    overall_score: float
    issues: List[SecurityIssue]
    recommendations: List[str]
    cwe_summary: Dict[str, int]
    risk_level: SecurityLevel

class LLMSecurityAnalyzer:
    """LLM 기반 보안 분석기"""
    
    def __init__(self, 
                 openai_api_key: Optional[str] = None,
                 anthropic_api_key: Optional[str] = None,
                 model_name: str = "gpt-4"):
        self.cwe_db = CWEDatabase()
        self.model_name = model_name
        
        # LLM 초기화
        if openai_api_key:
            self.llm = ChatOpenAI(
                model_name=model_name,
                openai_api_key=openai_api_key,
                temperature=0.1
            )
        elif anthropic_api_key:
            self.llm = ChatAnthropic(
                model_name="claude-3-opus-20240229",
                anthropic_api_key=anthropic_api_key,
                temperature=0.1
            )
        else:
            raise ValueError("Either OpenAI or Anthropic API key must be provided")
        
        # 보안 분석을 위한 시스템 프롬프트
        self.security_system_prompt = self._create_security_system_prompt()
        
    def _create_security_system_prompt(self) -> str:
        """보안 분석을 위한 시스템 프롬프트 생성"""
        return """당신은 20년 경력의 시니어 보안 아키텍트입니다. 
OWASP Top 10, CWE/SANS Top 25를 완벽하게 이해하고 있으며, 
코드의 효율성보다 안정성과 보안을 최우선으로 고려합니다.

주요 보안 취약점 패턴:
1. CWE-79 (XSS): 사용자 입력 검증 부족, 출력 인코딩 미적용
2. CWE-89 (SQL Injection): 사용자 입력을 SQL에 직접 삽입
3. CWE-200 (Information Exposure): 민감한 정보 노출
4. CWE-22 (Path Traversal): 경로 조작 공격
5. CWE-78 (OS Command Injection): OS 명령어 주입
6. CWE-434 (Unrestricted Upload): 무제한 파일 업로드
7. CWE-287 (Authentication Bypass): 인증 우회
8. CWE-311 (Missing Encryption): 암호화 부족

분석 시 다음을 고려하세요:
- 입력 검증 및 이스케이핑
- 인증 및 권한 관리
- 데이터 암호화 및 보호
- 에러 처리 및 로깅
- 안전한 라이브러리 사용

JSON 형식으로 응답하세요:
{
    "issues": [
        {
            "cwe_id": "CWE-79",
            "severity": "high",
            "description": "사용자 입력이 HTML에 직접 삽입되어 XSS 공격 가능",
            "line_number": 15,
            "code_snippet": "user_input",
            "risk_score": 9.0,
            "mitigation": "html.escape() 사용하여 입력 이스케이핑",
            "confidence": 0.95
        }
    ],
    "overall_score": 7.5,
    "recommendations": ["입력 검증 강화", "출력 인코딩 적용"],
    "risk_level": "medium"
}"""

    def analyze_code(self, 
                    code: str, 
                    language: str = "python",
                    context: str = "") -> SecurityAnalysisResult:
        """코드 보안 분석 수행"""
        try:
            # 컨텍스트 정보와 함께 분석 프롬프트 생성
            analysis_prompt = self._create_analysis_prompt(code, language, context)
            
            # LLM을 통한 분석 수행
            response = self.llm.invoke([
                SystemMessage(content=self.security_system_prompt),
                HumanMessage(content=analysis_prompt)
            ])
            
            # 응답 파싱 및 결과 생성
            analysis_result = self._parse_llm_response(response.content)
            
            # CWE 데이터베이스와 연동하여 상세 정보 보강
            enriched_result = self._enrich_with_cwe_data(analysis_result)
            
            return enriched_result
            
        except Exception as e:
            logger.error(f"Error during security analysis: {e}")
            return self._create_error_result(str(e))
    
    def _create_analysis_prompt(self, code: str, language: str, context: str) -> str:
        """분석을 위한 프롬프트 생성"""
        prompt = f"""
다음 {language} 코드의 보안 취약점을 분석해주세요:

코드:
```{language}
{code}
```

컨텍스트: {context if context else "웹 애플리케이션"}

위 코드에서 발견되는 모든 보안 취약점을 식별하고, 각각에 대해 CWE ID, 심각도, 설명, 수정 방안을 제시해주세요.
"""
        return prompt
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """LLM 응답을 파싱하여 구조화된 데이터로 변환"""
        try:
            # JSON 응답 추출 시도
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # JSON이 아닌 경우 기본 구조 반환
                return self._parse_text_response(response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response, falling back to text parsing")
            return self._parse_text_response(response)
    
    def _parse_text_response(self, response: str) -> Dict[str, Any]:
        """텍스트 응답을 파싱하여 기본 구조 생성"""
        # 간단한 텍스트 파싱 로직
        issues = []
        recommendations = []
        
        # CWE 패턴 찾기
        cwe_pattern = r'CWE-\d+'
        cwe_matches = re.findall(cwe_pattern, response)
        
        for cwe_id in cwe_matches:
            issue = {
                "cwe_id": cwe_id,
                "severity": "medium",
                "description": f"Potential security issue related to {cwe_id}",
                "line_number": None,
                "code_snippet": "Unknown",
                "risk_score": 5.0,
                "mitigation": "Review and fix according to CWE guidelines",
                "confidence": 0.7
            }
            issues.append(issue)
        
        return {
            "issues": issues,
            "overall_score": 5.0,
            "recommendations": recommendations,
            "risk_level": "medium"
        }
    
    def _enrich_with_cwe_data(self, analysis_result: Dict[str, Any]) -> SecurityAnalysisResult:
        """CWE 데이터베이스 정보로 분석 결과 보강"""
        enriched_issues = []
        cwe_summary = {}
        
        for issue_data in analysis_result.get("issues", []):
            cwe_id = issue_data.get("cwe_id", "")
            cwe_item = self.cwe_db.get_cwe(cwe_id)
            
            if cwe_item:
                # CWE 데이터베이스 정보로 보강
                enriched_issue = SecurityIssue(
                    cwe_id=cwe_id,
                    severity=SecurityLevel(issue_data.get("severity", "medium")),
                    description=cwe_item.description,
                    line_number=issue_data.get("line_number"),
                    code_snippet=issue_data.get("code_snippet", ""),
                    risk_score=cwe_item.risk_score,
                    mitigation="\n".join(cwe_item.mitigations),
                    confidence=issue_data.get("confidence", 0.8)
                )
                
                # CWE 요약 통계 업데이트
                cwe_summary[cwe_id] = cwe_summary.get(cwe_id, 0) + 1
            else:
                # CWE 정보가 없는 경우 기본 정보 사용
                enriched_issue = SecurityIssue(
                    cwe_id=cwe_id,
                    severity=SecurityLevel(issue_data.get("severity", "medium")),
                    description=issue_data.get("description", "Unknown security issue"),
                    line_number=issue_data.get("line_number"),
                    code_snippet=issue_data.get("code_snippet", ""),
                    risk_score=issue_data.get("risk_score", 5.0),
                    mitigation=issue_data.get("mitigation", "Review and fix"),
                    confidence=issue_data.get("confidence", 0.7)
                )
            
            enriched_issues.append(enriched_issue)
        
        # 전체 위험도 계산
        if enriched_issues:
            avg_risk_score = sum(issue.risk_score for issue in enriched_issues) / len(enriched_issues)
            if avg_risk_score >= 8.0:
                risk_level = SecurityLevel.CRITICAL
            elif avg_risk_score >= 6.0:
                risk_level = SecurityLevel.HIGH
            elif avg_risk_score >= 4.0:
                risk_level = SecurityLevel.MEDIUM
            elif avg_risk_score >= 2.0:
                risk_level = SecurityLevel.LOW
            else:
                risk_level = SecurityLevel.SAFE
        else:
            avg_risk_score = 0.0
            risk_level = SecurityLevel.SAFE
        
        return SecurityAnalysisResult(
            overall_score=avg_risk_score,
            issues=enriched_issues,
            recommendations=analysis_result.get("recommendations", []),
            cwe_summary=cwe_summary,
            risk_level=risk_level
        )
    
    def _create_error_result(self, error_message: str) -> SecurityAnalysisResult:
        """에러 발생 시 기본 결과 생성"""
        return SecurityAnalysisResult(
            overall_score=0.0,
            issues=[],
            recommendations=[f"Analysis failed: {error_message}"],
            cwe_summary={},
            risk_level=SecurityLevel.SAFE
        )
    
    def get_security_recommendations(self, issues: List[SecurityIssue]) -> List[str]:
        """보안 이슈에 대한 구체적인 권장사항 생성"""
        recommendations = []
        
        for issue in issues:
            cwe_item = self.cwe_db.get_cwe(issue.cwe_id)
            if cwe_item:
                recommendations.extend(cwe_item.mitigations)
            else:
                recommendations.append(f"Review and fix {issue.cwe_id}: {issue.description}")
        
        return list(set(recommendations))  # 중복 제거
    
    def generate_security_report(self, result: SecurityAnalysisResult) -> str:
        """보안 분석 결과를 리포트 형태로 생성"""
        report = f"""
# 보안 분석 리포트

## 전체 보안 점수: {result.overall_score:.1f}/10.0
## 위험 수준: {result.risk_level.value.upper()}

## 발견된 보안 이슈: {len(result.issues)}개

"""
        
        for i, issue in enumerate(result.issues, 1):
            report += f"""
### {i}. {issue.cwe_id}: {issue.description}
- **심각도**: {issue.severity.value.upper()}
- **위험도 점수**: {issue.risk_score}/10.0
- **신뢰도**: {issue.confidence:.1%}
- **코드 위치**: {issue.line_number if issue.line_number else 'Unknown'}
- **수정 방안**: {issue.mitigation}

"""
        
        if result.recommendations:
            report += "## 권장사항\n"
            for rec in result.recommendations:
                report += f"- {rec}\n"
        
        return report

# 사용 예시
if __name__ == "__main__":
    # 분석기 초기화 (API 키 필요)
    # analyzer = LLMSecurityAnalyzer(openai_api_key="your_key_here")
    
    # 테스트 코드
    test_code = """
@app.route('/search')
def search():
    query = request.args.get('q')
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    return execute_query(sql)
"""
    
    print("Security Analysis Test")
    print("=" * 50)
    print("Test Code:")
    print(test_code)
    print("\nNote: Set your API key to run actual analysis")

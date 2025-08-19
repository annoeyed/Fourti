"""
LLM 기반 보안 패치 생성기
SAST/DAST 결과와 RAG 컨텍스트를 기반으로 자동 패치 제안
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
import re

from langchain_openai.chat_models import ChatOpenAI
from langchain_anthropic.chat_models import ChatAnthropicMessages
from langchain_core.messages import HumanMessage, SystemMessage

from ..security.analysis.sast_dast_schema import SecurityFinding, Language, Severity
from ..rag.rag_search_adapter import RAGSearchResult

logger = logging.getLogger(__name__)

@dataclass
class PatchProposal:
    """패치 제안 결과"""
    finding_id: str                    # 원본 발견 결과 ID
    explanation: str                    # 위험 요약 (2~3줄)
    diff: str                          # git apply 가능한 unified diff
    test_snippet: str                  # 미니 재현/회귀 테스트
    commit_message: str                # 커밋 메시지 (한 줄)
    commit_body: str                   # 커밋 본문
    confidence: float                  # 패치 신뢰도 (0.0~1.0)
    risk_assessment: str               # 패치 후 위험도 평가
    alternative_approaches: List[str]  # 대안적 접근 방법

class LLMPatchGenerator:
    """LLM 기반 보안 패치 생성기"""
    
    def __init__(self, 
                 openai_api_key: Optional[str] = None,
                 anthropic_api_key: Optional[str] = None,
                 model_name: str = "gpt-4"):
        self.model_name = model_name
        
        # LLM 초기화
        if openai_api_key:
            self.llm = ChatOpenAI(
                model_name=model_name,
                openai_api_key=openai_api_key,
                temperature=0.1
            )
        elif anthropic_api_key:
            self.llm = ChatAnthropicMessages(
                model_name="claude-3-opus-20240229",
                anthropic_api_key=anthropic_api_key,
                temperature=0.1
            )
        else:
            raise ValueError("Either OpenAI or Anthropic API key must be provided")
        
        # 언어별 보안 가드레일
        self.language_guidelines = self._create_language_guidelines()
    
    def _create_language_guidelines(self) -> Dict[str, str]:
        """언어별 보안 가드레일 생성"""
        return {
            "python": """
Python 보안 가드레일:
1. SQL Injection 방지: parameterized query 사용, sqlite3/psycopg2의 ? 플레이스홀더
2. XSS 방지: html.escape(), markupsafe 사용
3. 경로 조작 방지: os.path.abspath(), pathlib.Path.resolve() 사용
4. 명령어 주입 방지: subprocess.run()의 shell=False, args 리스트 사용
5. 하드코딩 시크릿 방지: 환경변수, .env 파일, secrets 모듈 사용
6. 입력 검증: pydantic, marshmallow 등 스키마 검증 사용
7. 파일 업로드: 파일 확장자, MIME 타입, 크기 제한
8. 인증/권한: Flask-Login, Django Auth, JWT 토큰 검증
""",
            "java": """
Java 보안 가드레일:
1. SQL Injection 방지: PreparedStatement 사용, JPA/Hibernate의 파라미터 바인딩
2. XSS 방지: OWASP Java Encoder, JSTL c:out 사용
3. 경로 조작 방지: Path.normalize(), File.getCanonicalPath() 사용
4. 명령어 주입 방지: ProcessBuilder 사용, Runtime.exec() 피하기
5. 하드코딩 시크릿 방지: 환경변수, Spring @Value, ConfigurationProperties
6. 입력 검증: Bean Validation (JSR-303), @Valid, @NotNull 등
7. 파일 업로드: MultipartFile 검증, 파일 타입/크기 제한
8. 인증/권한: Spring Security, JAAS, JWT 토큰 검증
""",
            "cpp": """
C/C++ 보안 가드레일:
1. 버퍼 오버플로우 방지: strncpy_s, strncat_s 등 안전한 API 사용
2. 포맷 스트링 공격 방지: printf 포맷 문자열 검증
3. 정수 오버플로우 방지: size_t, uint64_t 등 적절한 타입 사용
4. 메모리 관리: RAII, 스마트 포인터, unique_ptr/shared_ptr 사용
5. 경계 검사: 배열 인덱스, 포인터 범위 검증
6. 입력 검증: 사용자 입력 길이, 타입, 범위 검증
7. 에러 처리: 예외 처리, 에러 코드 반환
8. 암호화: OpenSSL, libsodium 등 검증된 라이브러리 사용
""",
            "javascript": """
JavaScript/Node.js 보안 가드레일:
1. XSS 방지: DOMPurify, xss 라이브러리 사용
2. SQL Injection 방지: ORM 사용 (Sequelize, Prisma), 파라미터 바인딩
3. NoSQL Injection 방지: MongoDB ObjectId 검증, 쿼리 파라미터 검증
4. 명령어 주입 방지: child_process.execFile() 사용, shell 옵션 false
5. 경로 조작 방지: path.resolve(), path.join() 사용
6. 입력 검증: Joi, Yup, Zod 등 스키마 검증 사용
7. 파일 업로드: multer 미들웨어, 파일 타입/크기 제한
8. 인증/세션: JWT 토큰, bcrypt 해싱, 세션 고정 방지
""",
            "web": """
웹 보안 가드레일:
1. CSP (Content Security Policy): XSS, 인라인 스크립트 차단
2. HTTPS 강제: HSTS 헤더, 리다이렉트 설정
3. 인증/세션: CSRF 토큰, 세션 타임아웃, 로그아웃 처리
4. 입력 검증: 클라이언트/서버 양쪽 검증, 화이트리스트 방식
5. 파일 업로드: 허용된 확장자만, 바이러스 스캔
6. 에러 처리: 상세한 에러 메시지 노출 금지
7. 로깅: 민감한 정보 로깅 금지, 로그 무결성 보장
8. 헤더 보안: X-Frame-Options, X-Content-Type-Options 등
"""
        }
    
    def generate_patch(self, 
                       finding: SecurityFinding, 
                       rag_context: List[RAGSearchResult],
                       code_snippet: Optional[str] = None) -> PatchProposal:
        """
        보안 취약점에 대한 패치 제안 생성
        
        Args:
            finding: 보안 취약점 발견 결과
            rag_context: RAG 검색 결과 컨텍스트
            code_snippet: 취약한 코드 스니펫 (가능시)
            
        Returns:
            패치 제안 결과
        """
        try:
            # 언어별 가드레일 가져오기
            language = finding.language.value if finding.language else "python"
            guidelines = self.language_guidelines.get(language, self.language_guidelines["python"])
            
            # RAG 컨텍스트를 프롬프트에 포함
            rag_summary = self._format_rag_context(rag_context)
            
            # 패치 생성 프롬프트 구성
            system_prompt = self._create_patch_system_prompt(guidelines, rag_summary)
            user_prompt = self._create_patch_user_prompt(finding, code_snippet)
            
            # LLM 호출
            response = self.llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # 응답 파싱
            patch_data = self._parse_patch_response(response.content)
            
            # 패치 제안 객체 생성
            return PatchProposal(
                finding_id=finding.finding_id,
                explanation=patch_data.get("explanation", ""),
                diff=patch_data.get("diff", ""),
                test_snippet=patch_data.get("test_snippet", ""),
                commit_message=patch_data.get("commit_message", ""),
                commit_body=patch_data.get("commit_body", ""),
                confidence=patch_data.get("confidence", 0.5),
                risk_assessment=patch_data.get("risk_assessment", ""),
                alternative_approaches=patch_data.get("alternative_approaches", [])
            )
            
        except Exception as e:
            logger.error(f"패치 생성 중 오류 발생: {e}")
            # 기본 패치 제안 반환
            return self._create_fallback_patch(finding)
    
    def _format_rag_context(self, rag_context: List[RAGSearchResult]) -> str:
        """RAG 컨텍스트를 프롬프트용으로 포맷팅"""
        if not rag_context:
            return "관련 보안 정보가 없습니다."
        
        context_parts = []
        for i, result in enumerate(rag_context[:2], 1):  # 상위 2개만 사용
            context_parts.append(f"""
{i}. {result.cwe_id}: {result.name}
   설명: {result.excerpt[:300]}...
   완화 방안: {', '.join(result.mitigations[:2])}
""")
        
        return "\n".join(context_parts)
    
    def _create_patch_system_prompt(self, guidelines: str, rag_summary: str) -> str:
        """패치 생성을 위한 시스템 프롬프트"""
        return f"""당신은 20년 경력의 시니어 보안 아키텍트입니다.
보안 취약점을 안전하고 효과적으로 수정하는 전문가입니다.

{guidelines}

RAG 컨텍스트 (최신 보안 지식):
{rag_summary}

패치 생성 시 다음 원칙을 반드시 준수하세요:
1. Two-Step Generation: 보안 골격 → 기능 로직 순서로 생성
2. Critique: 생성된 패치의 잠재적 문제점 분석
3. Improve: 문제점을 해결한 최종 패치 생성
4. 테스트 가능성: 재현/회귀 테스트 코드 포함
5. 가독성: 명확한 주석과 설명 포함

출력은 반드시 다음 JSON 형식을 따라야 합니다:
{{
    "explanation": "2-3줄 위험 요약",
    "diff": "git apply 가능한 unified diff",
    "test_snippet": "미니 재현/회귀 테스트",
    "commit_message": "한 줄 커밋 메시지",
    "commit_body": "상세 커밋 설명",
    "confidence": 0.0-1.0,
    "risk_assessment": "패치 후 위험도 평가",
    "alternative_approaches": ["대안1", "대안2"]
}}"""
    
    def _create_patch_user_prompt(self, finding: SecurityFinding, code_snippet: Optional[str]) -> str:
        """패치 생성을 위한 사용자 프롬프트"""
        prompt = f"""
보안 취약점을 수정해주세요:

발견 정보:
- 도구: {finding.source}
- 규칙: {finding.rule_id}
- CWE: {finding.cwe or 'Unknown'}
- 심각도: {finding.severity.value}
- 언어: {finding.language.value if finding.language else 'Unknown'}
- 메시지: {finding.message}
- 증거: {finding.evidence}
"""
        
        if code_snippet:
            prompt += f"""
취약한 코드:
```{finding.language.value if finding.language else 'python'}
{code_snippet}
```
"""
        
        prompt += """
위의 보안 취약점을 수정하여 안전한 코드를 생성해주세요.
수정된 코드는 반드시 git diff 형식으로 제공해야 합니다.
"""
        
        return prompt
    
    def _parse_patch_response(self, response_content: str) -> Dict[str, Any]:
        """LLM 응답을 파싱하여 패치 데이터 추출"""
        try:
            # JSON 블록 찾기
            json_match = re.search(r'```json\s*(.*?)\s*```', response_content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            
            # JSON 형식이 없으면 전체 응답을 파싱 시도
            if response_content.strip().startswith('{'):
                return json.loads(response_content)
            
        except json.JSONDecodeError as e:
            logger.warning(f"JSON 파싱 실패: {e}")
        
        # 파싱 실패 시 기본값 반환
        return {
            "explanation": "패치 생성 중 오류가 발생했습니다.",
            "diff": "",
            "test_snippet": "",
            "commit_message": "security: fix vulnerability",
            "commit_body": "보안 취약점 수정",
            "confidence": 0.3,
            "risk_assessment": "패치 검증 필요",
            "alternative_approaches": []
        }
    
    def _create_fallback_patch(self, finding: SecurityFinding) -> PatchProposal:
        """기본 패치 제안 생성 (오류 시)"""
        return PatchProposal(
            finding_id=finding.finding_id,
            explanation=f"{finding.message} - 자동 패치 생성에 실패했습니다. 수동 검토가 필요합니다.",
            diff="",
            test_snippet="",
            commit_message=f"security: review {finding.rule_id}",
            commit_body=f"보안 취약점 {finding.rule_id} 수동 검토 필요",
            confidence=0.1,
            risk_assessment="패치 검증 필요",
            alternative_approaches=["수동 코드 리뷰", "보안 전문가 상담"]
        )
    
    def batch_generate_patches(self, 
                              findings: List[SecurityFinding],
                              rag_contexts: Dict[str, List[RAGSearchResult]],
                              code_snippets: Optional[Dict[str, str]] = None) -> List[PatchProposal]:
        """여러 발견 결과에 대한 배치 패치 생성"""
        patches = []
        
        for finding in findings:
            rag_context = rag_contexts.get(finding.finding_id, [])
            code_snippet = code_snippets.get(finding.finding_id) if code_snippets else None
            
            patch = self.generate_patch(finding, rag_context, code_snippet)
            patches.append(patch)
        
        return patches
    
    def validate_patch(self, patch: PatchProposal) -> Dict[str, Any]:
        """패치 제안의 유효성 검증"""
        validation_result = {
            "is_valid": True,
            "issues": [],
            "warnings": [],
            "score": 0.0
        }
        
        # 1. 필수 필드 검증
        required_fields = ["explanation", "diff", "test_snippet", "commit_message"]
        for field in required_fields:
            if not getattr(patch, field):
                validation_result["is_valid"] = False
                validation_result["issues"].append(f"Missing required field: {field}")
        
        # 2. diff 형식 검증
        if patch.diff:
            if not patch.diff.startswith("diff --git") and not patch.diff.startswith("---"):
                validation_result["warnings"].append("Diff format may not be standard git diff")
        
        # 3. 신뢰도 점수 검증
        if patch.confidence < 0.3:
            validation_result["warnings"].append("Low confidence patch - manual review recommended")
        
        # 4. 점수 계산
        score = 0.0
        if patch.explanation: score += 0.2
        if patch.diff: score += 0.3
        if patch.test_snippet: score += 0.2
        if patch.commit_message: score += 0.1
        if patch.confidence > 0.7: score += 0.2
        
        validation_result["score"] = min(1.0, score)
        
        return validation_result

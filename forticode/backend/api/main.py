"""
FortiCode 메인 API 서버
LLM 기반 보안 코드 분석 및 생성 서비스
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import logging
import os
from dotenv import load_dotenv
from datetime import datetime

# 상대 경로 import를 위한 설정
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.analysis.llm_security_analyzer import LLMSecurityAnalyzer, SecurityAnalysisResult
from security.cwe.cwe_database import CWEDatabase
from security.analysis.sast_dast_schema import SecurityFinding, ScanResult, ParserFactory, ToolType, Severity, Language
from security.analysis.patch_applier import PatchApplier
from rag.rag_search_adapter import RAGSearchAdapter
from llm.patch_generator import LLMPatchGenerator

# 환경 변수 로드
load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI 앱 생성
app = FastAPI(
    title="FortiCode API",
    description="LLM 기반 보안 코드 분석 및 생성 서비스",
    version="1.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic 모델들
class CodeAnalysisRequest(BaseModel):
    code: str
    language: str = "python"
    context: str = ""
    include_fixes: bool = True

class CodeGenerationRequest(BaseModel):
    description: str
    language: str = "python"
    security_requirements: List[str] = []
    include_tests: bool = False

class SecurityFixRequest(BaseModel):
    code: str
    language: str = "python"
    cwe_ids: List[str] = []

# 새로운 Pydantic 모델들
class SecurityScanRequest(BaseModel):
    tool_results: Dict[str, str]  # 도구명: 결과파일경로
    include_patches: bool = True
    auto_apply: bool = False

class PatchGenerationRequest(BaseModel):
    finding_ids: List[str]
    include_code_snippets: bool = True

class PatchApplicationRequest(BaseModel):
    finding_id: str
    patch_id: str
    auto_create_pr: bool = True

# 전역 변수들
analyzer: Optional[LLMSecurityAnalyzer] = None
cwe_db: Optional[CWEDatabase] = None
rag_adapter: Optional[RAGSearchAdapter] = None
patch_generator: Optional[LLMPatchGenerator] = None
patch_applier: Optional[PatchApplier] = None

def get_analyzer() -> LLMSecurityAnalyzer:
    """보안 분석기 인스턴스 반환"""
    global analyzer
    if analyzer is None:
        openai_key = os.getenv("OPENAI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        
        if not openai_key and not anthropic_key:
            raise HTTPException(
                status_code=500,
                detail="API key not configured. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY"
            )
        
        try:
            analyzer = LLMSecurityAnalyzer(
                openai_api_key=openai_key,
                anthropic_api_key=anthropic_key
            )
            logger.info("Security analyzer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize security analyzer: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to initialize security analyzer: {str(e)}"
            )
    
    return analyzer

def get_cwe_database() -> CWEDatabase:
    """CWE 데이터베이스 인스턴스 반환"""
    global cwe_db
    if cwe_db is None:
        cwe_db = CWEDatabase()
        logger.info("CWE database initialized successfully")
    return cwe_db

def get_rag_adapter() -> RAGSearchAdapter:
    """RAG 검색 어댑터 인스턴스 반환"""
    global rag_adapter
    if rag_adapter is None:
        # RAG 빌더 초기화 (실제 구현에서는 적절한 경로 설정 필요)
        from rag.rag_builder import RAGBuilder
        rag_builder = RAGBuilder("", "")  # 경로는 실제 환경에 맞게 설정
        rag_adapter = RAGSearchAdapter(rag_builder)
        logger.info("RAG adapter initialized successfully")
    return rag_adapter

def get_patch_generator() -> LLMPatchGenerator:
    """패치 생성기 인스턴스 반환"""
    global patch_generator
    if patch_generator is None:
        openai_key = os.getenv("OPENAI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        
        if not openai_key and not anthropic_key:
            raise HTTPException(
                status_code=500,
                detail="API key not configured for patch generation"
            )
        
        patch_generator = LLMPatchGenerator(
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key
        )
        logger.info("Patch generator initialized successfully")
    return patch_generator

def get_patch_applier() -> PatchApplier:
    """패치 적용기 인스턴스 반환"""
    global patch_applier
    if patch_applier is None:
        repo_path = os.getenv("REPO_PATH", ".")
        github_token = os.getenv("GITHUB_TOKEN")
        
        patch_applier = PatchApplier(
            repo_path=repo_path,
            github_token=github_token
        )
        logger.info("Patch applier initialized successfully")
    return patch_applier

@app.on_event("startup")
async def startup_event():
    """애플리케이션 시작 시 초기화"""
    logger.info("FortiCode API starting up...")
    
    # CWE 데이터베이스 초기화
    get_cwe_database()
    
    # RAG 어댑터 초기화
    get_rag_adapter()
    
    # 보안 분석기 초기화 (API 키가 있는 경우)
    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        get_analyzer()
        get_patch_generator()
        logger.info("All components initialized successfully")
    else:
        logger.warning("API keys not configured. Some features will be limited")
    
    # 패치 적용기 초기화
    get_patch_applier()

@app.get("/")
async def root():
    """루트 엔드포인트"""
    return {
        "message": "FortiCode API",
        "version": "1.0.0",
        "description": "LLM 기반 보안 코드 분석 및 생성 서비스"
    }

@app.get("/health")
async def health_check():
    """헬스 체크 엔드포인트"""
    return {
        "status": "healthy",
        "analyzer_ready": analyzer is not None,
        "cwe_db_ready": cwe_db is not None,
        "rag_adapter_ready": rag_adapter is not None,
        "patch_generator_ready": patch_generator is not None,
        "patch_applier_ready": patch_applier is not None
    }

@app.post("/analyze", response_model=Dict[str, Any])
async def analyze_code(request: CodeAnalysisRequest):
    """코드 보안 분석 수행"""
    try:
        analyzer_instance = get_analyzer()
        
        # 코드 분석 수행
        result = analyzer_instance.analyze_code(
            code=request.code,
            language=request.language,
            context=request.context
        )
        
        # 결과를 JSON 직렬화 가능한 형태로 변환
        response_data = {
            "overall_score": result.overall_score,
            "risk_level": result.risk_level.value,
            "issues_count": len(result.issues),
            "issues": [
                {
                    "cwe_id": issue.cwe_id,
                    "severity": issue.severity.value,
                    "description": issue.description,
                    "line_number": issue.line_number,
                    "code_snippet": issue.code_snippet,
                    "risk_score": issue.risk_score,
                    "mitigation": issue.mitigation,
                    "confidence": issue.confidence
                }
                for issue in result.issues
            ],
            "recommendations": result.recommendations,
            "cwe_summary": result.cwe_summary
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"Error during code analysis: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

@app.post("/generate", response_model=Dict[str, Any])
async def generate_secure_code(request: CodeGenerationRequest):
    """보안을 고려한 코드 생성"""
    try:
        analyzer_instance = get_analyzer()
        
        # 보안 요구사항을 포함한 코드 생성 프롬프트
        security_context = " ".join(request.security_requirements) if request.security_requirements else "OWASP Top 10 준수"
        
        generation_prompt = f"""
다음 요구사항에 따라 {request.language} 코드를 생성해주세요:

요구사항: {request.description}
보안 요구사항: {security_context}

다음 보안 원칙을 반드시 준수해야 합니다:
1. 입력 검증 및 이스케이핑
2. 인증 및 권한 관리
3. 안전한 라이브러리 사용
4. 에러 처리 및 로깅
5. 데이터 암호화 및 보호

코드와 함께 보안 설명을 제공해주세요.
"""
        
        # LLM을 통한 코드 생성
        response = analyzer_instance.llm.invoke([
            analyzer_instance.llm.system_message(content=generation_prompt),
            analyzer_instance.llm.human_message(content="코드를 생성해주세요.")
        ])
        
        return {
            "generated_code": response.content,
            "language": request.language,
            "security_context": security_context
        }
        
    except Exception as e:
        logger.error(f"Error during code generation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Code generation failed: {str(e)}"
        )

@app.post("/fix", response_model=Dict[str, Any])
async def fix_security_issues(request: SecurityFixRequest):
    """보안 취약점 자동 수정"""
    try:
        analyzer_instance = get_analyzer()
        
        # 기존 코드 분석
        analysis_result = analyzer_instance.analyze_code(
            code=request.code,
            language=request.language
        )
        
        if not analysis_result.issues:
            return {
                "message": "No security issues found",
                "fixed_code": request.code
            }
        
        # 수정이 필요한 CWE들
        target_cwes = request.cwe_ids if request.cwe_ids else [issue.cwe_id for issue in analysis_result.issues]
        
        # 수정 프롬프트 생성
        fix_prompt = f"""
다음 {request.language} 코드의 보안 취약점을 수정해주세요:

원본 코드:
```{request.language}
{request.code}
```

수정이 필요한 보안 이슈:
"""
        
        for issue in analysis_result.issues:
            if issue.cwe_id in target_cwes:
                fix_prompt += f"""
- {issue.cwe_id}: {issue.description}
  수정 방안: {issue.mitigation}
"""
        
        fix_prompt += "\n수정된 코드를 제공해주세요."
        
        # LLM을 통한 코드 수정
        response = analyzer_instance.llm.invoke([
            analyzer_instance.llm.system_message(content=fix_prompt),
            analyzer_instance.llm.human_message(content="코드를 수정해주세요.")
        ])
        
        return {
            "original_code": request.code,
            "fixed_code": response.content,
            "fixed_issues": target_cwes,
            "analysis_result": {
                "overall_score": analysis_result.overall_score,
                "issues_count": len(analysis_result.issues)
            }
        }
        
    except Exception as e:
        logger.error(f"Error during security fix: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Security fix failed: {str(e)}"
        )

@app.post("/scan", response_model=Dict[str, Any])
async def process_security_scan(request: SecurityScanRequest):
    """SAST/DAST 결과 처리 및 분석"""
    try:
        # 1. 모든 도구 결과 파싱
        parser_factory = ParserFactory()
        all_findings = parser_factory.parse_all_results(request.tool_results)
        
        if not all_findings:
            return {
                "message": "No security findings detected",
                "findings_count": 0,
                "scan_id": None
            }
        
        # 2. 스캔 결과 생성
        scan_result = ScanResult(
            scan_id=f"scan_{len(all_findings)}_{hash(str(all_findings)) % 10000:04d}",
            timestamp=str(datetime.now())
        )
        
        for finding in all_findings:
            scan_result.add_finding(finding)
        
        # 3. RAG 검색으로 컨텍스트 추가
        rag_adapter = get_rag_adapter()
        security_summary = rag_adapter.get_security_summary(all_findings)
        
        # 4. 패치 생성 요청이 있으면 처리
        patches = []
        if request.include_patches:
            patch_gen = get_patch_generator()
            
            # 각 발견 결과에 대해 RAG 컨텍스트 검색
            rag_contexts = {}
            for finding in all_findings:
                context = rag_adapter.search_security_context(finding)
                rag_contexts[finding.finding_id] = context
            
            # 패치 생성
            patches = patch_gen.batch_generate_patches(all_findings, rag_contexts)
        
        return {
            "scan_id": scan_result.scan_id,
            "timestamp": scan_result.timestamp,
            "findings_count": len(all_findings),
            "summary": scan_result.to_dict()["summary"],
            "findings": [finding.to_dict() for finding in all_findings],
            "security_summary": security_summary,
            "patches_generated": len(patches) if request.include_patches else 0,
            "patches": [patch.__dict__ for patch in patches] if request.include_patches else []
        }
        
    except Exception as e:
        logger.error(f"Security scan processing failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Scan processing failed: {str(e)}"
        )

@app.get("/findings", response_model=Dict[str, Any])
async def get_findings(
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    language: Optional[str] = None,
    cwe: Optional[str] = None,
    limit: int = 100
):
    """보안 발견 결과 조회 (필터링 지원)"""
    try:
        # 실제 구현에서는 데이터베이스에서 조회
        # 여기서는 간단한 예시 반환
        return {
            "message": "Findings retrieval endpoint",
            "filters": {
                "severity": severity,
                "tool": tool,
                "language": language,
                "cwe": cwe,
                "limit": limit
            },
            "note": "This endpoint requires database implementation"
        }
        
    except Exception as e:
        logger.error(f"Findings retrieval failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Findings retrieval failed: {str(e)}"
        )

@app.post("/patches/generate", response_model=Dict[str, Any])
async def generate_patches(request: PatchGenerationRequest):
    """특정 발견 결과에 대한 패치 생성"""
    try:
        patch_gen = get_patch_generator()
        rag_adapter = get_rag_adapter()
        
        # 실제 구현에서는 finding_ids로 실제 SecurityFinding 객체들을 조회해야 함
        # 여기서는 예시 데이터 사용
        mock_findings = [
            SecurityFinding(
                source="bandit",
                tool=ToolType.SAST,
                rule_id="B105",
                cwe="CWE-259",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                message="Hardcoded password string",
                evidence="password = 'secret123'"
            )
        ]
        
        # RAG 컨텍스트 검색
        rag_contexts = {}
        for finding in mock_findings:
            context = rag_adapter.search_security_context(finding)
            rag_contexts[finding.finding_id] = context
        
        # 패치 생성
        patches = patch_gen.batch_generate_patches(mock_findings, rag_contexts)
        
        return {
            "findings_processed": len(mock_findings),
            "patches_generated": len(patches),
            "patches": [patch.__dict__ for patch in patches]
        }
        
    except Exception as e:
        logger.error(f"Patch generation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Patch generation failed: {str(e)}"
        )

@app.post("/patches/apply", response_model=Dict[str, Any])
async def apply_patch(request: PatchApplicationRequest):
    """패치 적용 및 PR 생성"""
    try:
        patch_applier = get_patch_applier()
        
        # 실제 구현에서는 finding_id와 patch_id로 실제 객체들을 조회해야 함
        # 여기서는 예시 응답
        return {
            "message": "Patch application endpoint",
            "finding_id": request.finding_id,
            "patch_id": request.patch_id,
            "auto_create_pr": request.auto_create_pr,
            "note": "This endpoint requires actual patch and finding objects"
        }
        
    except Exception as e:
        logger.error(f"Patch application failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Patch application failed: {str(e)}"
        )

@app.get("/runs/{run_id}", response_model=Dict[str, Any])
async def get_scan_run(run_id: str):
    """특정 스캔 실행 결과 조회"""
    try:
        # 실제 구현에서는 데이터베이스에서 run_id로 조회
        return {
            "run_id": run_id,
            "message": "Scan run details endpoint",
            "note": "This endpoint requires database implementation"
        }
        
    except Exception as e:
        logger.error(f"Run retrieval failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Run retrieval failed: {str(e)}"
        )

@app.get("/proposals", response_model=Dict[str, Any])
async def get_patch_proposals(
    status: Optional[str] = None,
    confidence_min: Optional[float] = None,
    limit: int = 50
):
    """패치 제안 목록 조회"""
    try:
        return {
            "message": "Patch proposals endpoint",
            "filters": {
                "status": status,
                "confidence_min": confidence_min,
                "limit": limit
            },
            "note": "This endpoint requires database implementation"
        }
        
    except Exception as e:
        logger.error(f"Proposals retrieval failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Proposals retrieval failed: {str(e)}"
        )

@app.get("/cwe/{cwe_id}")
async def get_cwe_info(cwe_id: str):
    """특정 CWE 정보 조회"""
    try:
        cwe_db = get_cwe_database()
        cwe_item = cwe_db.get_cwe(cwe_id)
        
        if not cwe_item:
            raise HTTPException(
                status_code=404,
                detail=f"CWE {cwe_id} not found"
            )
        
        return {
            "id": cwe_item.id,
            "name": cwe_item.name,
            "description": cwe_item.description,
            "likelihood": cwe_item.likelihood,
            "severity": cwe_item.severity,
            "examples": cwe_item.examples,
            "mitigations": cwe_item.mitigations,
            "detection_methods": cwe_item.detection_methods,
            "risk_score": cwe_item.risk_score
        }
        
    except Exception as e:
        logger.error(f"Error retrieving CWE info: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve CWE info: {str(e)}"
        )

@app.get("/cwe/search/{query}")
async def search_cwe(query: str):
    """CWE 검색"""
    try:
        cwe_db = get_cwe_database()
        results = cwe_db.search_cwe(query)
        
        return {
            "query": query,
            "results_count": len(results),
            "results": [
                {
                    "id": cwe.id,
                    "name": cwe.name,
                    "description": cwe.description,
                    "risk_score": cwe.risk_score
                }
                for cwe in results
            ]
        }
        
    except Exception as e:
        logger.error(f"Error searching CWE: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )

@app.get("/cwe/list")
async def list_all_cwes():
    """모든 CWE 목록 조회"""
    try:
        cwe_db = get_cwe_database()
        all_cwes = cwe_db.get_all_cwes()
        
        return {
            "total_count": len(all_cwes),
            "cwe_list": [
                {
                    "id": cwe.id,
                    "name": cwe.name,
                    "risk_score": cwe.risk_score
                }
                for cwe in all_cwes
            ]
        }
        
    except Exception as e:
        logger.error(f"Error listing CWE: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list CWE: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    
    # 개발 서버 실행
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

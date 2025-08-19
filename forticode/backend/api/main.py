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

# 상대 경로 import를 위한 설정
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.analysis.llm_security_analyzer import LLMSecurityAnalyzer, SecurityAnalysisResult
from security.cwe.cwe_database import CWEDatabase

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

# 전역 변수들
analyzer: Optional[LLMSecurityAnalyzer] = None
cwe_db: Optional[CWEDatabase] = None

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

@app.on_event("startup")
async def startup_event():
    """애플리케이션 시작 시 초기화"""
    logger.info("FortiCode API starting up...")
    
    # CWE 데이터베이스 초기화
    get_cwe_database()
    
    # 보안 분석기 초기화 (API 키가 있는 경우)
    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        get_analyzer()
        logger.info("All components initialized successfully")
    else:
        logger.warning("API keys not configured. Some features will be limited")

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
        "cwe_db_ready": cwe_db is not None
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

"""
소스코드 기반 보안 분석 워크플로우 (LLM + RAG)
소스코드 -> RAG 검색 -> LLM CWE 식별 및 시큐어 코딩 가이드 생성
"""

import logging
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from .llm_security_analyzer import LLMSecurityAnalyzer
from forticode.backend.rag.rag_builder import RAGBuilder
from .sast_dast_schema import SecurityFinding, ToolType, Language, Severity

logger = logging.getLogger(__name__)

class VulnbankSecurityWorkflow:
    """소스코드를 직접 분석하여 보안 취약점을 찾는 워크플로우"""
    
    def __init__(self, 
                 openai_api_key: Optional[str] = None,
                 anthropic_api_key: Optional[str] = None):
        """초기화"""
        self.llm_analyzer = LLMSecurityAnalyzer(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key
        )
        
        # RAG 빌더 초기화를 위한 경로 설정 (프로젝트 루트를 정확히 찾도록 수정)
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        cwe_zip_path = base_dir / "cwec_latest.xml.zip"
        owasp_json_path = base_dir / "forticode" / "backend" / "api" / "data" / "owasp_cheatsheets_parsed.json"

        # 경로 디버깅을 위한 로그 추가
        logger.info(f"Base directory: {base_dir}")
        logger.info(f"CWE zip path: {cwe_zip_path}")
        logger.info(f"OWASP JSON path: {owasp_json_path}")
        logger.info(f"CWE file exists: {cwe_zip_path.exists()}")
        logger.info(f"OWASP file exists: {owasp_json_path.exists()}")

        # CWE zip 파일이 없으면 JSON 파일 사용
        if not cwe_zip_path.exists():
            logger.warning("CWE zip 파일을 찾을 수 없습니다. JSON 파일을 사용합니다.")
            cwe_json_path = base_dir / "forticode" / "backend" / "api" / "data" / "cwe_database.json"
            if cwe_json_path.exists():
                logger.info(f"CWE JSON 파일을 사용합니다: {cwe_json_path}")
                cwe_zip_path = cwe_json_path
            else:
                logger.error("CWE 데이터 파일을 찾을 수 없습니다.")
                # 기본 CWE 정보 제공
                cwe_zip_path = base_dir / "forticode" / "backend" / "api" / "data" / "cwe_database.json"

        # 기존에 성공적으로 빌드된 벡터 저장소 사용
        vector_store_path = base_dir / "forticode" / "faiss_unified_index"
        logger.info(f"Vector store path: {vector_store_path}")
        logger.info(f"Vector store exists: {vector_store_path.exists()}")

        # RAG 빌더 초기화 시 기존 벡터 저장소 경로 전달
        self.rag_builder = RAGBuilder(
            cwe_zip_path=str(cwe_zip_path),
            owasp_json_path=str(owasp_json_path),
            vector_store_path=str(vector_store_path)
        )
        logger.info("VulnbankSecurityWorkflow 초기화 완료")

    def analyze_source_directory(self, project_path: str) -> Dict[str, Any]:
        """
        소스코드 디렉토리를 분석하여 LLM과 RAG를 통해 보안 분석을 수행합니다.
        
        Args:
            project_path: 분석할 소스코드 디렉토리 경로
            
        Returns:
            통합 보안 분석 결과
        """
        logger.info(f"소스코드 디렉토리 분석 시작: {project_path}")

        # 1. 소스코드 파일 목록 가져오기
        source_files = self._get_source_code_files(project_path)

        # 2. 각 소스코드 파일 분석
        all_findings = []
        for file_path in source_files:
            logger.info(f"파일 분석 중: {file_path}")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 3. LLM과 RAG를 이용한 분석
                findings = self._analyze_code_with_llm_rag(content, str(file_path))
                all_findings.extend(findings)

            except Exception as e:
                logger.error(f"파일 분석 오류 ({file_path}): {e}")

        # 4. 최종 리포트 생성
        report = self._create_final_report(project_path, all_findings)

        logger.info("소스코드 디렉토리 분석 완료")
        return report

    def _get_source_code_files(self, project_path: str) -> List[Path]:
        """
        지정된 경로에서 분석할 소스코드 파일 목록을 가져옵니다.
        (우선순위: Python)
        """
        project_path = Path(project_path)
        python_files = list(project_path.rglob("*.py"))
        
        # venv 등 제외
        python_files = [
            f for f in python_files 
            if 'venv' not in f.parts and '.venv' not in f.parts and '__pycache__' not in f.parts
        ]
        
        logger.info(f"총 {len(python_files)}개의 Python 소스코드 파일을 찾았습니다.")
        return python_files

    def _analyze_code_with_llm_rag(self, code_content: str, file_path: str) -> List[SecurityFinding]:
        """
        LLM과 RAG를 사용하여 단일 코드 조각을 분석합니다.
        RAG가 실패하면 LLM만으로 분석을 진행합니다.
        """
        # 1. RAG로 관련 CWE 정보 검색 (실패 시 빈 리스트 사용)
        rag_results = []
        try:
            rag_query = "Identify potential security vulnerabilities in this Python code."
            rag_results = self.rag_builder.search(query=rag_query, k=5)
            logger.info(f"RAG 검색 성공: {len(rag_results)}개 결과")
        except Exception as e:
            logger.warning(f"RAG 검색 실패, LLM만으로 분석 진행: {e}")
            rag_results = []
        
        # 2. LLM에 전달할 프롬프트 생성
        prompt = self._create_llm_analysis_prompt(code_content, rag_results)

        # 3. LLM 호출
        try:
            response = self.llm_analyzer.analyze_code(prompt)
            # 4. LLM 응답 파싱하여 SecurityFinding 객체 생성
            findings = self._parse_llm_response(response, file_path, code_content)
            return findings
        except Exception as e:
            logger.error(f"LLM 분석 오류 ({file_path}): {e}")
            return []

    def _create_llm_analysis_prompt(self, code: str, rag_results: List) -> str:
        """
        코드 분석을 위한 LLM 프롬프트를 생성합니다.
        """
        rag_context_str = ""
        if rag_results:
            for res in rag_results:
                # Document 객체인지 확인하고 적절히 처리
                if hasattr(res, 'page_content') and hasattr(res, 'metadata'):
                    # LangChain Document 객체
                    content = res.page_content
                    source = res.metadata.get('source', 'Unknown')
                    cwe_id = res.metadata.get('cwe_id', '')
                    if content:
                        source_info = f"{source}"
                        if cwe_id:
                            source_info += f" ({cwe_id})"
                        rag_context_str += f"- (Source: {source_info}): {content[:500]}...\n"
                elif isinstance(res, dict):
                    # 딕셔너리 형태인 경우
                    content = res.get('content', '')
                    source = res.get('source', '')
                    if content:
                        rag_context_str += f"- (Source: {source}): {content}\n"
        
        if not rag_context_str.strip():
            rag_context_str = "- Common Python security vulnerabilities: SQL injection, XSS, command injection, insecure deserialization, path traversal, etc."

        prompt = f"""
You are a security expert analyzing Python code for vulnerabilities. 

IMPORTANT: Analyze the Python code provided below and identify security vulnerabilities.

For each identified vulnerability, provide a JSON object with:
- cwe_id: CWE identifier (e.g., "CWE-89")
- description: Brief description of the vulnerability
- line_number: Approximate line number (use 1 if unsure)
- evidence: Vulnerable code snippet or pattern
- severity: "Critical", "High", "Medium", or "Low"
- recommendation: How to fix the vulnerability

Return your response as a JSON array. If no vulnerabilities found, return [].

Example response format:
[
  {{
    "cwe_id": "CWE-89",
    "description": "SQL Injection vulnerability due to string formatting",
    "line_number": 1,
    "evidence": "db.execute(f'SELECT * FROM users WHERE name = {{user_input}}')",
    "severity": "High",
    "recommendation": "Use parameterized queries or ORM to prevent SQL injection"
  }}
]

Security Context from Knowledge Base:
{rag_context_str}

Python Code to Analyze:
```python
{code}
```

Analyze this code and return vulnerabilities in JSON format:
"""
        return prompt

    def _parse_llm_response(self, llm_response: str, file_path: str, code_content: str) -> List[SecurityFinding]:
        """
        LLM의 JSON 응답을 파싱하여 SecurityFinding 리스트로 변환합니다.
        """
        findings = []
        try:
            if not llm_response or not isinstance(llm_response, str):
                logger.warning(f"LLM 응답이 유효하지 않습니다: {type(llm_response)}")
                return []

            # JSON 배열 찾기
            start_idx = llm_response.find('[')
            end_idx = llm_response.rfind(']')
            
            if start_idx == -1 or end_idx == -1 or start_idx >= end_idx:
                logger.warning(f"LLM 응답에서 JSON 배열을 찾을 수 없습니다: {llm_response[:200]}...")
                return []
            
            # JSON 부분 추출
            json_part = llm_response[start_idx:end_idx + 1]
            logger.debug(f"추출된 JSON 부분: {json_part}")
            
            # JSON 파싱
            vulnerabilities = json.loads(json_part)

            if not isinstance(vulnerabilities, list):
                logger.warning(f"LLM 응답이 리스트 형식이 아닙니다: {type(vulnerabilities)}")
                return []

            logger.info(f"파싱된 취약점 개수: {len(vulnerabilities)}")
            
            for i, vuln in enumerate(vulnerabilities):
                try:
                    if not isinstance(vuln, dict):
                        logger.warning(f"취약점 {i}가 딕셔너리 형식이 아닙니다: {type(vuln)}")
                        continue
                        
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW,
                    }
                    
                    # 기본값 설정
                    cwe_id = vuln.get("cwe_id", f"LLM-DETECTED-{i}")
                    severity = severity_map.get(str(vuln.get("severity", "medium")).lower(), Severity.MEDIUM)
                    line_number = vuln.get("line_number", 0)
                    
                    finding = SecurityFinding(
                        finding_id=f"llm_{i}_{cwe_id}",
                        source="LLM_RAG_ANALYSIS",
                        tool=ToolType.SAST,
                        rule_id=cwe_id,
                        cwe=cwe_id,
                        severity=severity,
                        language=Language.PYTHON,
                        file_path=file_path,
                        line_number=line_number,
                        endpoint=None,
                        message=vuln.get("description", "LLM이 감지한 보안 취약점"),
                        evidence=vuln.get("evidence", "코드 분석 결과"),
                        secure_coding_guide=vuln.get("recommendation", "보안 코딩 가이드 필요")
                    )
                    findings.append(finding)
                    logger.debug(f"취약점 {i} 파싱 성공: {cwe_id}")
                    
                except Exception as e:
                    logger.error(f"취약점 {i} 파싱 중 오류: {e}")
                    continue
                    
        except json.JSONDecodeError as e:
            logger.error(f"LLM 응답 JSON 파싱 실패: {e}")
            logger.debug(f"파싱 시도한 JSON: {llm_response[:500]}...")
        except Exception as e:
            logger.error(f"LLM 응답 처리 중 오류 발생: {e}")
            logger.exception("상세 오류 정보:")
            
        return findings

    def _create_final_report(self, project_path: str, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """
        분석 결과를 바탕으로 최종 리포트를 생성합니다.
        """
        logger.info("최종 리포트 생성 중...")
        
        # 심각도별 취약점 분류
        critical_issues = [f for f in findings if f.severity == Severity.CRITICAL]
        high_issues = [f for f in findings if f.severity == Severity.HIGH]
        medium_issues = [f for f in findings if f.severity == Severity.MEDIUM]
        low_issues = [f for f in findings if f.severity == Severity.LOW]

        report = {
            "project_path": project_path,
            "security_summary": {
                "total_findings": len(findings),
                "critical_count": len(critical_issues),
                "high_count": len(high_issues),
                "medium_count": len(medium_issues),
                "low_count": len(low_issues),
            },
            "findings": [f.to_dict() for f in findings]
        }
        
        logger.info("최종 리포트 생성 완료")
        return report

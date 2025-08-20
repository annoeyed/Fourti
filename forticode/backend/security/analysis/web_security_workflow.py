"""
웹 보안 취약점 분석 워크플로우 (Python + 웹 취약점 집중)
프로젝트 디렉토리 → SAST/DAST 분석 → RAG 검색 → LLM 시큐어 코딩 가이드 생성
"""

import logging
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path
import subprocess
import tempfile
import shutil

from .sast_dast_parsers import BanditParser
from .sast_dast_schema import SecurityFinding, ToolType, Language, Severity
from .llm_security_analyzer import LLMSecurityAnalyzer
from ..rag.rag_builder import RAGBuilder

logger = logging.getLogger(__name__)

class WebSecurityWorkflow:
    """웹 보안 취약점 분석 워크플로우 (Python + 웹 취약점 집중)"""
    
    def __init__(self, 
                 openai_api_key: Optional[str] = None,
                 anthropic_api_key: Optional[str] = None):
        """초기화"""
        self.llm_analyzer = LLMSecurityAnalyzer(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key
        )
        
        # RAG 시스템 초기화
        self.rag_builder = RAGBuilder()
        
        # Python 전용 파서 초기화
        self.python_parsers = {
            'bandit': BanditParser(),
        }
        
        logger.info("웹 보안 워크플로우 초기화 완료")
    
    def analyze_project_directory(self, 
                                 project_path: str,
                                 include_dependencies: bool = True) -> Dict[str, Any]:
        """
        프로젝트 디렉토리를 분석하는 메인 워크플로우
        
        Args:
            project_path: 분석할 프로젝트 디렉토리 경로
            include_dependencies: 의존성 분석 포함 여부
            
        Returns:
            통합 보안 분석 결과
        """
        logger.info(f"프로젝트 디렉토리 분석 시작: {project_path}")
        
        # 1단계: 프로젝트 구조 분석
        project_structure = self._analyze_project_structure(project_path)
        
        # 2단계: Python 코드 SAST 분석
        python_findings = self._run_python_sast_analysis(project_path)
        
        # 3단계: 웹 취약점 분석
        web_vulnerabilities = self._analyze_web_vulnerabilities(project_path, project_structure)
        
        # 4단계: 의존성 보안 분석
        dependency_vulnerabilities = []
        if include_dependencies:
            dependency_vulnerabilities = self._analyze_dependencies(project_path)
        
        # 5단계: RAG 검색으로 보안 컨텍스트 수집
        security_contexts = self._collect_web_security_contexts(
            python_findings, web_vulnerabilities, dependency_vulnerabilities
        )
        
        # 6단계: LLM 기반 시큐어 코딩 가이드 생성
        secure_coding_guide = self._generate_web_security_guide(
            python_findings, web_vulnerabilities, dependency_vulnerabilities, security_contexts
        )
        
        # 7단계: 통합 리포트 생성
        final_report = self._create_web_security_report(
            project_structure, python_findings, web_vulnerabilities, 
            dependency_vulnerabilities, secure_coding_guide
        )
        
        logger.info("프로젝트 디렉토리 분석 완료")
        return final_report
    
    def _analyze_project_structure(self, project_path: str) -> Dict[str, Any]:
        """프로젝트 구조 분석"""
        logger.info("프로젝트 구조 분석 중...")
        
        project_path = Path(project_path)
        structure = {
            "root": str(project_path),
            "python_files": [],
            "web_files": [],
            "config_files": [],
            "dependency_files": [],
            "total_files": 0
        }
        
        # Python 파일 찾기
        for py_file in project_path.rglob("*.py"):
            if not any(part.startswith('.') for part in py_file.parts):  # 숨김 폴더 제외
                structure["python_files"].append({
                    "path": str(py_file.relative_to(project_path)),
                    "size": py_file.stat().st_size,
                    "lines": len(py_file.read_text(encoding='utf-8').splitlines())
                })
        
        # 웹 관련 파일 찾기
        web_extensions = ['.html', '.htm', '.js', '.css', '.xml', '.json', '.yaml', '.yml']
        for web_file in project_path.rglob("*"):
            if web_file.suffix.lower() in web_extensions and web_file.is_file():
                if not any(part.startswith('.') for part in web_file.parts):
                    structure["web_files"].append({
                        "path": str(web_file.relative_to(project_path)),
                        "type": web_file.suffix.lower()
                    })
        
        # 설정 파일 찾기
        config_files = ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile', 'poetry.lock']
        for config_file in config_files:
            config_path = project_path / config_file
            if config_path.exists():
                structure["dependency_files"].append(str(config_path))
        
        structure["total_files"] = len(structure["python_files"]) + len(structure["web_files"])
        
        logger.info(f"프로젝트 구조 분석 완료: {structure['total_files']}개 파일")
        return structure
    
    def _run_python_sast_analysis(self, project_path: str) -> List[SecurityFinding]:
        """Python 코드 SAST 분석 실행"""
        logger.info("Python SAST 분석 실행 중...")
        
        findings = []
        
        try:
            # Bandit 실행 (Python 보안 분석)
            bandit_findings = self._run_bandit_on_directory(project_path)
            findings.extend(bandit_findings)
            
            # Safety 실행 (의존성 보안 검사)
            safety_findings = self._run_safety_check(project_path)
            findings.extend(safety_findings)
            
        except Exception as e:
            logger.error(f"Python SAST 분석 오류: {e}")
        
        logger.info(f"Python SAST 분석 완료: {len(findings)}개 취약점 발견")
        return findings
    
    def _run_bandit_on_directory(self, project_path: str) -> List[SecurityFinding]:
        """Bandit을 사용한 디렉토리 전체 분석"""
        try:
            # Bandit 실행
            result = subprocess.run([
                'bandit', '-f', 'json', '-r', project_path
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # 결과 파싱
                data = json.loads(result.stdout)
                parser = BanditParser()
                return parser.parse_from_data(data)
            else:
                logger.warning(f"Bandit 실행 실패: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Bandit 실행 오류: {e}")
            return []
    
    def _run_safety_check(self, project_path: str) -> List[SecurityFinding]:
        """Safety를 사용한 의존성 보안 검사"""
        try:
            # requirements.txt가 있는지 확인
            req_file = Path(project_path) / "requirements.txt"
            if not req_file.exists():
                return []
            
            # Safety 실행
            result = subprocess.run([
                'safety', 'check', '-r', str(req_file), '--json'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Safety 결과 파싱
                return self._parse_safety_results(result.stdout)
            else:
                logger.warning(f"Safety 실행 실패: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Safety 실행 오류: {e}")
            return []
    
    def _parse_safety_results(self, safety_output: str) -> List[SecurityFinding]:
        """Safety 결과를 SecurityFinding으로 변환"""
        findings = []
        
        try:
            data = json.loads(safety_output)
            
            for vuln in data:
                finding = SecurityFinding(
                    source="safety",
                    tool=ToolType.SCA,
                    rule_id=vuln.get('vulnerability_id', 'unknown'),
                    cwe=vuln.get('cwe', None),
                    severity=self._map_safety_severity(vuln.get('severity', 'medium')),
                    language=Language.PYTHON,
                    file_path="requirements.txt",
                    line_number=None,
                    message=f"Vulnerable dependency: {vuln.get('package', 'unknown')} - {vuln.get('description', '')}",
                    evidence=f"Package: {vuln.get('package', 'unknown')}, Version: {vuln.get('installed_version', 'unknown')}",
                    links=[vuln.get('more_info_url', '')] if vuln.get('more_info_url') else []
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Safety 결과 파싱 오류: {e}")
        
        return findings
    
    def _map_safety_severity(self, safety_severity: str) -> Severity:
        """Safety 심각도를 표준 심각도로 매핑"""
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL
        }
        return severity_map.get(safety_severity.lower(), Severity.MEDIUM)
    
    def _analyze_web_vulnerabilities(self, project_path: str, project_structure: Dict[str, Any]) -> List[SecurityFinding]:
        """웹 취약점 분석"""
        logger.info("웹 취약점 분석 중...")
        
        web_findings = []
        
        # Python 파일에서 웹 관련 취약점 패턴 검색
        for py_file_info in project_structure["python_files"]:
            file_path = Path(project_path) / py_file_info["path"]
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 웹 취약점 패턴 검색
                web_vulns = self._scan_web_vulnerability_patterns(content, str(file_path))
                web_findings.extend(web_vulns)
                
            except Exception as e:
                logger.error(f"파일 분석 오류 ({file_path}): {e}")
        
        logger.info(f"웹 취약점 분석 완료: {len(web_findings)}개 발견")
        return web_findings
    
    def _scan_web_vulnerability_patterns(self, content: str, file_path: str) -> List[SecurityFinding]:
        """웹 취약점 패턴 스캔"""
        findings = []
        
        # SQL Injection 패턴
        sql_patterns = [
            (r'f"SELECT.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string'),
            (r'f"INSERT.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string'),
            (r'f"UPDATE.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string'),
            (r'f"DELETE.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string'),
            (r'execute\(f".*\{.*\}"', 'CWE-89', 'SQL Injection via execute'),
            (r'cursor\.execute\(f".*\{.*\}"', 'CWE-89', 'SQL Injection via cursor.execute'),
        ]
        
        # XSS 패턴
        xss_patterns = [
            (r'render_template_string\(f".*\{.*\}"', 'CWE-79', 'XSS via template string'),
            (r'Markup\(.*\)', 'CWE-79', 'XSS via Markup'),
            (r'f"<.*\{.*\}"', 'CWE-79', 'XSS via f-string HTML'),
        ]
        
        # CSRF 패턴
        csrf_patterns = [
            (r'@app\.route.*methods=\[.*POST.*\]', 'CWE-352', 'CSRF protection missing'),
            (r'@csrf\.exempt', 'CWE-352', 'CSRF protection disabled'),
        ]
        
        # 파일 업로드 취약점
        file_upload_patterns = [
            (r'request\.files\[.*\]\.save\(', 'CWE-434', 'Unrestricted file upload'),
            (r'\.filename', 'CWE-434', 'File upload without validation'),
        ]
        
        # 경로 순회 취약점
        path_traversal_patterns = [
            (r'os\.path\.join\(.*request\.args', 'CWE-22', 'Path traversal vulnerability'),
            (r'open\(.*request\.args', 'CWE-22', 'Path traversal vulnerability'),
        ]
        
        # 모든 패턴 검색
        all_patterns = sql_patterns + xss_patterns + csrf_patterns + file_upload_patterns + path_traversal_patterns
        
        for pattern, cwe_id, message in all_patterns:
            import re
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # 라인 번호 계산
                line_number = content[:match.start()].count('\n') + 1
                
                finding = SecurityFinding(
                    source="pattern_scan",
                    tool=ToolType.SAST,
                    rule_id=f"web_{cwe_id}",
                    cwe=cwe_id,
                    severity=self._get_web_vulnerability_severity(cwe_id),
                    language=Language.PYTHON,
                    file_path=file_path,
                    line_number=line_number,
                    message=message,
                    evidence=content[max(0, match.start()-50):match.end()+50],
                    links=[f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"]
                )
                findings.append(finding)
        
        return findings
    
    def _get_web_vulnerability_severity(self, cwe_id: str) -> Severity:
        """웹 취약점 CWE별 심각도 매핑"""
        severity_map = {
            'CWE-89': Severity.CRITICAL,  # SQL Injection
            'CWE-79': Severity.HIGH,      # XSS
            'CWE-352': Severity.HIGH,     # CSRF
            'CWE-434': Severity.HIGH,     # File Upload
            'CWE-22': Severity.MEDIUM,    # Path Traversal
        }
        return severity_map.get(cwe_id, Severity.MEDIUM)
    
    def _analyze_dependencies(self, project_path: str) -> List[SecurityFinding]:
        """의존성 보안 분석"""
        logger.info("의존성 보안 분석 중...")
        
        dependency_findings = []
        
        try:
            # pip-audit 실행 (추가 의존성 검사)
            pip_audit_findings = self._run_pip_audit(project_path)
            dependency_findings.extend(pip_audit_findings)
            
        except Exception as e:
            logger.error(f"의존성 분석 오류: {e}")
        
        logger.info(f"의존성 보안 분석 완료: {len(dependency_findings)}개 발견")
        return dependency_findings
    
    def _run_pip_audit(self, project_path: str) -> List[SecurityFinding]:
        """pip-audit 실행"""
        try:
            result = subprocess.run([
                'pip-audit', '--format', 'json'
            ], cwd=project_path, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return self._parse_pip_audit_results(result.stdout)
            else:
                logger.warning(f"pip-audit 실행 실패: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"pip-audit 실행 오류: {e}")
            return []
    
    def _parse_pip_audit_results(self, audit_output: str) -> List[SecurityFinding]:
        """pip-audit 결과 파싱"""
        findings = []
        
        try:
            data = json.loads(audit_output)
            
            for vuln in data.get('vulnerabilities', []):
                finding = SecurityFinding(
                    source="pip-audit",
                    tool=ToolType.SCA,
                    rule_id=vuln.get('id', 'unknown'),
                    cwe=vuln.get('cwe', None),
                    severity=self._map_audit_severity(vuln.get('severity', 'medium')),
                    language=Language.PYTHON,
                    file_path="dependencies",
                    line_number=None,
                    message=f"Vulnerable dependency: {vuln.get('package', 'unknown')} - {vuln.get('description', '')}",
                    evidence=f"Package: {vuln.get('package', 'unknown')}, Version: {vuln.get('installed_version', 'unknown')}",
                    links=[vuln.get('url', '')] if vuln.get('url') else []
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"pip-audit 결과 파싱 오류: {e}")
        
        return findings
    
    def _map_audit_severity(self, audit_severity: str) -> Severity:
        """pip-audit 심각도 매핑"""
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL
        }
        return severity_map.get(audit_severity.lower(), Severity.MEDIUM)
    
    def _collect_web_security_contexts(self, 
                                      python_findings: List[SecurityFinding],
                                      web_vulnerabilities: List[SecurityFinding],
                                      dependency_vulnerabilities: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """웹 보안 컨텍스트 수집"""
        logger.info("웹 보안 컨텍스트 수집 중...")
        
        contexts = []
        all_findings = python_findings + web_vulnerabilities + dependency_vulnerabilities
        
        # CWE 기반 검색
        for finding in all_findings:
            if finding.cwe:
                try:
                    search_results = self.rag_builder.search(
                        query=f"{finding.cwe} {finding.message}",
                        top_k=3
                    )
                    
                    contexts.append({
                        "finding": finding,
                        "rag_results": search_results,
                        "cwe_id": finding.cwe
                    })
                    
                except Exception as e:
                    logger.error(f"RAG 검색 오류 ({finding.cwe}): {e}")
        
        # 웹 보안 특화 검색
        web_security_queries = [
            "OWASP Top 10 web application security",
            "Python web security best practices",
            "Flask Django security vulnerabilities",
            "SQL injection prevention Python",
            "XSS prevention Python web",
            "CSRF protection web applications"
        ]
        
        for query in web_security_queries:
            try:
                search_results = self.rag_builder.search(query=query, top_k=2)
                contexts.append({
                    "general_web_security": query,
                    "rag_results": search_results
                })
            except Exception as e:
                logger.error(f"웹 보안 RAG 검색 오류: {e}")
        
        logger.info(f"웹 보안 컨텍스트 수집 완료: {len(contexts)}개")
        return contexts
    
    def _generate_web_security_guide(self, 
                                    python_findings: List[SecurityFinding],
                                    web_vulnerabilities: List[SecurityFinding],
                                    dependency_vulnerabilities: List[SecurityFinding],
                                    security_contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """웹 보안 시큐어 코딩 가이드 생성"""
        logger.info("웹 보안 시큐어 코딩 가이드 생성 중...")
        
        try:
            # 모든 취약점 통합
            all_vulnerabilities = python_findings + web_vulnerabilities + dependency_vulnerabilities
            
            # 웹 보안 특화 가이드 생성
            guide_prompt = self._create_web_security_guide_prompt(all_vulnerabilities, security_contexts)
            
            guide_result = self.llm_analyzer.llm.invoke([
                self.llm_analyzer.llm.system_message(guide_prompt),
                self.llm_analyzer.llm.human_message("웹 보안 시큐어 코딩 가이드를 생성해주세요.")
            ])
            
            # 가이드 구조화
            web_security_guide = {
                "overview": "웹 애플리케이션 보안 코딩 가이드",
                "critical_vulnerabilities": [],
                "web_specific_guidelines": [],
                "python_best_practices": [],
                "framework_specific": [],
                "testing_recommendations": [],
                "resources": []
            }
            
            # 발견된 취약점별 가이드 생성
            for vuln in all_vulnerabilities:
                if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                    web_security_guide["critical_vulnerabilities"].append({
                        "cwe": vuln.cwe,
                        "description": vuln.message,
                        "severity": vuln.severity.value,
                        "mitigation": self._get_mitigation_for_cwe(vuln.cwe)
                    })
            
            # RAG 컨텍스트에서 추가 정보 추출
            for context in security_contexts:
                if "rag_results" in context:
                    for result in context["rag_results"]:
                        if "content" in result:
                            # OWASP 치트시트 등에서 모범 사례 추출
                            if "OWASP" in str(result.get("source", "")):
                                web_security_guide["web_specific_guidelines"].append({
                                    "source": result.get("source", ""),
                                    "guideline": result.get("content", "")[:300] + "..."
                                })
            
            logger.info("웹 보안 시큐어 코딩 가이드 생성 완료")
            return web_security_guide
            
        except Exception as e:
            logger.error(f"웹 보안 가이드 생성 오류: {e}")
            return {"error": str(e)}
    
    def _get_mitigation_for_cwe(self, cwe_id: str) -> str:
        """CWE별 완화 방안"""
        mitigation_map = {
            'CWE-89': "Parameterized queries 사용, 입력 검증 강화",
            'CWE-79': "출력 인코딩, CSP 헤더 설정, 입력 검증",
            'CWE-352': "CSRF 토큰 사용, SameSite 쿠키 설정",
            'CWE-434': "파일 확장자 검증, 안전한 업로드 디렉토리",
            'CWE-22': "경로 검증, 사용자 입력 sanitization",
            'CWE-78': "OS 명령어 실행 금지, 입력 검증",
            'CWE-200': "민감한 정보 노출 방지, 에러 메시지 제한"
        }
        return mitigation_map.get(cwe_id, "일반적인 보안 모범 사례 적용")
    
    def _create_web_security_guide_prompt(self, 
                                         vulnerabilities: List[SecurityFinding],
                                         security_contexts: List[Dict[str, Any]]) -> str:
        """웹 보안 가이드 생성을 위한 프롬프트"""
        prompt = """
당신은 웹 애플리케이션 보안 전문가입니다. 
다음 Python 웹 애플리케이션 보안 분석 결과를 바탕으로 종합적인 시큐어 코딩 가이드를 생성해주세요.

발견된 취약점:
"""
        
        for vuln in vulnerabilities:
            prompt += f"- {vuln.cwe}: {vuln.message} (심각도: {vuln.severity.value})\n"
        
        prompt += """
다음 구조로 웹 보안 가이드를 작성해주세요:
1. OWASP Top 10 기반 웹 보안 원칙
2. Python 웹 프레임워크별 보안 가이드 (Flask, Django)
3. SQL Injection, XSS, CSRF 등 주요 취약점 방어법
4. 입력 검증 및 출력 인코딩 모범 사례
5. 보안 테스트 및 모니터링 방법
6. 추가 학습 자료 및 도구

실용적이고 구체적인 코드 예시를 포함해주세요.
"""
        
        return prompt
    
    def _create_web_security_report(self, 
                                   project_structure: Dict[str, Any],
                                   python_findings: List[SecurityFinding],
                                   web_vulnerabilities: List[SecurityFinding],
                                   dependency_vulnerabilities: List[SecurityFinding],
                                   secure_coding_guide: Dict[str, Any]) -> Dict[str, Any]:
        """웹 보안 통합 리포트 생성"""
        logger.info("웹 보안 통합 리포트 생성 중...")
        
        # 모든 취약점 통합
        all_findings = python_findings + web_vulnerabilities + dependency_vulnerabilities
        
        # 전체 보안 점수 계산
        total_score = self._calculate_web_security_score(all_findings)
        
        # 우선순위별 취약점 분류
        critical_issues = [f for f in all_findings if f.severity == Severity.CRITICAL]
        high_issues = [f for f in all_findings if f.severity == Severity.HIGH]
        medium_issues = [f for f in all_findings if f.severity == Severity.MEDIUM]
        low_issues = [f for f in all_findings if f.severity == Severity.LOW]
        
        # 웹 취약점별 분류
        web_vuln_categories = {
            'sql_injection': [f for f in all_findings if f.cwe == 'CWE-89'],
            'xss': [f for f in all_findings if f.cwe == 'CWE-79'],
            'csrf': [f for f in all_findings if f.cwe == 'CWE-352'],
            'file_upload': [f for f in all_findings if f.cwe == 'CWE-434'],
            'path_traversal': [f for f in all_findings if f.cwe == 'CWE-22'],
            'dependency': dependency_vulnerabilities
        }
        
        report = {
            "project_overview": {
                "path": project_structure["root"],
                "total_files": project_structure["total_files"],
                "python_files": len(project_structure["python_files"]),
                "web_files": len(project_structure["web_files"])
            },
            "security_summary": {
                "total_findings": len(all_findings),
                "security_score": total_score,
                "risk_level": self._get_risk_level(total_score),
                "critical_count": len(critical_issues),
                "high_count": len(high_issues),
                "medium_count": len(medium_issues),
                "low_count": len(low_issues)
            },
            "vulnerability_categories": web_vuln_categories,
            "findings_by_severity": {
                "critical": [f.to_dict() for f in critical_issues],
                "high": [f.to_dict() for f in high_issues],
                "medium": [f.to_dict() for f in medium_issues],
                "low": [f.to_dict() for f in low_issues]
            },
            "secure_coding_guide": secure_coding_guide,
            "recommendations": self._generate_web_security_recommendations(all_findings, total_score),
            "next_steps": self._generate_web_security_next_steps(all_findings, total_score)
        }
        
        logger.info("웹 보안 통합 리포트 생성 완료")
        return report
    
    def _calculate_web_security_score(self, findings: List[SecurityFinding]) -> float:
        """웹 보안 점수 계산 (0-100, 높을수록 안전)"""
        base_score = 100.0
        
        # 심각도별 점수 차감
        severity_weights = {
            Severity.CRITICAL: 25.0,  # 웹 취약점은 더 위험
            Severity.HIGH: 20.0,
            Severity.MEDIUM: 15.0,
            Severity.LOW: 8.0
        }
        
        for finding in findings:
            base_score -= severity_weights.get(finding.severity, 10.0)
        
        return max(0.0, min(100.0, base_score))
    
    def _get_risk_level(self, score: float) -> str:
        """점수 기반 위험 수준 판정"""
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _generate_web_security_recommendations(self, 
                                             findings: List[SecurityFinding], 
                                             score: float) -> List[str]:
        """웹 보안 개선 권장사항 생성"""
        recommendations = []
        
        if score < 50:
            recommendations.append("즉시 웹 보안 검토 및 수정이 필요합니다.")
        
        if any(f.severity == Severity.CRITICAL for f in findings):
            recommendations.append("Critical 수준 웹 취약점을 우선적으로 수정하세요.")
        
        # 웹 취약점별 구체적 권장사항
        if any(f.cwe == 'CWE-89' for f in findings):
            recommendations.append("SQL Injection 취약점이 발견되었습니다. Parameterized Query를 사용하세요.")
        
        if any(f.cwe == 'CWE-79' for f in findings):
            recommendations.append("XSS 취약점이 발견되었습니다. 입력 검증과 출력 인코딩을 적용하세요.")
        
        if any(f.cwe == 'CWE-352' for f in findings):
            recommendations.append("CSRF 취약점이 발견되었습니다. CSRF 토큰을 구현하세요.")
        
        if any(f.cwe == 'CWE-434' for f in findings):
            recommendations.append("파일 업로드 취약점이 발견되었습니다. 파일 검증을 강화하세요.")
        
        if len(recommendations) == 0:
            recommendations.append("현재 웹 애플리케이션은 보안 관점에서 양호합니다. 정기적인 보안 검토를 유지하세요.")
        
        return recommendations
    
    def _generate_web_security_next_steps(self, 
                                         findings: List[SecurityFinding], 
                                         score: float) -> List[str]:
        """웹 보안 다음 단계 제안"""
        next_steps = []
        
        if score < 60:
            next_steps.append("발견된 웹 취약점을 우선순위에 따라 수정하세요.")
            next_steps.append("웹 보안 코드 리뷰 프로세스를 강화하세요.")
        
        next_steps.append("OWASP ZAP 등 웹 보안 도구를 사용한 정기적인 테스트를 수행하세요.")
        next_steps.append("웹 보안 모범 사례 교육을 진행하세요.")
        next_steps.append("웹 애플리케이션 방화벽(WAF) 도입을 고려하세요.")
        
        return next_steps

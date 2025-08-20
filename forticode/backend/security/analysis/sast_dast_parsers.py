"""
RAG 기반 보안 분석 파서
CWE 데이터베이스와 RAG 검색 결과를 통합하여 보안 취약점 분석
"""

import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class BaseParser:
    """기본 보안 분석 파서 클래스"""
    
    def __init__(self):
        self.name = "base_parser"
        self.supported_languages = []
    
    def parse(self, content: str, file_path: str = None) -> List[Dict[str, Any]]:
        """기본 파싱 메서드"""
        raise NotImplementedError("하위 클래스에서 구현해야 합니다")
    
    def get_supported_languages(self) -> List[str]:
        """지원하는 언어 목록 반환"""
        return self.supported_languages

class BanditParser(BaseParser):
    """Bandit SAST 도구 결과 파서"""
    
    def __init__(self):
        super().__init__()
        self.name = "bandit_parser"
        self.supported_languages = ["python"]
    
    def parse(self, content: str, file_path: str = None) -> List[Dict[str, Any]]:
        """Bandit 결과 파싱"""
        try:
            # JSON 형태의 Bandit 결과를 파싱
            if isinstance(content, str):
                data = json.loads(content)
            else:
                data = content
            
            findings = []
            
            for result in data.get('results', []):
                finding = {
                    'id': f"bandit_{result.get('issue_id', 'unknown')}",
                    'source': 'bandit',
                    'severity': self._map_severity(result.get('issue_severity', 'low')),
                    'confidence': self._map_confidence(result.get('issue_confidence', 'low')),
                    'title': result.get('issue_text', ''),
                    'description': result.get('more_info', ''),
                    'file_path': result.get('filename', file_path or ''),
                    'line_number': result.get('line_number', 0),
                    'code': result.get('code', ''),
                    'cwe_id': self._extract_cwe_id(result),
                    'tool_specific': {
                        'test_id': result.get('test_id', ''),
                        'test_name': result.get('test_name', ''),
                        'issue_severity': result.get('issue_severity', ''),
                        'issue_confidence': result.get('issue_confidence', '')
                    }
                }
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Bandit 결과 파싱 실패: {e}")
            return []
    
    def _map_severity(self, bandit_severity: str) -> str:
        """Bandit 심각도를 표준 심각도로 매핑"""
        severity_mapping = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high'
        }
        return severity_mapping.get(bandit_severity.lower(), 'low')
    
    def _map_confidence(self, bandit_confidence: str) -> float:
        """Bandit 신뢰도를 점수로 매핑"""
        confidence_mapping = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.9
        }
        return confidence_mapping.get(bandit_confidence.lower(), 0.5)
    
    def _extract_cwe_id(self, result: Dict[str, Any]) -> Optional[str]:
        """Bandit 결과에서 CWE ID 추출"""
        # Bandit은 직접적인 CWE ID를 제공하지 않으므로 test_id 기반으로 매핑
        test_id = result.get('test_id', '')
        
        # 일반적인 Python 보안 테스트 ID와 CWE 매핑
        cwe_mapping = {
            'B101': 'CWE-78',  # assert_used
            'B102': 'CWE-78',  # exec_used
            'B103': 'CWE-78',  # set_bad_file_permissions
            'B104': 'CWE-78',  # hardcoded_bind_all_interfaces
            'B105': 'CWE-259', # hardcoded_password_string
            'B106': 'CWE-259', # hardcoded_password_funcarg
            'B107': 'CWE-259', # hardcoded_password_default
            'B201': 'CWE-78',  # flask_debug_true
            'B301': 'CWE-78',  # pickle
            'B302': 'CWE-78',  # marshal
            'B303': 'CWE-327', # md5
            'B304': 'CWE-327', # md5_insecure
            'B305': 'CWE-327', # sha1
            'B306': 'CWE-78',  # mktemp_q
            'B307': 'CWE-78',  # eval
            'B308': 'CWE-78',  # mark_safe
            'B309': 'CWE-78',  # httpsconnection
            'B310': 'CWE-78',  # urllib_urlopen
            'B311': 'CWE-78',  # random
            'B312': 'CWE-78',  # telnetlib
            'B313': 'CWE-78',  # xml_bad_cElementTree
            'B314': 'CWE-78',  # xml_bad_ElementTree
            'B315': 'CWE-78',  # xml_bad_expatreader
            'B316': 'CWE-78',  # xml_bad_expatbuilder
            'B317': 'CWE-78',  # xml_bad_sax
            'B318': 'CWE-78',  # xml_bad_minidom
            'B319': 'CWE-78',  # xml_bad_pulldom
            'B320': 'CWE-78',  # xml_bad_etree
            'B321': 'CWE-78',  # ftplib
            'B322': 'CWE-78',  # input
            'B323': 'CWE-78',  # unverified_context
            'B324': 'CWE-78',  # hashlib_new_insecure_functions
            'B325': 'CWE-78',  # tempnam
            'B401': 'CWE-78',  # import_telnetlib
            'B402': 'CWE-78',  # import_ftplib
            'B403': 'CWE-78',  # import_pickle
            'B404': 'CWE-78',  # import_subprocess
            'B405': 'CWE-78',  # import_xml_etree
            'B406': 'CWE-78',  # import_xml_sax
            'B407': 'CWE-78',  # import_xml_expat
            'B408': 'CWE-78',  # import_xml_minidom
            'B409': 'CWE-78',  # import_xml_pulldom
            'B410': 'CWE-78',  # import_lxml
            'B411': 'CWE-78',  # import_xmlrpclib
            'B412': 'CWE-78',  # import_httpoxy
            'B413': 'CWE-78',  # import_pycrypto
            'B501': 'CWE-78',  # request_with_no_cert_validation
            'B601': 'CWE-78',  # paramiko_calls
            'B602': 'CWE-78',  # subprocess_popen_with_shell_equals_true
            'B603': 'CWE-78',  # subprocess_without_shell_equals_true
            'B604': 'CWE-78',  # any_other_function_with_shell_equals_true
            'B605': 'CWE-78',  # start_process_with_a_shell
            'B606': 'CWE-78',  # start_process_with_no_shell
            'B607': 'CWE-78',  # start_process_with_partial_path
            'B608': 'CWE-78',  # hardcoded_sql_expressions
            'B609': 'CWE-78',  # linux_commands_wildcard_injection
            'B701': 'CWE-78',  # jinja2_autoescape_false
        }
        
        return cwe_mapping.get(test_id)

class RAGSecurityParser:
    """RAG 기반 보안 분석 파서"""
    
    def __init__(self, cwe_database_path: str = None):
        """RAG 보안 파서 초기화"""
        self.cwe_database = {}
        if cwe_database_path:
            self.load_cwe_database(cwe_database_path)
    
    def load_cwe_database(self, database_path: str):
        """CWE 데이터베이스 로드"""
        try:
            with open(database_path, 'r', encoding='utf-8') as f:
                self.cwe_database = json.load(f)
            logger.info(f"CWE 데이터베이스 로드됨: {len(self.cwe_database)}개 항목")
        except Exception as e:
            logger.error(f"CWE 데이터베이스 로드 실패: {e}")
            self.cwe_database = {}
    
    def parse_rag_results(self, rag_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """RAG 검색 결과를 파싱하여 보안 분석 결과로 변환"""
        security_findings = []
        
        for result in rag_results:
            finding = self._create_security_finding(result)
            if finding:
                security_findings.append(finding)
        
        return security_findings
    
    def _create_security_finding(self, rag_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """RAG 결과에서 보안 발견 항목 생성"""
        try:
            # RAG 결과에서 CWE 정보 추출
            cwe_id = self._extract_cwe_id(rag_result)
            
            # CWE 데이터베이스에서 상세 정보 조회
            cwe_details = self._get_cwe_details(cwe_id) if cwe_id else {}
            
            finding = {
                'id': rag_result.get('id', ''),
                'source': 'rag_analysis',
                'cwe_id': cwe_id,
                'title': cwe_details.get('name', rag_result.get('title', '')),
                'description': cwe_details.get('description', rag_result.get('content', '')),
                'severity': self._assess_severity(cwe_details, rag_result),
                'confidence': rag_result.get('score', 0.0),
                'references': cwe_details.get('references', []),
                'mitigation': cwe_details.get('mitigation', ''),
                'rag_context': {
                    'source_document': rag_result.get('source', ''),
                    'relevance_score': rag_result.get('score', 0.0),
                    'extracted_content': rag_result.get('content', '')
                }
            }
            
            return finding
            
        except Exception as e:
            logger.error(f"보안 발견 항목 생성 실패: {e}")
            return None
    
    def _extract_cwe_id(self, rag_result: Dict[str, Any]) -> Optional[str]:
        """RAG 결과에서 CWE ID 추출"""
        content = rag_result.get('content', '')
        title = rag_result.get('title', '')
        
        # CWE 패턴 매칭 (CWE-123 형식)
        import re
        cwe_pattern = r'CWE-(\d+)'
        
        # 제목에서 먼저 검색
        title_match = re.search(cwe_pattern, title)
        if title_match:
            return f"CWE-{title_match.group(1)}"
        
        # 내용에서 검색
        content_match = re.search(cwe_pattern, content)
        if content_match:
            return f"CWE-{content_match.group(1)}"
        
        return None
    
    def _get_cwe_details(self, cwe_id: str) -> Dict[str, Any]:
        """CWE ID에 해당하는 상세 정보 조회"""
        if not cwe_id or cwe_id not in self.cwe_database:
            return {}
        
        return self.cwe_database[cwe_id]
    
    def _assess_severity(self, cwe_details: Dict[str, Any], rag_result: Dict[str, Any]) -> str:
        """보안 심각도 평가"""
        # CWE 데이터베이스의 심각도 정보 우선 사용
        if 'severity' in cwe_details:
            return cwe_details['severity']
        
        # RAG 결과의 신뢰도 점수 기반 심각도 평가
        score = rag_result.get('score', 0.0)
        
        if score >= 0.8:
            return 'high'
        elif score >= 0.6:
            return 'medium'
        else:
            return 'low'
    
    def generate_security_report(self, rag_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """보안 분석 보고서 생성"""
        findings = self.parse_rag_results(rag_results)
        
        # 통계 정보 계산
        severity_counts = {}
        cwe_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            cwe_id = finding.get('cwe_id')
            if cwe_id:
                cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
        
        report = {
            'summary': {
                'total_findings': len(findings),
                'severity_distribution': severity_counts,
                'top_cwe_vulnerabilities': sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            },
            'findings': findings,
            'analysis_metadata': {
                'parser_version': '1.0',
                'analysis_type': 'rag_based_security_analysis',
                'timestamp': self._get_timestamp()
            }
        }
        
        return report
    
    def _get_timestamp(self) -> str:
        """현재 타임스탬프 반환"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def export_findings(self, findings: List[Dict[str, Any]], output_path: str, format: str = 'json'):
        """발견 항목을 파일로 내보내기"""
        try:
            if format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(findings, f, ensure_ascii=False, indent=2)
            else:
                logger.warning(f"지원하지 않는 형식: {format}")
                return False
            
            logger.info(f"발견 항목 내보내기 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"발견 항목 내보내기 실패: {e}")
            return False

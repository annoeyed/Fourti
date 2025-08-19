"""
SAST/DAST 도구 결과 파서
Bandit, SpotBugs, cppcheck, ZAP 등의 결과를 통합 스키마로 변환
"""

import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from .sast_dast_schema import SecurityFinding, ToolType, Language, Severity

logger = logging.getLogger(__name__)

class BaseParser:
    """기본 파서 클래스"""
    
    def parse(self, file_path: str) -> List[SecurityFinding]:
        """파일을 파싱하여 SecurityFinding 리스트 반환"""
        raise NotImplementedError
    
    def _map_severity(self, tool_severity: str) -> Severity:
        """도구별 심각도를 표준 심각도로 매핑"""
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL,
            'info': Severity.LOW,
            'warning': Severity.MEDIUM,
            'error': Severity.HIGH,
            'fatal': Severity.CRITICAL
        }
        return severity_map.get(tool_severity.lower(), Severity.MEDIUM)

class BanditParser(BaseParser):
    """Bandit (Python) 결과 파서"""
    
    def parse(self, file_path: str) -> List[SecurityFinding]:
        """Bandit JSON 결과 파싱"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            
            # Bandit 결과 구조: {"results": [{"filename": "...", "line_number": ..., "issue_severity": "...", ...}]}
            for result in data.get('results', []):
                finding = SecurityFinding(
                    source="bandit",
                    tool=ToolType.SAST,
                    rule_id=result.get('test_id', 'unknown'),
                    cwe=self._map_bandit_to_cwe(result.get('test_id')),
                    severity=self._map_severity(result.get('issue_severity', 'medium')),
                    language=Language.PYTHON,
                    file_path=result.get('filename'),
                    line_number=result.get('line_number'),
                    message=result.get('issue_text', ''),
                    evidence=result.get('code', ''),
                    links=[f"https://bandit.readthedocs.io/en/latest/plugins/b{result.get('test_id', '')}.html"]
                )
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Bandit 파싱 오류: {e}")
            return []
    
    def _map_bandit_to_cwe(self, test_id: str) -> Optional[str]:
        """Bandit 테스트 ID를 CWE로 매핑"""
        cwe_mapping = {
            'B101': 'CWE-78',    # assert_used
            'B102': 'CWE-78',    # exec_used
            'B103': 'CWE-78',    # set_bad_file_permissions
            'B104': 'CWE-78',    # hardcoded_bind_all_interfaces
            'B105': 'CWE-259',   # hardcoded_password_string
            'B106': 'CWE-259',   # hardcoded_password_funcarg
            'B107': 'CWE-259',   # hardcoded_password_default
            'B201': 'CWE-78',    # flask_debug_true
            'B301': 'CWE-78',    # pickle
            'B302': 'CWE-78',    # marshal
            'B303': 'CWE-327',   # md5
            'B304': 'CWE-327',   # md5_insecure
            'B305': 'CWE-327',   # sha1
            'B306': 'CWE-78',    # mktemp_q
            'B307': 'CWE-78',    # eval
            'B308': 'CWE-78',    # mark_safe
            'B309': 'CWE-78',    # httpsconnection
            'B310': 'CWE-78',    # urllib_urlopen
            'B311': 'CWE-78',    # random
            'B312': 'CWE-78',    # telnetlib
            'B313': 'CWE-78',    # xml_bad_cElementTree
            'B314': 'CWE-78',    # xml_bad_ElementTree
            'B315': 'CWE-78',    # xml_bad_expatreader
            'B316': 'CWE-78',    # xml_bad_expatbuilder
            'B317': 'CWE-78',    # xml_bad_sax
            'B318': 'CWE-78',    # xml_bad_minidom
            'B319': 'CWE-78',    # xml_bad_pulldom
            'B320': 'CWE-78',    # xml_bad_etree
            'B321': 'CWE-78',    # ftplib
            'B322': 'CWE-78',    # input
            'B323': 'CWE-78',    # unverified_context
            'B324': 'CWE-78',    # hashlib_new_insecure_functions
            'B325': 'CWE-78',    # tempnam
            'B401': 'CWE-78',    # import_telnetlib
            'B402': 'CWE-78',    # import_ftplib
            'B403': 'CWE-78',    # import_pickle
            'B404': 'CWE-78',    # import_subprocess
            'B405': 'CWE-78',    # import_xml_etree
            'B406': 'CWE-78',    # import_xml_expat
            'B407': 'CWE-78',    # import_xml_sax
            'B408': 'CWE-78',    # import_xml_minidom
            'B409': 'CWE-78',    # import_xml_pulldom
            'B410': 'CWE-78',    # import_lxml
            'B411': 'CWE-78',    # import_xmlrpclib
            'B412': 'CWE-78',    # import_httpoxy
            'B413': 'CWE-78',    # import_pycrypto
            'B501': 'CWE-78',    # request_with_no_cert_validation
            'B601': 'CWE-78',    # paramiko_calls
            'B602': 'CWE-78',    # subprocess_popen_with_shell_equals_true
            'B603': 'CWE-78',    # subprocess_without_shell_equals_true
            'B604': 'CWE-78',    # any_other_function_with_shell_equals_true
            'B605': 'CWE-78',    # start_process_with_a_shell
            'B606': 'CWE-78',    # start_process_with_no_shell
            'B607': 'CWE-78',    # start_process_with_partial_path
            'B608': 'CWE-78',    # hardcoded_sql_expressions
            'B609': 'CWE-78',    # django_extra_used
            'B610': 'CWE-78',    # django_models_xml
            'B611': 'CWE-78',    # django_rawsql
            'B701': 'CWE-78',    # jinja2_autoescape_false
        }
        return cwe_mapping.get(test_id)

class ZAPParser(BaseParser):
    """ZAP (웹 애플리케이션) 결과 파서"""
    
    def parse(self, file_path: str) -> List[SecurityFinding]:
        """ZAP JSON 결과 파싱"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            
            # ZAP 결과 구조: {"site": [{"alerts": [{"alert": "...", "risk": "...", ...}]}]}
            for site in data.get('site', []):
                for alert in site.get('alerts', []):
                    finding = SecurityFinding(
                        source="zap",
                        tool=ToolType.DAST,
                        rule_id=alert.get('pluginid', 'unknown'),
                        cwe=self._map_zap_to_cwe(alert.get('cweid')),
                        severity=self._map_zap_severity(alert.get('risk')),
                        language=Language.WEB,
                        endpoint=alert.get('url'),
                        message=alert.get('alert', ''),
                        evidence=alert.get('evidence', ''),
                        links=[alert.get('reference', '')] if alert.get('reference') else []
                    )
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"ZAP 파싱 오류: {e}")
            return []
    
    def _map_zap_severity(self, risk: str) -> Severity:
        """ZAP 위험도를 표준 심각도로 매핑"""
        risk_map = {
            'Low': Severity.LOW,
            'Medium': Severity.MEDIUM,
            'High': Severity.HIGH,
            'Informational': Severity.LOW
        }
        return risk_map.get(risk, Severity.MEDIUM)
    
    def _map_zap_to_cwe(self, cwe_id: str) -> Optional[str]:
        """ZAP CWE ID를 표준 형식으로 변환"""
        if cwe_id and cwe_id.isdigit():
            return f"CWE-{cwe_id}"
        return cwe_id

class SpotBugsParser(BaseParser):
    """SpotBugs (Java) 결과 파서"""
    
    def parse(self, file_path: str) -> List[SecurityFinding]:
        """SpotBugs XML/JSON 결과 파싱"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.json'):
                    data = json.load(f)
                    return self._parse_spotbugs_json(data)
                else:
                    # XML 파싱은 간단한 구현
                    content = f.read()
                    return self._parse_spotbugs_xml(content)
            
        except Exception as e:
            logger.error(f"SpotBugs 파싱 오류: {e}")
            return []
    
    def _parse_spotbugs_json(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """SpotBugs JSON 결과 파싱"""
        findings = []
        
        for bug in data.get('bugs', []):
            finding = SecurityFinding(
                source="spotbugs",
                tool=ToolType.SAST,
                rule_id=bug.get('type', 'unknown'),
                cwe=self._map_spotbugs_to_cwe(bug.get('type')),
                severity=self._map_spotbugs_severity(bug.get('priority')),
                language=Language.JAVA,
                file_path=bug.get('sourceFile'),
                line_number=bug.get('lineNumber'),
                message=bug.get('message', ''),
                evidence=bug.get('sourceLine', ''),
                links=[bug.get('url', '')] if bug.get('url') else []
            )
            findings.append(finding)
        
        return findings
    
    def _parse_spotbugs_xml(self, content: str) -> List[SecurityFinding]:
        """SpotBugs XML 결과 파싱 (간단한 구현)"""
        # XML 파싱은 복잡하므로 간단한 키워드 기반 파싱
        findings = []
        
        # 간단한 패턴 매칭으로 주요 보안 이슈 찾기
        security_patterns = [
            ('SQL_INJECTION', 'CWE-89', 'SQL Injection vulnerability'),
            ('XSS', 'CWE-79', 'Cross-site scripting vulnerability'),
            ('PATH_TRAVERSAL', 'CWE-22', 'Path traversal vulnerability'),
            ('COMMAND_INJECTION', 'CWE-78', 'Command injection vulnerability')
        ]
        
        for pattern, cwe, message in security_patterns:
            if pattern.lower() in content.lower():
                finding = SecurityFinding(
                    source="spotbugs",
                    tool=ToolType.SAST,
                    rule_id=pattern,
                    cwe=cwe,
                    severity=Severity.HIGH,
                    language=Language.JAVA,
                    message=message,
                    evidence=f"Pattern: {pattern}"
                )
                findings.append(finding)
        
        return findings
    
    def _map_spotbugs_severity(self, priority: str) -> Severity:
        """SpotBugs 우선순위를 표준 심각도로 매핑"""
        priority_map = {
            'Low': Severity.LOW,
            'Medium': Severity.MEDIUM,
            'High': Severity.HIGH
        }
        return priority_map.get(priority, Severity.MEDIUM)
    
    def _map_spotbugs_to_cwe(self, bug_type: str) -> Optional[str]:
        """SpotBugs 버그 타입을 CWE로 매핑"""
        cwe_mapping = {
            'SQL_INJECTION': 'CWE-89',
            'XSS': 'CWE-79',
            'PATH_TRAVERSAL': 'CWE-22',
            'COMMAND_INJECTION': 'CWE-78',
            'HARD_CODE_PASSWORD': 'CWE-259',
            'WEAK_ENCRYPTION': 'CWE-327',
            'INSECURE_RANDOM': 'CWE-338'
        }
        return cwe_mapping.get(bug_type)

class CppCheckParser(BaseParser):
    """cppcheck (C/C++) 결과 파서"""
    
    def parse(self, file_path: str) -> List[SecurityFinding]:
        """cppcheck XML/JSON 결과 파싱"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.json'):
                    data = json.load(f)
                    return self._parse_cppcheck_json(data)
                else:
                    content = f.read()
                    return self._parse_cppcheck_xml(content)
            
        except Exception as e:
            logger.error(f"cppcheck 파싱 오류: {e}")
            return []
    
    def _parse_cppcheck_json(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """cppcheck JSON 결과 파싱"""
        findings = []
        
        for error in data.get('errors', []):
            finding = SecurityFinding(
                source="cppcheck",
                tool=ToolType.SAST,
                rule_id=error.get('id', 'unknown'),
                cwe=self._map_cppcheck_to_cwe(error.get('id')),
                severity=self._map_cppcheck_severity(error.get('severity')),
                language=Language.CPP if error.get('file', '').endswith(('.cpp', '.cc', '.cxx')) else Language.C,
                file_path=error.get('file'),
                line_number=error.get('line'),
                message=error.get('msg', ''),
                evidence=error.get('verbose', ''),
                links=[f"https://cppcheck.sourceforge.io/error/{error.get('id', '')}.html"]
            )
            findings.append(finding)
        
        return findings
    
    def _parse_cppcheck_xml(self, content: str) -> List[SecurityFinding]:
        """cppcheck XML 결과 파싱 (간단한 구현)"""
        findings = []
        
        # 간단한 패턴 매칭으로 주요 보안 이슈 찾기
        security_patterns = [
            ('bufferAccessOutOfBounds', 'CWE-119', 'Buffer access out of bounds'),
            ('arrayIndexOutOfBounds', 'CWE-119', 'Array index out of bounds'),
            ('nullPointer', 'CWE-476', 'Null pointer dereference'),
            ('uninitvar', 'CWE-457', 'Uninitialized variable'),
            ('memleak', 'CWE-401', 'Memory leak'),
            ('resourceLeak', 'CWE-772', 'Resource leak')
        ]
        
        for pattern, cwe, message in security_patterns:
            if pattern.lower() in content.lower():
                finding = SecurityFinding(
                    source="cppcheck",
                    tool=ToolType.SAST,
                    rule_id=pattern,
                    cwe=cwe,
                    severity=Severity.HIGH,
                    language=Language.CPP,
                    message=message,
                    evidence=f"Pattern: {pattern}"
                )
                findings.append(finding)
        
        return findings
    
    def _map_cppcheck_severity(self, severity: str) -> Severity:
        """cppcheck 심각도를 표준 심각도로 매핑"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'style': Severity.LOW,
            'performance': Severity.LOW,
            'portability': Severity.LOW,
            'information': Severity.LOW
        }
        return severity_map.get(severity, Severity.MEDIUM)
    
    def _map_cppcheck_to_cwe(self, error_id: str) -> Optional[str]:
        """cppcheck 에러 ID를 CWE로 매핑"""
        cwe_mapping = {
            'bufferAccessOutOfBounds': 'CWE-119',
            'arrayIndexOutOfBounds': 'CWE-119',
            'nullPointer': 'CWE-476',
            'uninitvar': 'CWE-457',
            'memleak': 'CWE-401',
            'resourceLeak': 'CWE-772',
            'useAfterMove': 'CWE-825',
            'danglingLifetime': 'CWE-416'
        }
        return cwe_mapping.get(error_id)

class ParserFactory:
    """파서 팩토리 클래스"""
    
    @staticmethod
    def create_parser(tool_name: str) -> BaseParser:
        """도구명에 따라 적절한 파서 생성"""
        parsers = {
            'bandit': BanditParser,
            'zap': ZAPParser,
            'spotbugs': SpotBugsParser,
            'cppcheck': CppCheckParser
        }
        
        parser_class = parsers.get(tool_name.lower())
        if parser_class:
            return parser_class()
        else:
            raise ValueError(f"지원하지 않는 도구: {tool_name}")
    
    @staticmethod
    def parse_all_results(result_files: Dict[str, str]) -> List[SecurityFinding]:
        """여러 도구의 결과를 한번에 파싱"""
        all_findings = []
        
        for tool_name, file_path in result_files.items():
            try:
                parser = ParserFactory.create_parser(tool_name)
                findings = parser.parse(file_path)
                all_findings.extend(findings)
                logger.info(f"{tool_name}: {len(findings)}개 발견")
            except Exception as e:
                logger.error(f"{tool_name} 파싱 실패: {e}")
        
        return all_findings

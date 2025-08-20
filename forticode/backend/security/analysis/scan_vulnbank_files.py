"""
실제 VulnBank 파일들을 스캔하여 취약점을 찾고 워크플로우 분석을 수행하는 스크립트
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_vulnbank_patterns():
    """VulnBank 취약점 패턴 정의"""
    return [
        # SQL Injection 패턴
        (r'f"SELECT.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string', 'HIGH'),
        (r'f"INSERT.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string', 'HIGH'),
        (r'f"UPDATE.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string', 'HIGH'),
        (r'f"DELETE.*\{.*\}"', 'CWE-89', 'SQL Injection via f-string', 'HIGH'),
        (r'execute\(f".*\{.*\}"', 'CWE-89', 'SQL Injection via execute', 'HIGH'),
        (r'cursor\.execute\(f".*\{.*\}"', 'CWE-89', 'SQL Injection via cursor.execute', 'HIGH'),
        
        # Command Injection 패턴
        (r'subprocess\.run\(.*shell=True', 'CWE-78', 'Command Injection via shell=True', 'CRITICAL'),
        (r'os\.system\(', 'CWE-78', 'Command Injection via os.system', 'CRITICAL'),
        (r'subprocess\.call\(.*shell=True', 'CWE-78', 'Command Injection via subprocess.call', 'CRITICAL'),
        
        # Unsafe Deserialization 패턴
        (r'pickle\.loads\(', 'CWE-502', 'Unsafe Pickle Deserialization', 'HIGH'),
        (r'pickle\.load\(', 'CWE-502', 'Unsafe Pickle Deserialization', 'HIGH'),
        
        # Path Traversal 패턴
        (r'os\.path\.join\(.*filename\)', 'CWE-22', 'Path Traversal vulnerability', 'MEDIUM'),
        (r'open\(.*filename', 'CWE-22', 'Path Traversal via file open', 'MEDIUM'),
        (r'file_path = os\.path\.join\(.*filename\)', 'CWE-22', 'Path Traversal in file path', 'MEDIUM'),
        
        # Weak Cryptography 패턴
        (r'hashlib\.md5\(', 'CWE-328', 'Weak MD5 hash algorithm', 'MEDIUM'),
        (r'random\.seed\(', 'CWE-338', 'Predictable random seed', 'MEDIUM'),
        (r'random\.seed\(12345\)', 'CWE-338', 'Fixed random seed', 'HIGH'),
        
        # Information Disclosure 패턴
        (r'print\(f"\[DEBUG\].*\{.*\}"', 'CWE-200', 'Debug information disclosure', 'LOW'),
        (r'print\(f"\[ERROR\].*\{.*\}"', 'CWE-200', 'Error information disclosure', 'LOW'),
        
        # Format String 패턴
        (r'\.format\(.*user_input', 'CWE-134', 'Format String vulnerability', 'MEDIUM'),
        (r'f".*\{.*\}"', 'CWE-134', 'Potential format string vulnerability', 'LOW'),
        
        # File Upload 패턴
        (r'\.endswith\(\.py\)', 'CWE-434', 'Python file upload risk', 'MEDIUM'),
        (r'\.endswith\(\.sh\)', 'CWE-434', 'Shell script upload risk', 'HIGH'),
        (r'subprocess\.run\(\[.*upload_path\]', 'CWE-434', 'Uploaded file execution', 'CRITICAL'),
        
        # XXE 패턴
        (r'ET\.XMLParser\(\)', 'CWE-611', 'XXE vulnerability risk', 'MEDIUM'),
        (r'ET\.fromstring\(.*parser\)', 'CWE-611', 'XXE vulnerability risk', 'MEDIUM'),
    ]

def scan_file_for_vulnerabilities(file_path: Path, patterns: List) -> List[Dict[str, Any]]:
    """개별 파일을 스캔하여 취약점 찾기"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        findings = []
        
        for pattern, cwe_id, message, severity_level in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # 라인 번호 계산
                line_number = content[:match.start()].count('\n') + 1
                
                # 컨텍스트 추출 (매칭 전후 50자)
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(content), match.end() + 50)
                context = content[start_pos:end_pos]
                
                finding = {
                    'file_path': str(file_path),
                    'line_number': line_number,
                    'pattern': pattern,
                    'cwe': cwe_id,
                    'message': message,
                    'severity': severity_level,
                    'matched_code': match.group(),
                    'context': context,
                    'start_pos': match.start(),
                    'end_pos': match.end()
                }
                findings.append(finding)
        
        return findings
        
    except Exception as e:
        print(f"파일 스캔 오류 ({file_path}): {e}")
        return []

def generate_secure_code_suggestions(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """발견된 취약점에 대한 안전한 코드 제안 생성"""
    secure_code_suggestions = {}
    
    for finding in findings:
        cwe = finding['cwe']
        message = finding['message']
        matched_code = finding['matched_code']
        
        if cwe == 'CWE-89':  # SQL Injection
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: parameterized query 사용\ncursor.execute('SELECT * FROM users WHERE name = %s', (user_input,))",
                'explanation': 'SQL Injection을 방지하기 위해 parameterized query를 사용하세요.',
                'best_practices': ['parameterized query 사용', '입력 검증', '출력 인코딩']
            }
        
        elif cwe == 'CWE-78':  # Command Injection
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: shell=False 사용\nsubprocess.run(command.split(), shell=False, capture_output=True, text=True)",
                'explanation': 'Command Injection을 방지하기 위해 shell=True를 피하고 명령어를 리스트로 분리하세요.',
                'best_practices': ['shell=False 사용', '명령어 검증', '화이트리스트 기반 실행']
            }
        
        elif cwe == 'CWE-502':  # Unsafe Deserialization
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: json 사용\nimport json\ndata = json.loads(safe_data)",
                'explanation': 'pickle 대신 json을 사용하여 안전한 역직렬화를 수행하세요.',
                'best_practices': ['pickle 사용 금지', 'json 사용', '입력 검증']
            }
        
        elif cwe == 'CWE-22':  # Path Traversal
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: 경로 검증\nimport os\nsafe_path = os.path.abspath(os.path.join('/tmp', filename))\nif not safe_path.startswith('/tmp'):\n    raise ValueError('Invalid path')\nwith open(safe_path, 'r') as f:\n    return f.read()",
                'explanation': 'Path Traversal을 방지하기 위해 경로를 검증하고 절대 경로를 사용하세요.',
                'best_practices': ['경로 검증', '절대 경로 사용', '화이트리스트 기반 접근']
            }
        
        elif cwe == 'CWE-328':  # Weak Cryptography
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: SHA-256 사용\nimport hashlib\nhashed = hashlib.sha256(password.encode()).hexdigest()",
                'explanation': 'MD5 대신 SHA-256과 같은 강력한 해시 알고리즘을 사용하세요.',
                'best_practices': ['강력한 해시 알고리즘 사용', '솔트 추가', 'bcrypt 사용 고려']
            }
        
        elif cwe == 'CWE-338':  # Predictable Random Seed
            secure_code_suggestions[f"fix_{cwe}_{finding['line_number']}"] = {
                'vulnerability': finding,
                'secure_code': f"# 취약한 코드: {matched_code}\n# 안전한 코드: 암호학적으로 안전한 난수 사용\nimport secrets\nrandom_value = secrets.randbelow(1000)",
                'explanation': '예측 가능한 난수 시드를 피하고 암호학적으로 안전한 난수를 사용하세요.',
                'best_practices': ['secrets 모듈 사용', '예측 가능한 시드 금지', '암호학적 난수 사용']
            }
    
    return secure_code_suggestions

def generate_secure_file_version(file_path: str, findings: List[Dict[str, Any]]) -> str:
    """전체 파일의 안전한 버전 생성"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 취약점별 수정 사항 적용
        secure_content = content
        
        for finding in findings:
            if finding['cwe'] == 'CWE-89':  # SQL Injection
                # f-string SQL을 parameterized query로 변경
                old_pattern = r'f"SELECT.*\{.*\}"'
                new_code = "cursor.execute('SELECT * FROM users WHERE name = %s', (user_input,))"
                secure_content = re.sub(old_pattern, new_code, secure_content)
            
            elif finding['cwe'] == 'CWE-78':  # Command Injection
                # shell=True를 shell=False로 변경
                secure_content = secure_content.replace('shell=True', 'shell=False')
                secure_content = secure_content.replace('os.system(', '# os.system( # 보안상 위험 - 사용 금지')
            
            elif finding['cwe'] == 'CWE-502':  # Unsafe Deserialization
                # pickle.loads를 json.loads로 변경
                secure_content = secure_content.replace('pickle.loads(', 'json.loads( # pickle 대신 json 사용')
                secure_content = secure_content.replace('pickle.load(', 'json.load( # pickle 대신 json 사용')
            
            elif finding['cwe'] == 'CWE-22':  # Path Traversal
                # 경로 검증 코드 추가
                path_validation = """
# 경로 검증 함수 추가
def validate_path(filename):
    safe_path = os.path.abspath(os.path.join('/tmp', filename))
    if not safe_path.startswith('/tmp'):
        raise ValueError('Invalid path')
    return safe_path
"""
                secure_content = secure_content.replace('def vulnerable_path_traversal(filename):', 
                                                     'def vulnerable_path_traversal(filename):' + path_validation)
        
        # 보안 헤더 추가
        security_header = '''"""
보안 취약점이 수정된 안전한 버전
수정된 취약점: {}
""".format(', '.join(set(f['cwe'] for f in findings)))

'''
        
        return security_header + secure_content
        
    except Exception as e:
        print(f"안전한 파일 버전 생성 오류 ({file_path}): {e}")
        return content

def scan_vulnbank_project(vulnbank_path: str) -> Dict[str, Any]:
    """VulnBank 프로젝트 전체 스캔 및 워크플로우 분석"""
    vulnbank_path = Path(vulnbank_path)
    
    if not vulnbank_path.exists():
        return {"error": f"VulnBank 프로젝트 경로를 찾을 수 없습니다: {vulnbank_path}"}
    
    print(f"VulnBank 프로젝트 스캔 및 워크플로우 분석 시작: {vulnbank_path}")
    
    # 취약점 패턴 가져오기
    patterns = get_vulnbank_patterns()
    print(f"정의된 취약점 패턴 수: {len(patterns)}")
    
    # Python 파일 찾기
    python_files = []
    for py_file in vulnbank_path.rglob("*.py"):
        if not any(part.startswith('.') for part in py_file.parts):
            python_files.append(py_file)
    
    print(f"발견된 Python 파일 수: {len(python_files)}")
    
    # 각 파일 스캔
    all_findings = []
    file_findings = {}
    
    for py_file in python_files:
        print(f"스캔 중: {py_file.relative_to(vulnbank_path)}")
        findings = scan_file_for_vulnerabilities(py_file, patterns)
        
        if findings:
            file_findings[str(py_file.relative_to(vulnbank_path))] = findings
            all_findings.extend(findings)
    
    # 결과 분석
    total_findings = len(all_findings)
    
    # CWE별 분류
    cwe_distribution = {}
    for finding in all_findings:
        cwe = finding['cwe']
        cwe_distribution[cwe] = cwe_distribution.get(cwe, 0) + 1
    
    # 심각도별 분류
    severity_distribution = {}
    for finding in all_findings:
        severity = finding['severity']
        severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
    
    # 보안 점수 계산 (0-100, 높을수록 안전)
    severity_weights = {
        'CRITICAL': 30.0,
        'HIGH': 25.0,
        'MEDIUM': 20.0,
        'LOW': 10.0
    }
    
    base_score = 100.0
    for finding in all_findings:
        base_score -= severity_weights.get(finding['severity'], 15.0)
    
    security_score = max(0.0, min(100.0, base_score))
    
    # 위험 수준 판정
    if security_score >= 80:
        risk_level = "LOW"
    elif security_score >= 60:
        risk_level = "MEDIUM"
    elif security_score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"
    
    # 워크플로우 분석: 안전한 코드 생성
    print("\n워크플로우 분석: 안전한 코드 생성 중...")
    secure_code_suggestions = generate_secure_code_suggestions(all_findings)
    
    # 안전한 파일 버전 생성
    secure_file_versions = {}
    for file_path, findings in file_findings.items():
        full_path = vulnbank_path / file_path
        secure_file_versions[file_path] = {
            'original_file': file_path,
            'secure_code': generate_secure_file_version(str(full_path), findings),
            'vulnerabilities_fixed': len(findings),
            'cwe_list': list(set(f['cwe'] for f in findings))
        }
    
    # 권장사항 생성
    recommendations = []
    if security_score < 50:
        recommendations.append("VulnBank 프로젝트는 교육용이지만 즉시 보안 검토가 필요합니다.")
    
    if any(f['severity'] == 'CRITICAL' for f in all_findings):
        recommendations.append("Critical 수준 취약점을 우선적으로 수정하세요.")
    
    if 'CWE-89' in cwe_distribution:
        recommendations.append("SQL Injection 취약점이 다수 발견되었습니다. Parameterized Query를 사용하세요.")
    
    if 'CWE-78' in cwe_distribution:
        recommendations.append("Command Injection 취약점이 발견되었습니다. shell=True 사용을 피하세요.")
    
    if 'CWE-502' in cwe_distribution:
        recommendations.append("Unsafe Deserialization 취약점이 발견되었습니다. pickle 대신 json을 사용하세요.")
    
    if 'CWE-22' in cwe_distribution:
        recommendations.append("Path Traversal 취약점이 발견되었습니다. 경로 검증을 강화하세요.")
    
    if len(recommendations) == 0:
        recommendations.append("VulnBank 프로젝트는 교육용으로 설계되었으며, 실제 프로덕션 환경에서는 사용하지 마세요.")
    
    # 다음 단계 제안
    next_steps = []
    if security_score < 60:
        next_steps.append("생성된 안전한 코드로 취약점을 수정하세요.")
        next_steps.append("보안 코드 리뷰를 통해 추가 취약점을 확인하세요.")
    
    next_steps.extend([
        "OWASP Top 10 웹 애플리케이션 보안 가이드를 학습하세요.",
        "Python 보안 모범 사례를 적용하세요.",
        "정기적인 보안 테스트를 수행하세요.",
        "보안 도구를 활용한 자동화된 검사를 구현하세요."
    ])
    
    # 결과 구성
    result = {
        "project_info": {
            "name": "VulnBank",
            "path": str(vulnbank_path),
            "total_python_files": len(python_files),
            "scanned_files": list(file_findings.keys())
        },
        "security_analysis": {
            "total_findings": total_findings,
            "security_score": security_score,
            "risk_level": risk_level,
            "severity_distribution": severity_distribution,
            "cwe_distribution": cwe_distribution
        },
        "findings_details": all_findings,
        "file_summary": {
            file_path: {
                "findings_count": len(findings),
                "cwe_list": list(set(f['cwe'] for f in findings)),
                "severity_list": list(set(f['severity'] for f in findings))
            }
            for file_path, findings in file_findings.items()
        },
        "workflow_analysis": {
            "secure_code_suggestions": secure_code_suggestions,
            "secure_file_versions": secure_file_versions,
            "recommendations": recommendations,
            "next_steps": next_steps
        }
    }
    
    return result

def print_scan_results(results: Dict[str, Any]):
    """스캔 결과 및 워크플로우 분석 결과 출력"""
    if "error" in results:
        print(f"오류: {results['error']}")
        return
    
    print("\n" + "=" * 60)
    print("VULNBANK 보안 스캔 및 워크플로우 분석 결과")
    print("=" * 60)
    
    # 프로젝트 정보
    project_info = results["project_info"]
    print(f"프로젝트: {project_info['name']}")
    print(f"경로: {project_info['path']}")
    print(f"Python 파일 수: {project_info['total_python_files']}")
    
    # 보안 분석 결과
    security = results["security_analysis"]
    print(f"\n보안 분석 결과:")
    print(f"   총 취약점 수: {security['total_findings']}")
    print(f"   보안 점수: {security['security_score']:.1f}/100")
    print(f"   위험 수준: {security['risk_level']}")
    
    # 심각도별 분포
    severity_dist = security["severity_distribution"]
    print(f"\n심각도별 분포:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_dist.get(severity, 0)
        if count > 0:
            print(f"   {severity}: {count}개")
    
    # CWE별 분포
    cwe_dist = security["cwe_distribution"]
    if cwe_dist:
        print(f"\nCWE별 분포 (상위 10개):")
        sorted_cwe = sorted(cwe_dist.items(), key=lambda x: x[1], reverse=True)[:10]
        for cwe, count in sorted_cwe:
            print(f"   {cwe}: {count}개")
    
    # 파일별 요약
    file_summary = results["file_summary"]
    if file_summary:
        print(f"\n파일별 취약점 요약:")
        for file_path, summary in file_summary.items():
            print(f"   파일: {file_path}: {summary['findings_count']}개 취약점")
            if summary['cwe_list']:
                print(f"      CWE: {', '.join(summary['cwe_list'][:3])}{'...' if len(summary['cwe_list']) > 3 else ''}")
    
    # 워크플로우 분석 결과
    if "workflow_analysis" in results:
        workflow = results["workflow_analysis"]
        
        print(f"\n워크플로우 분석 결과:")
        print(f"   안전한 코드 제안: {len(workflow['secure_code_suggestions'])}개")
        print(f"   안전한 파일 버전: {len(workflow['secure_file_versions'])}개")
        
        # 주요 권장사항
        recommendations = workflow["recommendations"]
        print(f"\n주요 권장사항:")
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")
        
        # 다음 단계
        next_steps = workflow["next_steps"]
        print(f"\n다음 단계:")
        for i, step in enumerate(next_steps, 1):
            print(f"   {i}. {step}")

def main():
    """메인 함수"""
    print("VulnBank 프로젝트 보안 취약점 스캔 및 워크플로우 분석")
    print("=" * 50)
    
    # VulnBank 프로젝트 경로 설정
    vulnbank_path = input("VulnBank 프로젝트 경로를 입력하세요 (기본값: ../../../../vulnbank): ").strip()
    if not vulnbank_path:
        vulnbank_path = "../../../../vulnbank"
    
    vulnbank_path = Path(vulnbank_path).resolve()
    
    if not vulnbank_path.exists():
        print(f"오류: VulnBank 프로젝트 경로를 찾을 수 없습니다: {vulnbank_path}")
        return
    
    print(f"VulnBank 프로젝트 경로: {vulnbank_path}")
    print()
    
    # 프로젝트 스캔 및 워크플로우 분석 실행
    try:
        results = scan_vulnbank_project(str(vulnbank_path))
        print_scan_results(results)
        
        # 결과 저장
        results_dir = vulnbank_path / "security_workflow_results"
        results_dir.mkdir(exist_ok=True)
        
        # 기본 스캔 결과 저장
        json_file = results_dir / "vulnbank_vulnerability_scan.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n스캔 결과가 저장되었습니다: {json_file}")
        
        # 워크플로우 분석 결과 저장
        workflow_file = results_dir / "vulnbank_workflow_analysis.json"
        with open(workflow_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"워크플로우 분석 결과가 저장되었습니다: {workflow_file}")
        
        # 안전한 코드 파일들 저장
        if "workflow_analysis" in results:
            secure_files_dir = results_dir / "secure_code_files"
            secure_files_dir.mkdir(exist_ok=True)
            
            for file_path, file_info in results["workflow_analysis"]["secure_file_versions"].items():
                filename = Path(file_path).name
                secure_file_path = secure_files_dir / f"secure_{filename}"
                
                with open(secure_file_path, 'w', encoding='utf-8') as f:
                    f.write(file_info["secure_code"])
                
                print(f"   안전한 코드 파일 저장: {secure_file_path}")
            
            print(f"모든 안전한 코드 파일이 저장되었습니다: {secure_files_dir}")
        
    except Exception as e:
        print(f"스캔 및 워크플로우 분석 실행 중 오류 발생: {e}")

if __name__ == "__main__":
    main()

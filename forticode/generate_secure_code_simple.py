#!/usr/bin/env python3
"""
간단한 보안 코드 생성 스크립트
기존 취약점 분석 결과를 기반으로 시큐어 코드를 생성합니다.
"""

import os
import json
import sys
from pathlib import Path

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def main():
    """메인 함수"""
    print("🔒 FortiCode 간단한 보안 코드 생성 시작")
    print("=" * 60)
    
    # 1. API 키 확인
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        print("❌ OPENAI_API_KEY 환경변수가 설정되지 않았습니다.")
        return
    
    print("✅ API 키 확인 완료")
    
    # 2. 기존 취약점 분석 결과 확인
    vulnbank_analysis_file = "../vulnbank_security_analysis.json"
    if not Path(vulnbank_analysis_file).exists():
        print(f"❌ 취약점 분석 결과 파일을 찾을 수 없습니다: {vulnbank_analysis_file}")
        print("먼저 취약점 분석을 실행해주세요.")
        return
    
    # 3. 기존 분석 결과 로드
    try:
        with open(vulnbank_analysis_file, 'r', encoding='utf-8') as f:
            analysis_result = json.load(f)
        print("✅ 기존 분석 결과 로드 완료")
    except Exception as e:
        print(f"❌ 분석 결과 로드 실패: {e}")
        return
    
    # 4. 간단한 보안 가이드 생성
    print("🔍 보안 가이드 생성 중...")
    
    security_guide = generate_simple_security_guide(analysis_result)
    
    # 5. 결과 저장
    output_file = "vulnbank_simple_security_guide.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(security_guide, f, indent=2, ensure_ascii=False)
    
    print(f"📁 보안 가이드 저장됨: {output_file}")
    
    # 6. 다음 단계 안내
    print("\n🎯 다음 단계:")
    print("1. 생성된 보안 가이드 검토")
    print("2. 수동으로 코드 수정")
    print("3. 보안 테스트 재실행")

def generate_simple_security_guide(analysis_result):
    """간단한 보안 가이드 생성"""
    
    # 기존 분석 결과에서 취약점 정보 추출
    findings = []
    
    # 새로운 구조에 맞게 파싱
    if 'findings' in analysis_result:
        for result in analysis_result['findings']:
            finding = {
                'id': result.get('finding_id', 'unknown'),
                'source': result.get('source', 'unknown'),
                'severity': result.get('severity', 'low'),
                'title': result.get('message', ''),
                'file_path': result.get('file_path', ''),
                'line_number': result.get('line_number', 0),
                'code': result.get('evidence', ''),
                'cwe': result.get('cwe', ''),
                'mitigation': result.get('secure_coding_guide', '일반적인 보안 모범 사례 적용')
            }
            findings.append(finding)
    
    # Bandit 결과 처리 (기존 구조 지원)
    if 'bandit_report' in analysis_result:
        bandit_data = analysis_result['bandit_report']
        if isinstance(bandit_data, dict) and 'results' in bandit_data:
            for result in bandit_data['results']:
                finding = {
                    'id': f"bandit_{result.get('test_id', 'unknown')}",
                    'source': 'bandit',
                    'severity': result.get('issue_severity', 'low'),
                    'title': result.get('issue_text', ''),
                    'file_path': result.get('filename', ''),
                    'line_number': result.get('line_number', 0),
                    'code': result.get('code', ''),
                    'mitigation': get_mitigation_for_bandit_test(result.get('test_id', ''))
                }
                findings.append(finding)
    
    # Semgrep 결과 처리 (기존 구조 지원)
    if 'semgrep_report' in analysis_result:
        semgrep_data = analysis_result['semgrep_report']
        if isinstance(semgrep_data, list):
            for result in semgrep_data:
                finding = {
                    'id': f"semgrep_{result.get('check_id', 'unknown')}",
                    'source': 'semgrep',
                    'severity': 'medium',  # 기본값
                    'title': result.get('message', ''),
                    'file_path': result.get('path', ''),
                    'line_number': result.get('start', {}).get('line', 0),
                    'code': result.get('extra', {}).get('lines', ''),
                    'mitigation': get_mitigation_for_semgrep_check(result.get('check_id', ''))
                }
                findings.append(finding)
    
    # 보안 가이드 생성
    security_guide = {
        'overview': 'VulnBank 프로젝트 보안 코딩 가이드',
        'total_findings': len(findings),
        'findings': findings,
        'security_recommendations': generate_security_recommendations(findings),
        'code_examples': generate_secure_code_examples(findings),
        'next_steps': [
            '발견된 취약점을 우선순위에 따라 수정',
            '보안 코딩 가이드 준수',
            '정기적인 보안 테스트 수행',
            '보안 코드 리뷰 프로세스 도입'
        ]
    }
    
    return security_guide

def get_mitigation_for_bandit_test(test_id):
    """Bandit 테스트 ID별 완화 방안"""
    mitigations = {
        'B101': 'assert 문을 제거하고 적절한 검증 로직으로 대체',
        'B102': 'exec() 사용 금지, 안전한 대안 사용',
        'B103': '파일 권한을 0o600 이하로 설정',
        'B104': '바인딩 주소를 127.0.0.1로 제한',
        'B105': '하드코딩된 패스워드 제거, 환경변수 사용',
        'B106': '함수 인자로 패스워드 전달 금지',
        'B107': '기본값으로 패스워드 설정 금지',
        'B201': 'Flask debug 모드 비활성화',
        'B301': 'pickle 사용 금지, JSON 등 안전한 형식 사용',
        'B302': 'marshal 사용 금지',
        'B303': 'MD5 사용 금지, hashlib.sha256 사용',
        'B304': 'mktemp 사용 금지, tempfile.mkstemp 사용',
        'B305': 'SHA1 사용 금지, SHA256 사용',
        'B306': 'mktemp_q 사용 금지',
        'B307': 'eval() 사용 금지',
        'B308': 'mark_safe 사용 금지',
        'B309': 'HTTP 연결 시 SSL 검증 활성화',
        'B310': 'urllib.urlopen 대신 requests 사용',
        'B311': 'random 모듈 대신 secrets 모듈 사용',
        'B312': 'telnetlib 사용 금지',
        'B313': 'cElementTree 사용 금지',
        'B314': 'ElementTree 사용 시 입력 검증',
        'B315': 'expatreader 사용 시 입력 검증',
        'B316': 'expatbuilder 사용 시 입력 검증',
        'B317': 'sax 사용 시 입력 검증',
        'B318': 'minidom 사용 시 입력 검증',
        'B319': 'pulldom 사용 시 입력 검증',
        'B320': 'etree 사용 시 입력 검증',
        'B321': 'ftplib 사용 금지',
        'B322': 'input() 사용 금지, raw_input() 사용',
        'B323': 'SSL 컨텍스트 검증 활성화',
        'B324': '안전하지 않은 해시 함수 사용 금지',
        'B325': 'tempnam 사용 금지',
        'B401': 'telnetlib 임포트 금지',
        'B402': 'ftplib 임포트 금지',
        'B403': 'pickle 임포트 금지',
        'B404': 'subprocess 임포트 시 주의',
        'B405': 'xml.etree 임포트 시 주의',
        'B406': 'xml.sax 임포트 시 주의',
        'B407': 'xml.expat 임포트 시 주의',
        'B408': 'xml.minidom 임포트 시 주의',
        'B409': 'xml.pulldom 임포트 시 주의',
        'B410': 'lxml 임포트 시 주의',
        'B411': 'xmlrpclib 임포트 시 주의',
        'B412': 'httpoxy 임포트 금지',
        'B413': 'pycrypto 임포트 금지, pycryptodome 사용',
        'B501': 'SSL 인증서 검증 활성화',
        'B601': 'paramiko 사용 시 주의',
        'B602': 'subprocess에서 shell=True 사용 금지',
        'B603': 'subprocess에서 shell=True 사용 금지',
        'B604': 'shell=True 사용 금지',
        'B605': 'shell=True 사용 금지',
        'B606': 'shell=True 사용 금지',
        'B607': '부분 경로 사용 금지',
        'B608': '하드코딩된 SQL 표현식 사용 금지',
        'B609': '와일드카드 인젝션 방지',
        'B701': 'Jinja2 autoescape 활성화'
    }
    return mitigations.get(test_id, '일반적인 보안 모범 사례 적용')

def get_mitigation_for_semgrep_check(check_id):
    """Semgrep 체크 ID별 완화 방안"""
    mitigations = {
        'python.security.audit.avoid-unsafe-deserialization': '역직렬화 시 신뢰할 수 있는 데이터만 처리',
        'python.security.audit.avoid-unsafe-yaml': 'PyYAML에서 Loader 사용 금지',
        'python.security.audit.avoid-unsafe-xml': 'XML 파싱 시 안전한 파서 사용',
        'python.security.audit.avoid-unsafe-json': 'JSON 파싱 시 안전한 파서 사용',
        'python.security.audit.avoid-unsafe-csv': 'CSV 파싱 시 안전한 파서 사용',
        'python.security.audit.avoid-unsafe-pickle': 'pickle 사용 금지',
        'python.security.audit.avoid-unsafe-marshal': 'marshal 사용 금지',
        'python.security.audit.avoid-unsafe-eval': 'eval() 사용 금지',
        'python.security.audit.avoid-unsafe-exec': 'exec() 사용 금지',
        'python.security.audit.avoid-unsafe-input': 'input() 사용 금지',
        'python.security.audit.avoid-unsafe-os-command': 'OS 명령어 실행 금지',
        'python.security.audit.avoid-unsafe-file-operation': '파일 작업 시 경로 검증',
        'python.security.audit.avoid-unsafe-network': '네트워크 연결 시 검증',
        'python.security.audit.avoid-unsafe-crypto': '안전한 암호화 라이브러리 사용'
    }
    return mitigations.get(check_id, '일반적인 보안 모범 사례 적용')

def generate_security_recommendations(findings):
    """보안 권장사항 생성"""
    recommendations = []
    
    # 심각도별 권장사항
    high_severity = [f for f in findings if f['severity'] in ['high', 'critical']]
    if high_severity:
        recommendations.append(f"고위험 취약점 {len(high_severity)}개를 즉시 수정하세요.")
    
    # 소스별 권장사항
    bandit_findings = [f for f in findings if f['source'] == 'bandit']
    if bandit_findings:
        recommendations.append(f"Bandit 발견 취약점 {len(bandit_findings)}개를 수정하세요.")
    
    semgrep_findings = [f for f in findings if f['source'] == 'semgrep']
    if semgrep_findings:
        recommendations.append(f"Semgrep 발견 취약점 {len(semgrep_findings)}개를 수정하세요.")
    
    # 일반적인 권장사항
    recommendations.extend([
        "입력 검증을 강화하세요.",
        "하드코딩된 시크릿을 환경변수로 이동하세요.",
        "안전한 라이브러리와 API를 사용하세요.",
        "정기적인 보안 코드 리뷰를 수행하세요.",
        "보안 테스트를 자동화하세요."
    ])
    
    return recommendations

def generate_secure_code_examples(findings):
    """안전한 코드 예시 생성"""
    examples = {}
    
    # SQL Injection 방지
    examples['sql_injection_prevention'] = {
        'description': 'SQL Injection 방지를 위한 안전한 코드',
        'unsafe': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'safe': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'explanation': '파라미터화된 쿼리를 사용하여 SQL Injection을 방지합니다.'
    }
    
    # XSS 방지
    examples['xss_prevention'] = {
        'description': 'XSS 방지를 위한 안전한 코드',
        'unsafe': 'return f"<div>{user_input}</div>"',
        'safe': 'return f"<div>{html.escape(user_input)}</div>"',
        'explanation': '사용자 입력을 HTML 이스케이프하여 XSS를 방지합니다.'
    }
    
    # 하드코딩된 시크릿 방지
    examples['secret_management'] = {
        'description': '시크릿 관리를 위한 안전한 코드',
        'unsafe': 'SECRET_KEY = "hardcoded_secret_key_123456"',
        'safe': 'SECRET_KEY = os.environ.get("SECRET_KEY")',
        'explanation': '환경변수를 사용하여 시크릿을 안전하게 관리합니다.'
    }
    
    # 파일 업로드 보안
    examples['secure_file_upload'] = {
        'description': '안전한 파일 업로드',
        'unsafe': 'file.save(os.path.join(upload_folder, filename))',
        'safe': '''
allowed_extensions = {'.txt', '.pdf', '.png'}
if file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
    safe_filename = secure_filename(file.filename)
    file.save(os.path.join(upload_folder, safe_filename))
''',
        'explanation': '파일 확장자를 검증하고 안전한 파일명을 사용합니다.'
    }
    
    return examples

if __name__ == "__main__":
    main()

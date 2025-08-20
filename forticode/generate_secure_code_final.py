#!/usr/bin/env python3
"""
FortiCode 시큐어 코드 자동 생성 스크립트
LLM을 사용해서 취약한 코드를 안전한 코드로 자동 변환합니다.
"""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def main():
    """메인 함수"""
    print("FortiCode 시큐어 코드 자동 생성 시작")
    print("=" * 60)
    
    # 1. API 키 확인
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        print("OPENAI_API_KEY 환경변수가 설정되지 않았습니다.")
        return
    
    print("API 키 확인 완료")
    
    # 2. 기존 분석 결과 로드
    vulnbank_analysis_file = "../vulnbank_security_analysis.json"
    if not Path(vulnbank_analysis_file).exists():
        print(f"취약점 분석 결과 파일을 찾을 수 없습니다: {vulnbank_analysis_file}")
        return
    
    try:
        with open(vulnbank_analysis_file, 'r', encoding='utf-8') as f:
            analysis_result = json.load(f)
        print("기존 분석 결과 로드 완료")
    except Exception as e:
        print(f"분석 결과 로드 실패: {e}")
        return
    
    # 3. 시큐어 코드 생성
    print("시큐어 코드 생성 중...")
    
    secure_code_results = generate_secure_code(analysis_result, openai_key)
    
    # 4. 결과 저장
    output_file = "vulnbank_secure_code_generated.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(secure_code_results, f, indent=2, ensure_ascii=False)
    
    print(f"시큐어 코드 생성 결과 저장됨: {output_file}")
    
    # 5. 다음 단계 안내
    print("\n다음 단계:")
    print("1. 생성된 시큐어 코드 검토")
    print("2. 자동 패치 적용 (apply_patches.py 사용)")
    print("3. 보안 테스트 재실행")

def generate_secure_code(analysis_result: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """LLM을 사용해서 시큐어 코드 생성"""
    
    try:
        from openai import OpenAI
        
        client = OpenAI(api_key=api_key)
        
        findings = analysis_result.get('findings', [])
        secure_code_results = {
            'overview': 'VulnBank 프로젝트 시큐어 코드 자동 생성 결과',
            'total_findings': len(findings),
            'secure_code_patches': [],
            'summary': {
                'critical_fixed': 0,
                'high_fixed': 0,
                'medium_fixed': 0,
                'low_fixed': 0
            }
        }
        
        print(f"{len(findings)}개의 취약점에 대해 시큐어 코드 생성 중...")
        
        # 우선순위별로 처리 (Critical → High → Medium → Low)
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            severity_findings = [f for f in findings if f.get('severity') == severity]
            
            for i, finding in enumerate(severity_findings):
                title = finding.get('message', finding.get('title', '제목 없음'))
                print(f"  {severity.upper()} 취약점 {i+1}/{len(severity_findings)} 처리 중: {title}")
                
                try:
                    # LLM을 사용해서 시큐어 코드 생성
                    secure_code = generate_secure_code_for_finding(client, finding)
                    
                    if secure_code:
                        secure_code_results['secure_code_patches'].append(secure_code)
                        
                        # 통계 업데이트
                        if severity == 'critical':
                            secure_code_results['summary']['critical_fixed'] += 1
                        elif severity == 'high':
                            secure_code_results['summary']['high_fixed'] += 1
                        elif severity == 'medium':
                            secure_code_results['summary']['medium_fixed'] += 1
                        elif severity == 'low':
                            secure_code_results['summary']['low_fixed'] += 1
                    
                except Exception as e:
                    print(f"    오류 발생: {e}")
                    continue
        
        print(f"시큐어 코드 생성 완료: {len(secure_code_results['secure_code_patches'])}개 패치 생성")
        
        return secure_code_results
        
    except ImportError:
        print("OpenAI 라이브러리가 설치되지 않았습니다.")
        print("pip install openai 로 설치해주세요.")
        return {"error": "OpenAI library not installed"}
    except Exception as e:
        print(f"시큐어 코드 생성 중 오류: {e}")
        return {"error": str(e)}

def generate_secure_code_for_finding(client, finding: Dict[str, Any]) -> Dict[str, Any]:
    """개별 취약점에 대한 시큐어 코드 생성"""
    
    # 취약점 정보 추출
    title = finding.get('message', finding.get('title', '제목 없음'))
    evidence = finding.get('evidence', '')
    file_path = finding.get('file_path', '')
    line_number = finding.get('line_number', 0)
    cwe = finding.get('cwe', '')
    mitigation = finding.get('secure_coding_guide', finding.get('mitigation', ''))
    
    # 프롬프트 생성
    prompt = f"""
당신은 보안 전문가입니다. 다음 Python 코드의 보안 취약점을 수정해주세요.

**취약점 정보:**
- 제목: {title}
- CWE: {cwe}
- 파일: {file_path}
- 라인: {line_number}
- 취약한 코드: {evidence}
- 완화 방안: {mitigation}

**요구사항:**
1. 취약한 코드를 안전한 코드로 변환
2. Python 보안 모범 사례 적용
3. 구체적인 코드 예시 제공
4. 추가 보안 고려사항 설명

**출력 형식:**
```python
# 취약한 코드 (원본)
{evidence}

# 안전한 코드 (수정된 버전)
[여기에 안전한 코드를 작성하세요]

# 보안 개선 사항
[여기에 보안 개선 사항을 설명하세요]
```

위 형식으로 응답해주세요.
"""
    
    try:
        # OpenAI API 호출
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "당신은 Python 보안 전문가입니다. 보안 취약점을 안전한 코드로 변환하는 것이 전문입니다."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2000
        )
        
        # 응답 파싱
        secure_code_content = response.choices[0].message.content
        
        # 결과 구조화
        result = {
            'finding_id': finding.get('finding_id', 'unknown'),
            'cwe': cwe,
            'severity': finding.get('severity', 'unknown'),
            'file_path': file_path,
            'line_number': line_number,
            'original_vulnerability': {
                'title': title,
                'evidence': evidence,
                'mitigation': mitigation
            },
            'secure_code_patch': secure_code_content,
            'status': 'generated'
        }
        
        return result
        
    except Exception as e:
        print(f"    LLM 호출 실패: {e}")
        return None

if __name__ == "__main__":
    main()

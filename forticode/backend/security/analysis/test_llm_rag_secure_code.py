#!/usr/bin/env python3
"""
LLM+RAG를 사용하여 VulnBank 취약점을 분석하고 시큐어 코드를 생성하는 테스트 스크립트
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from vulnbank_security_workflow import VulnBankSecurityWorkflow
    print("VulnBank 보안 워크플로우 모듈을 성공적으로 임포트했습니다.")
except ImportError as e:
    print(f"모듈 임포트 오류: {e}")
    print("현재 디렉토리:", current_dir)
    print("Python 경로:", sys.path)
    sys.exit(1)

def load_vulnbank_analysis(analysis_path: str) -> Dict[str, Any]:
    """VulnBank 분석 결과 로드"""
    try:
        with open(analysis_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"분석 결과 로드 오류: {e}")
        return {}

def load_vulnbank_source_code(vulnbank_path: str) -> Dict[str, str]:
    """VulnBank 원본 소스 코드 로드"""
    source_codes = {}
    vulnbank_path = Path(vulnbank_path)
    
    for py_file in vulnbank_path.rglob("*.py"):
        if not any(part.startswith('.') for part in py_file.parts):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    relative_path = str(py_file.relative_to(vulnbank_path))
                    source_codes[relative_path] = f.read()
            except Exception as e:
                print(f"소스 코드 로드 오류 ({py_file}): {e}")
    
    return source_codes

def create_llm_rag_prompt(vulnerability: Dict[str, Any], source_code: str, analysis_context: str) -> str:
    """LLM+RAG를 위한 프롬프트 생성"""
    
    prompt = f"""
당신은 Python 보안 전문가입니다. 다음 취약점을 분석하고 안전한 코드를 생성해주세요.

## 취약점 정보
- CWE: {vulnerability.get('cwe', 'Unknown')}
- 심각도: {vulnerability.get('severity', 'Unknown')}
- 메시지: {vulnerability.get('message', 'Unknown')}
- 라인: {vulnerability.get('line_number', 'Unknown')}
- 매칭된 코드: {vulnerability.get('matched_code', 'Unknown')}

## 원본 소스 코드 컨텍스트
```python
{vulnerability.get('context', source_code[:500])}
```

## 보안 분석 컨텍스트
{analysis_context}

## 요구사항
1. 이 취약점의 구체적인 위험성을 설명하세요
2. 안전한 코드로 수정해주세요
3. 수정 사항에 대한 상세한 설명을 제공하세요
4. 추가 보안 모범 사례를 제안하세요

## 출력 형식
```python
# 취약한 코드
{vulnerability.get('matched_code', '')}

# 안전한 코드
[여기에 안전한 코드를 작성]

# 수정 사항 설명
[구체적인 수정 내용 설명]

# 추가 보안 모범 사례
[추가 권장사항]
```

실용적이고 프로덕션 환경에서 사용 가능한 코드를 작성해주세요.
"""
    
    return prompt

def test_llm_rag_secure_code_generation():
    """LLM+RAG를 사용한 시큐어 코드 생성 테스트"""
    
    print("LLM+RAG 시큐어 코드 생성 테스트 시작")
    print("=" * 60)
    
    # 경로 설정
    vulnbank_path = "/mnt/c/Users/amiab/vulnbank"
    analysis_path = f"{vulnbank_path}/security_workflow_results/vulnbank_workflow_analysis.json"
    
    # 파일 존재 확인
    if not Path(vulnbank_path).exists():
        print(f"오류: VulnBank 경로를 찾을 수 없습니다: {vulnbank_path}")
        return
    
    if not Path(analysis_path).exists():
        print(f"오류: 분석 결과 파일을 찾을 수 없습니다: {analysis_path}")
        return
    
    print(f"VulnBank 경로: {vulnbank_path}")
    print(f"분석 결과 경로: {analysis_path}")
    print()
    
    # 데이터 로드
    print("데이터 로드 중...")
    analysis_data = load_vulnbank_analysis(analysis_path)
    source_codes = load_vulnbank_source_code(vulnbank_path)
    
    if not analysis_data:
        print("분석 데이터를 로드할 수 없습니다.")
        return
    
    if not source_codes:
        print("소스 코드를 로드할 수 없습니다.")
        return
    
    print(f"로드된 파일 수: {len(source_codes)}")
    print()
    
    # 워크플로우 초기화
    try:
        print("VulnBank 보안 워크플로우 초기화 중...")
        workflow = VulnBankSecurityWorkflow()
        print("워크플로우 초기화 완료")
        print()
    except Exception as e:
        print(f"워크플로우 초기화 오류: {e}")
        return
    
    # 취약점별 LLM+RAG 분석
    findings = analysis_data.get("findings_details", [])
    
    if not findings:
        print("분석할 취약점이 없습니다.")
        return
    
    print(f"총 {len(findings)}개 취약점에 대해 LLM+RAG 분석 시작...")
    print()
    
    # 상위 3개 취약점만 테스트 (시간 절약)
    test_findings = findings[:3]
    
    for i, finding in enumerate(test_findings, 1):
        print(f"취약점 {i}/{len(test_findings)} 분석 중...")
        print(f"CWE: {finding.get('cwe', 'Unknown')}")
        print(f"심각도: {finding.get('severity', 'Unknown')}")
        print(f"파일: {finding.get('file_path', 'Unknown')}")
        print(f"라인: {finding.get('line_number', 'Unknown')}")
        
        # 해당 파일의 소스 코드 가져오기
        file_path = finding.get('file_path', '')
        if file_path in source_codes:
            source_code = source_codes[file_path]
        else:
            source_code = "소스 코드를 찾을 수 없습니다."
        
        # 분석 컨텍스트 생성
        analysis_context = f"""
발견된 취약점 패턴: {finding.get('pattern', 'Unknown')}
매칭된 코드: {finding.get('matched_code', 'Unknown')}
컨텍스트: {finding.get('context', 'Unknown')}
"""
        
        # LLM+RAG 프롬프트 생성
        prompt = create_llm_rag_prompt(finding, source_code, analysis_context)
        
        try:
            # LLM+RAG를 사용한 시큐어 코드 생성
            print("LLM+RAG를 사용한 시큐어 코드 생성 중...")
            
            # 실제 LLM 호출 (워크플로우의 메서드 사용)
            secure_code_result = workflow._generate_secure_code_for_finding(
                finding, 
                [{"cwe_id": finding.get('cwe'), "rag_results": [analysis_context]}]
            )
            
            if secure_code_result:
                print("시큐어 코드 생성 성공!")
                print("=" * 40)
                print("생성된 시큐어 코드:")
                print(secure_code_result.get('secure_code', '코드를 생성할 수 없습니다.'))
                print("=" * 40)
            else:
                print("시큐어 코드 생성 실패")
            
        except Exception as e:
            print(f"LLM+RAG 분석 오류: {e}")
        
        print("-" * 60)
        print()
    
    print("LLM+RAG 시큐어 코드 생성 테스트 완료")

def main():
    """메인 함수"""
    print("LLM+RAG 시큐어 코드 생성 테스트")
    print("=" * 50)
    
    try:
        test_llm_rag_secure_code_generation()
    except Exception as e:
        print(f"테스트 실행 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

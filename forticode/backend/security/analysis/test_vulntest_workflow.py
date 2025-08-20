#!/usr/bin/env python3
"""
VulnTest 워크플로우 테스트 스크립트
vulntest와 vulntest_analysis를 입력으로 받아 LLM+RAG로 안전한 코드 생성
"""

import os
import sys
import json
import logging
from pathlib import Path

# 상위 디렉토리를 Python 경로에 추가
sys.path.append(str(Path(__file__).parent.parent.parent))

from vulnbank_security_workflow import VulnBankSecurityWorkflow

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """메인 함수"""
    print("=== VulnTest 보안 워크플로우 테스트 ===")
    
    # 환경 변수에서 API 키 가져오기
    openai_api_key = os.getenv('OPENAI_API_KEY')
    anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
    
    if not openai_api_key and not anthropic_api_key:
        print("경고: OPENAI_API_KEY 또는 ANTHROPIC_API_KEY가 설정되지 않았습니다.")
        print("LLM 기능은 제한될 수 있습니다.")
    
    # 워크플로우 초기화
    workflow = VulnBankSecurityWorkflow(
        openai_api_key=openai_api_key,
        anthropic_api_key=anthropic_api_key
    )
    
    # 입력 경로 설정
    vulntest_path = input("vulntest 프로젝트 경로를 입력하세요: ").strip()
    vulntest_analysis_path = input("vulntest_analysis 결과 파일 경로를 입력하세요: ").strip()
    
    # 경로 유효성 검사
    if not os.path.exists(vulntest_path):
        print(f"오류: vulntest 경로가 존재하지 않습니다: {vulntest_path}")
        return
    
    if not os.path.exists(vulntest_analysis_path):
        print(f"오류: vulntest_analysis 파일이 존재하지 않습니다: {vulntest_analysis_path}")
        return
    
    print(f"\nvulntest 경로: {vulntest_path}")
    print(f"vulntest_analysis 경로: {vulntest_analysis_path}")
    print("\n분석을 시작합니다...")
    
    try:
        # VulnTest 분석 실행
        results = workflow.analyze_vulntest_with_analysis(
            vulntest_path=vulntest_path,
            vulntest_analysis_path=vulntest_analysis_path
        )
        
        # 결과 출력
        print("\n=== 분석 결과 ===")
        print(f"프로젝트 정보: {results.get('project_info', {})}")
        
        security_analysis = results.get('security_analysis', {})
        print(f"총 발견된 취약점: {security_analysis.get('total_findings', 0)}")
        print(f"보안 점수: {security_analysis.get('security_score', 0)}")
        print(f"위험 수준: {security_analysis.get('risk_level', 'UNKNOWN')}")
        
        # 심각도별 분포
        severity_dist = security_analysis.get('severity_distribution', {})
        print(f"심각도별 분포:")
        for severity, count in severity_dist.items():
            print(f"  {severity}: {count}")
        
        # CWE별 분포
        cwe_dist = security_analysis.get('cwe_distribution', {})
        if cwe_dist:
            print(f"CWE별 분포:")
            for cwe, count in cwe_dist.items():
                print(f"  {cwe}: {count}")
        
        # 안전한 코드 버전
        secure_code_versions = results.get('secure_code_versions', {})
        if secure_code_versions:
            print(f"\n생성된 안전한 코드 버전: {len(secure_code_versions)}개")
            
            # 파일별 안전한 버전
            secure_files = secure_code_versions.get('secure_files', {})
            for file_path, secure_file in secure_files.items():
                print(f"  {file_path}: {secure_file.get('vulnerabilities_fixed', 0)}개 취약점 수정")
        
        # 권장사항
        recommendations = results.get('recommendations', [])
        if recommendations:
            print(f"\n권장사항:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        # 다음 단계
        next_steps = results.get('next_steps', [])
        if next_steps:
            print(f"\n다음 단계:")
            for i, step in enumerate(next_steps, 1):
                print(f"  {i}. {step}")
        
        # 결과를 JSON 파일로 저장
        output_file = "vulntest_security_report.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n상세 결과가 {output_file}에 저장되었습니다.")
        
    except Exception as e:
        print(f"분석 중 오류가 발생했습니다: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

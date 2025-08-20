#!/usr/bin/env python3
"""
보안 코드 생성 메인 스크립트
vulnbank 프로젝트의 취약점을 분석하고 시큐어 코드를 생성합니다.
"""

import os
import sys
from pathlib import Path

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def main():
    """메인 함수"""
    print("🔒 FortiCode 보안 코드 생성 시작")
    print("=" * 60)
    
    # 1. API 키 확인
    openai_key = os.getenv('OPENAI_API_KEY')
    anthropic_key = os.getenv('ANTHROPIC_API_KEY')
    
    if not openai_key and not anthropic_key:
        print("❌ API 키가 설정되지 않았습니다.")
        print("다음 중 하나를 설정해주세요:")
        print("1. OPENAI_API_KEY 환경변수")
        print("2. ANTHROPIC_API_KEY 환경변수")
        print("\n예시:")
        print("export OPENAI_API_KEY='your_key_here'")
        print("또는")
        print("export ANTHROPIC_API_KEY='your_key_here'")
        return
    
    print("✅ API 키 확인 완료")
    
    # 2. 보안 워크플로우 실행
    try:
        from backend.security.analysis.integrated_security_workflow import WebSecurityWorkflow
        
        # 워크플로우 초기화
        workflow = WebSecurityWorkflow(
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key
        )
        
        print("✅ 보안 워크플로우 초기화 완료")
        
        # 3. vulnbank 프로젝트 분석
        vulnbank_path = "vulntest_total/vulnbank"
        if not Path(vulnbank_path).exists():
            print(f"❌ VulnBank 프로젝트를 찾을 수 없습니다: {vulnbank_path}")
            return
        
        print(f"🔍 VulnBank 프로젝트 분석 시작: {vulnbank_path}")
        
        # 프로젝트 분석 실행
        analysis_result = workflow.analyze_project_directory(
            project_path=vulnbank_path,
            include_dependencies=True
        )
        
        print("✅ 프로젝트 분석 완료")
        
        # 4. 결과 저장
        output_file = "vulnbank_security_analysis_with_patches.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            import json
            json.dump(analysis_result, f, indent=2, ensure_ascii=False)
        
        print(f"📁 분석 결과 저장됨: {output_file}")
        
        # 5. 다음 단계 안내
        print("\n🎯 다음 단계:")
        print("1. 생성된 패치 검토")
        print("2. 자동 패치 적용 (patch_applier.py 사용)")
        print("3. 보안 테스트 실행")
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

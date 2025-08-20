#!/usr/bin/env python3
"""
생성된 보안 패치를 자동으로 적용하는 스크립트
"""

import json
import os
import sys
from pathlib import Path

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def apply_security_patches():
    """보안 패치를 자동으로 적용"""
    print("🔧 보안 패치 자동 적용 시작")
    print("=" * 60)
    
    # 1. 분석 결과 파일 확인
    analysis_file = "vulnbank_security_analysis_with_patches.json"
    if not Path(analysis_file).exists():
        print(f"❌ 분석 결과 파일을 찾을 수 없습니다: {analysis_file}")
        print("먼저 generate_secure_code.py를 실행해주세요.")
        return
    
    # 2. 분석 결과 로드
    try:
        with open(analysis_file, 'r', encoding='utf-8') as f:
            analysis_result = json.load(f)
        print("✅ 분석 결과 로드 완료")
    except Exception as e:
        print(f"❌ 분석 결과 로드 실패: {e}")
        return
    
    # 3. 패치 적용기 초기화
    try:
        from backend.security.analysis.patch_applier import PatchApplier
        
        # GitHub 토큰 확인
        github_token = os.getenv('GITHUB_TOKEN')
        
        patch_applier = PatchApplier(
            repo_path="vulntest_total/vulnbank",
            github_token=github_token,
            auto_pr_threshold="HIGH"
        )
        print("✅ 패치 적용기 초기화 완료")
        
    except Exception as e:
        print(f"❌ 패치 적용기 초기화 실패: {e}")
        return
    
    # 4. 패치 적용
    if 'secure_coding_guide' in analysis_result and 'patches' in analysis_result['secure_coding_guide']:
        patches = analysis_result['secure_coding_guide']['patches']
        print(f"🔍 {len(patches)}개의 패치를 발견했습니다.")
        
        for i, patch in enumerate(patches, 1):
            print(f"\n📝 패치 {i}/{len(patches)} 적용 중...")
            print(f"   취약점: {patch.get('finding_id', 'Unknown')}")
            print(f"   설명: {patch.get('explanation', 'No description')}")
            
            try:
                # 패치 적용
                result = patch_applier.apply_patch(patch)
                
                if result['success']:
                    print(f"   ✅ 패치 적용 성공")
                    print(f"   브랜치: {result.get('branch_name', 'N/A')}")
                    if result.get('pr_created'):
                        print(f"   PR 생성됨: {result.get('pr_url', 'N/A')}")
                else:
                    print(f"   ❌ 패치 적용 실패: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"   ❌ 패치 적용 중 오류: {e}")
        
        print(f"\n🎯 패치 적용 완료: {len(patches)}개")
        
    else:
        print("⚠️  적용할 패치를 찾을 수 없습니다.")
        print("분석 결과에 패치 정보가 포함되어 있는지 확인해주세요.")
    
    # 5. 다음 단계 안내
    print("\n🎯 다음 단계:")
    print("1. 적용된 패치 검토")
    print("2. 보안 테스트 실행")
    print("3. 코드 품질 검사")

def main():
    """메인 함수"""
    apply_security_patches()

if __name__ == "__main__":
    main()

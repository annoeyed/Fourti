#!/usr/bin/env python3
"""
LLM+RAG 파이프라인 테스트 스크립트
vulnbank + vulnbank_analysis를 input으로 받아서 시큐어 코드 생성 테스트
"""

import json
import sys
from pathlib import Path

# 현재 디렉토리를 Python 경로에 추가
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_llm_rag_pipeline():
    """LLM+RAG 파이프라인 테스트"""
    
    print("LLM+RAG 파이프라인 테스트 시작")
    print("=" * 60)
    
    try:
        # 워크플로우 임포트 테스트
        print("1. 워크플로우 모듈 임포트 테스트...")
        from vulnbank_security_workflow import VulnBankSecurityWorkflow
        print("   ✅ 워크플로우 모듈 임포트 성공")
        
        # 워크플로우 초기화 테스트
        print("2. 워크플로우 초기화 테스트...")
        workflow = VulnBankSecurityWorkflow()
        print("   ✅ 워크플로우 초기화 성공")
        
        # RAG 시스템 테스트
        print("3. RAG 시스템 테스트...")
        try:
            rag_results = workflow.rag_builder.search("SQL injection prevention Python", top_k=3)
            print(f"   ✅ RAG 검색 성공: {len(rag_results)}개 결과")
        except Exception as e:
            print(f"   ❌ RAG 검색 실패: {e}")
        
        # LLM 시스템 테스트
        print("4. LLM 시스템 테스트...")
        try:
            # 간단한 프롬프트로 LLM 테스트
            test_prompt = "Python에서 SQL Injection을 방지하는 방법을 간단히 설명해주세요."
            print(f"   테스트 프롬프트: {test_prompt}")
            print("   ⚠️  LLM API 키가 설정되지 않아 실제 호출은 불가능합니다.")
        except Exception as e:
            print(f"   ❌ LLM 시스템 테스트 실패: {e}")
        
        # 전체 파이프라인 테스트
        print("5. 전체 파이프라인 테스트...")
        vulnbank_path = "/mnt/c/Users/amiab/vulnbank"
        
        if Path(vulnbank_path).exists():
            print(f"   VulnBank 프로젝트 경로: {vulnbank_path}")
            print("   전체 분석 파이프라인 실행 시도...")
            
            try:
                # 프로젝트 구조 분석만 먼저 테스트
                project_structure = workflow._analyze_vulnbank_structure(vulnbank_path)
                print(f"   ✅ 프로젝트 구조 분석 성공: {project_structure['total_files']}개 파일")
                
                # 패턴 스캔 테스트
                pattern_findings = workflow._scan_vulnbank_patterns(vulnbank_path)
                print(f"   ✅ 패턴 스캔 성공: {len(pattern_findings)}개 취약점 발견")
                
                print("   ⚠️  LLM+RAG 코드 생성은 API 키 설정 후 가능합니다.")
                
            except Exception as e:
                print(f"   ❌ 파이프라인 테스트 실패: {e}")
        else:
            print(f"   ❌ VulnBank 프로젝트를 찾을 수 없습니다: {vulnbank_path}")
        
        print("\n" + "=" * 60)
        print("LLM+RAG 파이프라인 테스트 완료")
        print("\n다음 단계:")
        print("1. OpenAI API 키 또는 Anthropic API 키 설정")
        print("2. 실제 LLM 호출 테스트")
        print("3. RAG + LLM을 통한 시큐어 코드 생성 테스트")
        
    except Exception as e:
        print(f"❌ 테스트 실행 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()

def main():
    """메인 함수"""
    test_llm_rag_pipeline()

if __name__ == "__main__":
    main()

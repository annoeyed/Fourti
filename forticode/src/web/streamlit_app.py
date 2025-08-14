"""
FortiCode Streamlit 웹 인터페이스
사용자 친화적인 보안 코드 분석 및 생성 웹 애플리케이션
"""

import streamlit as st
import requests
import json
import os
from typing import Dict, Any, List
import time

# 페이지 설정
st.set_page_config(
    page_title="FortiCode - 보안 코드 분석기",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 환경 변수
API_BASE_URL = os.getenv("FORTICODE_API_URL", "http://localhost:8000")

# 세션 상태 초기화
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'generation_history' not in st.session_state:
    st.session_state.generation_history = []

def check_api_health() -> bool:
    """API 서버 상태 확인"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def analyze_code(code: str, language: str, context: str) -> Dict[str, Any]:
    """코드 보안 분석 API 호출"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/analyze",
            json={
                "code": code,
                "language": language,
                "context": context
            },
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API 호출 실패: {str(e)}")
        return None

def generate_secure_code(description: str, language: str, security_requirements: List[str]) -> Dict[str, Any]:
    """보안 코드 생성 API 호출"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/generate",
            json={
                "description": description,
                "language": language,
                "security_requirements": security_requirements
            },
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API 호출 실패: {str(e)}")
        return None

def fix_security_issues(code: str, language: str, cwe_ids: List[str]) -> Dict[str, Any]:
    """보안 취약점 수정 API 호출"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/fix",
            json={
                "code": code,
                "language": language,
                "cwe_ids": cwe_ids
            },
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API 호출 실패: {str(e)}")
        return None

def get_cwe_info(cwe_id: str) -> Dict[str, Any]:
    """CWE 정보 조회 API 호출"""
    try:
        response = requests.get(f"{API_BASE_URL}/cwe/{cwe_id}", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"CWE 정보 조회 실패: {str(e)}")
        return None

def main():
    """메인 애플리케이션"""
    
    # 헤더
    st.title("🔒 FortiCode - LLM 기반 보안 코드 분석기")
    st.markdown("**개발 속도를 저해하지 않으면서 코드의 보안성을 근본적으로 강화하는 솔루션**")
    
    # 사이드바
    with st.sidebar:
        st.header("🔧 설정")
        
        # API 상태 확인
        api_healthy = check_api_health()
        if api_healthy:
            st.success("✅ API 서버 연결됨")
        else:
            st.error("❌ API 서버 연결 실패")
            st.info("API 서버가 실행 중인지 확인해주세요.")
        
        st.markdown("---")
        
        # 언어 선택
        language = st.selectbox(
            "프로그래밍 언어",
            ["python", "javascript", "java", "csharp", "php", "go", "rust"],
            index=0
        )
        
        # 보안 요구사항
        st.subheader("보안 요구사항")
        security_requirements = st.multiselect(
            "적용할 보안 원칙",
            [
                "OWASP Top 10 준수",
                "입력 검증 강화",
                "출력 인코딩",
                "인증 및 권한 관리",
                "데이터 암호화",
                "안전한 라이브러리 사용",
                "에러 처리 및 로깅"
            ],
            default=["OWASP Top 10 준수"]
        )
    
    # 메인 컨텐츠
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 코드 분석", 
        "⚡ 코드 생성", 
        "🛠️ 취약점 수정",
        "📚 CWE 데이터베이스"
    ])
    
    # 탭 1: 코드 분석
    with tab1:
        st.header("🔍 코드 보안 분석")
        st.markdown("기존 코드의 보안 취약점을 LLM을 통해 분석합니다.")
        
        # 코드 입력
        code_input = st.text_area(
            "분석할 코드를 입력하세요",
            height=300,
            placeholder=f"여기에 {language} 코드를 입력하세요..."
        )
        
        context_input = st.text_input(
            "컨텍스트 (선택사항)",
            placeholder="예: 웹 애플리케이션, API 서버, 데스크톱 앱 등"
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            analyze_button = st.button("🔍 분석 시작", type="primary")
        
        with col2:
            if analyze_button and code_input.strip():
                with st.spinner("코드를 분석하고 있습니다..."):
                    result = analyze_code(code_input, language, context_input or "")
                    
                    if result:
                        # 분석 결과 저장
                        analysis_record = {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "language": language,
                            "code": code_input[:100] + "..." if len(code_input) > 100 else code_input,
                            "result": result
                        }
                        st.session_state.analysis_history.append(analysis_record)
                        
                        # 결과 표시
                        st.success("✅ 분석 완료!")
                        
                        # 전체 보안 점수
                        col_score1, col_score2, col_score3 = st.columns(3)
                        with col_score1:
                            st.metric("보안 점수", f"{result['overall_score']:.1f}/10.0")
                        with col_score2:
                            st.metric("위험 수준", result['risk_level'].upper())
                        with col_score3:
                            st.metric("발견된 이슈", result['issues_count'])
                        
                        # 보안 이슈 상세
                        if result['issues']:
                            st.subheader("🚨 발견된 보안 이슈")
                            
                            for i, issue in enumerate(result['issues']):
                                with st.expander(f"{issue['cwe_id']}: {issue['description']}"):
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.write(f"**심각도**: {issue['severity'].upper()}")
                                        st.write(f"**위험도 점수**: {issue['risk_score']}/10.0")
                                        st.write(f"**신뢰도**: {issue['confidence']:.1%}")
                                    with col2:
                                        st.write(f"**코드 위치**: {issue['line_number'] or 'Unknown'}")
                                        st.write(f"**코드 스니펫**: `{issue['code_snippet']}`")
                                    
                                    st.write("**수정 방안**:")
                                    st.info(issue['mitigation'])
                        
                        # 권장사항
                        if result['recommendations']:
                            st.subheader("💡 권장사항")
                            for rec in result['recommendations']:
                                st.write(f"• {rec}")
                        
                        # CWE 요약
                        if result['cwe_summary']:
                            st.subheader("📊 CWE 분포")
                            cwe_data = []
                            for cwe_id, count in result['cwe_summary'].items():
                                cwe_info = get_cwe_info(cwe_id)
                                if cwe_info:
                                    cwe_data.append({
                                        "CWE ID": cwe_id,
                                        "이름": cwe_info['name'],
                                        "발생 횟수": count,
                                        "위험도": cwe_info['risk_score']
                                    })
                            
                            if cwe_data:
                                st.dataframe(cwe_data, use_container_width=True)
        
        # 분석 히스토리
        if st.session_state.analysis_history:
            st.subheader("📋 분석 히스토리")
            for record in reversed(st.session_state.analysis_history[-5:]):
                with st.expander(f"{record['timestamp']} - {record['language']} 코드 분석"):
                    st.code(record['code'], language=record['language'])
                    st.write(f"**보안 점수**: {record['result']['overall_score']:.1f}/10.0")
                    st.write(f"**위험 수준**: {record['result']['risk_level']}")
                    st.write(f"**발견된 이슈**: {record['result']['issues_count']}개")
    
    # 탭 2: 코드 생성
    with tab2:
        st.header("⚡ 보안 코드 생성")
        st.markdown("보안 요구사항을 포함한 안전한 코드를 자동으로 생성합니다.")
        
        # 요구사항 입력
        description = st.text_area(
            "코드 요구사항을 자세히 설명하세요",
            height=150,
            placeholder="예: Flask를 사용하여 사용자 로그인 API를 구현하고, JWT 토큰을 사용하여 인증을 처리합니다."
        )
        
        # 언어 선택 (탭별)
        gen_language = st.selectbox(
            "생성할 언어",
            ["python", "javascript", "java", "csharp", "php", "go", "rust"],
            index=0,
            key="gen_language"
        )
        
        # 보안 요구사항 선택 (탭별)
        gen_security_reqs = st.multiselect(
            "적용할 보안 원칙",
            [
                "OWASP Top 10 준수",
                "입력 검증 강화",
                "출력 인코딩",
                "인증 및 권한 관리",
                "데이터 암호화",
                "안전한 라이브러리 사용",
                "에러 처리 및 로깅"
            ],
            default=["OWASP Top 10 준수"],
            key="gen_security"
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            generate_button = st.button("⚡ 코드 생성", type="primary")
        
        with col2:
            if generate_button and description.strip():
                with st.spinner("보안 코드를 생성하고 있습니다..."):
                    result = generate_secure_code(description, gen_language, gen_security_reqs)
                    
                    if result:
                        # 생성 결과 저장
                        generation_record = {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "language": gen_language,
                            "description": description[:100] + "..." if len(description) > 100 else description,
                            "result": result
                        }
                        st.session_state.generation_history.append(generation_record)
                        
                        st.success("✅ 코드 생성 완료!")
                        
                        # 생성된 코드 표시
                        st.subheader("📝 생성된 코드")
                        st.code(result['generated_code'], language=gen_language)
                        
                        # 보안 컨텍스트
                        st.subheader("🔒 적용된 보안 원칙")
                        st.write(result['security_context'])
                        
                        # 코드 다운로드
                        st.download_button(
                            label="📥 코드 다운로드",
                            data=result['generated_code'],
                            file_name=f"secure_code.{gen_language}",
                            mime="text/plain"
                        )
        
        # 생성 히스토리
        if st.session_state.generation_history:
            st.subheader("📋 생성 히스토리")
            for record in reversed(st.session_state.generation_history[-5:]):
                with st.expander(f"{record['timestamp']} - {record['language']} 코드 생성"):
                    st.write(f"**요구사항**: {record['description']}")
                    st.write(f"**언어**: {record['language']}")
                    st.code(record['result']['generated_code'][:200] + "...", language=record['language'])
    
    # 탭 3: 취약점 수정
    with tab3:
        st.header("🛠️ 보안 취약점 자동 수정")
        st.markdown("기존 코드의 보안 취약점을 자동으로 수정합니다.")
        
        # 수정할 코드 입력
        fix_code_input = st.text_area(
            "수정할 코드를 입력하세요",
            height=300,
            placeholder=f"여기에 {language} 코드를 입력하세요..."
        )
        
        # 수정할 CWE 선택
        cwe_to_fix = st.multiselect(
            "수정할 보안 이슈 (CWE)",
            ["CWE-79", "CWE-89", "CWE-200", "CWE-22", "CWE-78", "CWE-434", "CWE-287", "CWE-311"],
            help="수정하고 싶은 특정 보안 이슈를 선택하세요. 비워두면 모든 발견된 이슈를 수정합니다."
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            fix_button = st.button("🛠️ 수정 시작", type="primary")
        
        with col2:
            if fix_button and fix_code_input.strip():
                with st.spinner("보안 취약점을 수정하고 있습니다..."):
                    result = fix_security_issues(fix_code_input, language, cwe_to_fix)
                    
                    if result:
                        st.success("✅ 수정 완료!")
                        
                        # 원본 코드와 수정된 코드 비교
                        col1, col2 = st.columns(2)
                        with col1:
                            st.subheader("📝 원본 코드")
                            st.code(result['original_code'], language=language)
                        
                        with col2:
                            st.subheader("✅ 수정된 코드")
                            st.code(result['fixed_code'], language=language)
                        
                        # 수정된 이슈 정보
                        st.subheader("🔧 수정된 보안 이슈")
                        for cwe_id in result['fixed_issues']:
                            cwe_info = get_cwe_info(cwe_id)
                            if cwe_info:
                                st.write(f"**{cwe_id}**: {cwe_info['name']}")
                        
                        # 분석 결과 요약
                        analysis_summary = result['analysis_result']
                        st.subheader("📊 수정 전 분석 결과")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("보안 점수", f"{analysis_summary['overall_score']:.1f}/10.0")
                        with col2:
                            st.metric("발견된 이슈", analysis_summary['issues_count'])
                        
                        # 수정된 코드 다운로드
                        st.download_button(
                            label="📥 수정된 코드 다운로드",
                            data=result['fixed_code'],
                            file_name=f"fixed_code.{language}",
                            mime="text/plain"
                        )
    
    # 탭 4: CWE 데이터베이스
    with tab4:
        st.header("📚 CWE (Common Weakness Enumeration) 데이터베이스")
        st.markdown("보안 취약점 분류 및 상세 정보를 조회할 수 있습니다.")
        
        # CWE 검색
        search_query = st.text_input("CWE 검색", placeholder="예: injection, xss, sql 등")
        
        col1, col2 = st.columns([1, 4])
        with col1:
            search_button = st.button("🔍 검색", type="primary")
        
        with col2:
            if search_button and search_query.strip():
                with st.spinner("CWE를 검색하고 있습니다..."):
                    try:
                        response = requests.get(f"{API_BASE_URL}/cwe/search/{search_query}")
                        if response.status_code == 200:
                            search_results = response.json()
                            
                            st.success(f"✅ {search_results['results_count']}개의 CWE를 찾았습니다.")
                            
                            # 검색 결과 표시
                            for result in search_results['results']:
                                with st.expander(f"{result['id']}: {result['name']}"):
                                    st.write(f"**설명**: {result['description']}")
                                    st.write(f"**위험도 점수**: {result['risk_score']}/10.0")
                                    
                                    # 상세 정보 조회
                                    if st.button(f"{result['id']} 상세 정보", key=f"detail_{result['id']}"):
                                        cwe_detail = get_cwe_info(result['id'])
                                        if cwe_detail:
                                            st.write("**상세 정보**")
                                            st.write(f"**가능성**: {cwe_detail['likelihood']}")
                                            st.write(f"**심각도**: {cwe_detail['severity']}")
                                            
                                            st.write("**예시**")
                                            for example in cwe_detail['examples']:
                                                st.write(f"• {example}")
                                            
                                            st.write("**수정 방안**")
                                            for mitigation in cwe_detail['mitigations']:
                                                st.write(f"• {mitigation}")
                        
                    except Exception as e:
                        st.error(f"검색 중 오류가 발생했습니다: {str(e)}")
        
        # 모든 CWE 목록
        if st.button("📋 모든 CWE 목록 보기"):
            with st.spinner("CWE 목록을 불러오고 있습니다..."):
                try:
                    response = requests.get(f"{API_BASE_URL}/cwe/list")
                    if response.status_code == 200:
                        cwe_list = response.json()
                        
                        st.success(f"✅ 총 {cwe_list['total_count']}개의 CWE가 있습니다.")
                        
                        # CWE 목록을 데이터프레임으로 표시
                        import pandas as pd
                        df = pd.DataFrame(cwe_list['cwe_list'])
                        st.dataframe(df, use_container_width=True)
                        
                except Exception as e:
                    st.error(f"CWE 목록을 불러오는 중 오류가 발생했습니다: {str(e)}")

if __name__ == "__main__":
    main()

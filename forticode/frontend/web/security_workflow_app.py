"""
통합 보안 워크플로우 Streamlit 앱
사용자가 코드를 입력하면 SAST/DAST 분석 → RAG 검색 → LLM 패치 생성 → 시큐어 코딩 가이드 제공
"""

import streamlit as st
import sys
import os
from pathlib import Path
import json
import time

# 상위 디렉토리 추가
sys.path.append(str(Path(__file__).parent.parent.parent / "backend"))

try:
    from security.analysis.integrated_security_workflow import IntegratedSecurityWorkflow
    from security.analysis.sast_dast_schema import Language
except ImportError as e:
    st.error(f"모듈 import 오류: {e}")
    st.stop()

# 페이지 설정
st.set_page_config(
    page_title="FortiCode 보안 워크플로우",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 사이드바 설정
st.sidebar.title("🔒 FortiCode 보안 워크플로우")
st.sidebar.markdown("""
### 사용법
1. 프로그래밍 언어 선택
2. 코드 입력 또는 파일 업로드
3. 보안 분석 실행
4. 결과 및 패치 확인
5. 시큐어 코딩 가이드 학습
""")

# 메인 타이틀
st.title("🔒 FortiCode 통합 보안 코딩 워크플로우")
st.markdown("""
**사용자 코드 → SAST/DAST 분석 → RAG 검색 → LLM 패치 생성 → 시큐어 코딩 가이드**

보안 취약점을 자동으로 탐지하고, AI 기반 패치를 생성하며, 시큐어 코딩 모범 사례를 제공합니다.
""")

# 언어 선택
languages = {
    "python": "Python",
    "java": "Java", 
    "cpp": "C++",
    "c": "C",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "php": "PHP",
    "ruby": "Ruby",
    "go": "Go",
    "rust": "Rust"
}

selected_language = st.sidebar.selectbox(
    "프로그래밍 언어 선택",
    options=list(languages.keys()),
    format_func=lambda x: languages[x],
    index=0
)

# API 키 설정
st.sidebar.markdown("---")
st.sidebar.markdown("### API 키 설정 (선택사항)")
openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password", help="LLM 기능을 위해 필요")
anthropic_api_key = st.sidebar.text_input("Anthropic API Key", type="password", help="LLM 기능을 위해 필요")

# 코드 입력 방법 선택
input_method = st.radio(
    "코드 입력 방법",
    ["직접 입력", "파일 업로드", "샘플 코드 선택"],
    horizontal=True
)

# 코드 입력
code_content = ""
file_name = "user_code.py"

if input_method == "직접 입력":
    st.markdown("### 📝 코드 입력")
    code_content = st.text_area(
        "코드를 입력하세요:",
        height=400,
        placeholder=f"여기에 {languages[selected_language]} 코드를 입력하세요..."
    )
    
elif input_method == "파일 업로드":
    st.markdown("### 📁 파일 업로드")
    uploaded_file = st.file_uploader(
        "코드 파일을 업로드하세요",
        type=['py', 'java', 'cpp', 'c', 'js', 'ts', 'php', 'rb', 'go', 'rs', 'txt'],
        help="지원되는 프로그래밍 언어 파일을 업로드하세요"
    )
    
    if uploaded_file is not None:
        code_content = uploaded_file.getvalue().decode("utf-8")
        file_name = uploaded_file.name
        st.success(f"파일 '{file_name}' 업로드 완료!")
        
elif input_method == "샘플 코드 선택":
    st.markdown("### 📚 샘플 코드 선택")
    
    sample_codes = {
        "sql_injection": {
            "name": "SQL Injection 취약점",
            "description": "사용자 입력을 직접 SQL 쿼리에 삽입하는 취약한 코드",
            "code": '''import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 취약한 코드: 사용자 입력을 직접 쿼리에 삽입
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 취약한 코드: SQL Injection 가능
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result is not None'''
        },
        "xss_vulnerability": {
            "name": "XSS 취약점",
            "description": "사용자 입력을 HTML에 직접 삽입하는 취약한 코드",
            "code": '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 취약한 코드: 사용자 입력을 직접 HTML에 삽입
    template = f'''
    <html>
        <head><title>검색 결과</title></head>
        <body>
            <h1>검색 결과: {query}</h1>
            <p>검색어 "{query}"에 대한 결과입니다.</p>
        </body>
    </html>
    '''
    
    return render_template_string(template)'''
        },
        "file_upload_vulnerability": {
            "name": "파일 업로드 취약점",
            "description": "파일 검증 없이 업로드를 허용하는 취약한 코드",
            "code": '''import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return '파일이 없습니다', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return '파일명이 없습니다', 400
    
    # 취약한 코드: 파일 확장자 검증 없음
    filename = file.filename
    file_path = os.path.join('/uploads', filename)
    
    # 취약한 코드: 경로 검증 없음
    file.save(file_path)
    
    return f'파일 {filename}이 업로드되었습니다' '''
        }
    }
    
    selected_sample = st.selectbox(
        "샘플 코드 선택:",
        options=list(sample_codes.keys()),
        format_func=lambda x: sample_codes[x]["name"]
    )
    
    if selected_sample:
        sample = sample_codes[selected_sample]
        st.markdown(f"**{sample['name']}**")
        st.markdown(f"*{sample['description']}*")
        code_content = sample['code']
        file_name = f"sample_{selected_sample}.py"

# 분석 실행 버튼
if code_content.strip():
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyze_button = st.button(
            "🔍 보안 분석 실행",
            type="primary",
            use_container_width=True
        )
    
    if analyze_button:
        # 진행 상황 표시
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # 1단계: 워크플로우 초기화
            status_text.text("1/6: 보안 워크플로우 초기화 중...")
            progress_bar.progress(16)
            
            workflow = IntegratedSecurityWorkflow(
                openai_api_key=openai_api_key if openai_api_key else None,
                anthropic_api_key=anthropic_api_key if anthropic_api_key else None
            )
            
            # 2단계: SAST 분석
            status_text.text("2/6: SAST 정적 분석 실행 중...")
            progress_bar.progress(33)
            time.sleep(1)
            
            # 3단계: LLM 보안 분석
            status_text.text("3/6: LLM 보안 분석 실행 중...")
            progress_bar.progress(50)
            time.sleep(1)
            
            # 4단계: RAG 검색
            status_text.text("4/6: RAG 검색으로 보안 컨텍스트 수집 중...")
            progress_bar.progress(66)
            time.sleep(1)
            
            # 5단계: 패치 생성
            status_text.text("5/6: 보안 패치 생성 중...")
            progress_bar.progress(83)
            time.sleep(1)
            
            # 6단계: 최종 분석
            status_text.text("6/6: 통합 리포트 생성 중...")
            progress_bar.progress(100)
            
            # 실제 분석 실행
            result = workflow.analyze_user_code(
                code_content=code_content,
                language=selected_language,
                file_name=file_name
            )
            
            status_text.text("✅ 분석 완료!")
            time.sleep(1)
            
            # 결과 표시
            display_analysis_results(result)
            
        except Exception as e:
            st.error(f"분석 중 오류가 발생했습니다: {str(e)}")
            st.exception(e)

def display_analysis_results(result):
    """분석 결과를 보기 좋게 표시"""
    
    # 요약 정보
    st.markdown("## 📊 보안 분석 요약")
    
    summary = result.get('summary', {})
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "보안 점수", 
            f"{summary.get('security_score', 0):.1f}/100",
            delta=f"{summary.get('security_score', 0) - 50:.1f}"
        )
    
    with col2:
        risk_level = summary.get('risk_level', 'UNKNOWN')
        risk_color = {
            'LOW': '🟢',
            'MEDIUM': '🟡', 
            'HIGH': '🔴',
            'CRITICAL': '🚨'
        }.get(risk_level, '⚪')
        st.metric("위험 수준", f"{risk_color} {risk_level}")
    
    with col3:
        st.metric("총 발견사항", summary.get('total_findings', 0))
    
    with col4:
        critical_count = summary.get('critical_count', 0)
        st.metric("Critical", critical_count, delta=-critical_count if critical_count > 0 else 0)
    
    # 취약점 상세
    st.markdown("## 🔍 발견된 취약점")
    
    findings = result.get('findings', {})
    
    # Critical & High 우선 표시
    for severity in ['critical', 'high']:
        if findings.get(severity):
            severity_emoji = {'critical': '🚨', 'high': '🔴'}[severity]
            st.markdown(f"### {severity_emoji} {severity.upper()}")
            
            for finding in findings[severity]:
                with st.expander(f"{finding.get('cwe', 'N/A')}: {finding.get('message', 'N/A')}"):
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        st.markdown(f"**파일:** {finding.get('file_path', 'N/A')}")
                        st.markdown(f"**라인:** {finding.get('line_number', 'N/A')}")
                        st.markdown(f"**도구:** {finding.get('source', 'N/A')}")
                    
                    with col2:
                        st.markdown(f"**증거:**")
                        st.code(finding.get('evidence', 'N/A'), language=selected_language)
    
    # Medium & Low
    for severity in ['medium', 'low']:
        if findings.get(severity):
            severity_emoji = {'medium': '🟡', 'low': '🟢'}[severity]
            st.markdown(f"### {severity_emoji} {severity.upper()}")
            
            for finding in findings[severity]:
                st.markdown(f"- **{finding.get('cwe', 'N/A')}**: {finding.get('message', 'N/A')}")
    
    # 보안 패치
    patches = result.get('security_patches', [])
    if patches:
        st.markdown("## 🔧 생성된 보안 패치")
        
        for i, patch in enumerate(patches):
            finding = patch.get('finding', {})
            patch_data = patch.get('patch', {})
            
            with st.expander(f"패치 {i+1}: {finding.get('cwe', 'N/A')} - {finding.get('message', 'N/A')}"):
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    st.markdown("**취약한 코드:**")
                    st.code(finding.get('evidence', 'N/A'), language=selected_language)
                
                with col2:
                    st.markdown("**수정된 코드:**")
                    if 'patched_code' in patch_data:
                        st.code(patch_data['patched_code'], language=selected_language)
                    else:
                        st.info("패치 코드가 생성되지 않았습니다.")
                
                if 'explanation' in patch_data:
                    st.markdown("**수정 설명:**")
                    st.info(patch_data['explanation'])
    
    # 권장사항
    recommendations = result.get('recommendations', [])
    if recommendations:
        st.markdown("## 💡 보안 개선 권장사항")
        
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")
    
    # 다음 단계
    next_steps = result.get('next_steps', [])
    if next_steps:
        st.markdown("## 📋 다음 단계")
        
        for i, step in enumerate(next_steps, 1):
            st.markdown(f"{i}. {step}")
    
    # 시큐어 코딩 가이드
    secure_coding_guide = result.get('secure_coding_guide', {})
    if secure_coding_guide and 'error' not in secure_coding_guide:
        st.markdown("## 📚 시큐어 코딩 가이드")
        
        with st.expander("시큐어 코딩 모범 사례"):
            if 'principles' in secure_coding_guide:
                st.markdown("### 핵심 원칙")
                for principle in secure_coding_guide['principles']:
                    st.markdown(f"- {principle}")
            
            if 'best_practices' in secure_coding_guide:
                st.markdown("### 모범 사례")
                for practice in secure_coding_guide['best_practices']:
                    st.markdown(f"**{practice.get('source', 'N/A')}**")
                    st.markdown(f"*{practice.get('practice', 'N/A')}*")
                    st.markdown("---")

# 푸터
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🔒 FortiCode - AI 기반 보안 코딩 워크플로우</p>
    <p>SAST/DAST + RAG + LLM을 통한 종합적인 보안 분석 및 패치 생성</p>
</div>
""", unsafe_allow_html=True)

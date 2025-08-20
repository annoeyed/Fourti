# FortiCode - AI 기반 보안 코딩 워크플로우

FortiCode는 사용자 코드를 입력받아 SAST/DAST 분석, RAG 검색, LLM 패치 생성, 시큐어 코딩 가이드를 제공하는 통합 보안 코딩 시스템입니다.

## 🚀 주요 기능

### 1. 통합 보안 워크플로우
- **사용자 코드 입력** → **SAST/DAST 분석** → **RAG 검색** → **LLM 패치 생성** → **시큐어 코딩 가이드**
- 다양한 프로그래밍 언어 지원 (Python, Java, C++, JavaScript, PHP, Ruby, Go, Rust 등)
- 코드 직접 입력, 파일 업로드, 샘플 코드 선택 지원

### 2. 자동 보안 분석
- **SAST (정적 분석)**: Bandit, SpotBugs, cppcheck 등 도구 연동
- **DAST (동적 분석)**: ZAP 등 웹 보안 도구 연동
- **LLM 보안 분석**: AI 기반 추가 취약점 탐지
- **CWE 매핑**: 자동으로 CWE ID와 보안 정보 연결

### 3. AI 기반 패치 생성
- **RAG 검색**: CWE 데이터베이스와 OWASP 치트시트에서 관련 정보 수집
- **LLM 패치 생성**: 발견된 취약점에 대한 구체적인 수정 코드 생성
- **패치 검증**: 생성된 패치의 유효성 검증

### 4. 시큐어 코딩 가이드
- **모범 사례**: OWASP Top 10, CWE/SANS Top 25 기반
- **언어별 가이드**: 프로그래밍 언어별 특화된 보안 권장사항
- **학습 자료**: 추가 보안 교육 자료 제공

## 🏗️ 시스템 아키텍처

```
사용자 코드 입력
        ↓
   SAST/DAST 분석
        ↓
   LLM 보안 분석
        ↓
   RAG 컨텍스트 수집
        ↓
   보안 패치 생성
        ↓
   시큐어 코딩 가이드
        ↓
   통합 리포트 생성
```

## 📁 프로젝트 구조

```
forticode/
├── backend/
│   ├── security/analysis/
│   │   ├── integrated_security_workflow.py  # 🆕 통합 워크플로우
│   │   ├── test_integrated_workflow.py      # 🆕 워크플로우 테스트
│   │   ├── sast_dast_parsers.py            # SAST/DAST 파서
│   │   ├── sast_dast_schema.py             # 통합 스키마
│   │   ├── llm_security_analyzer.py        # LLM 보안 분석기
│   │   └── patch_applier.py                # 패치 적용기
│   ├── rag/
│   │   ├── rag_builder.py                  # RAG 시스템
│   │   └── cwe_seeds/                      # CWE 데이터
│   ├── llm/
│   │   └── patch_generator.py              # 패치 생성기
│   └── api/
│       └── main.py                         # API 서버
├── frontend/web/
│   ├── security_workflow_app.py            # 🆕 웹 인터페이스
│   └── streamlit_app.py                    # 기존 앱
└── README.md
```

## 🚀 빠른 시작

### 1. 환경 설정
```bash
# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

### 2. 환경 변수 설정
```bash
export OPENAI_API_KEY="your_openai_api_key"
export ANTHROPIC_API_KEY="your_anthropic_api_key"
```

### 3. 웹 애플리케이션 실행
```bash
cd frontend/web
streamlit run security_workflow_app.py
```

### 4. 백엔드 테스트
```bash
cd backend/security/analysis
python test_integrated_workflow.py
```

## 💻 사용 예시

### Python 코드 보안 분석
```python
from security.analysis.integrated_security_workflow import IntegratedSecurityWorkflow

# 워크플로우 초기화
workflow = IntegratedSecurityWorkflow(
    openai_api_key="your_key",
    anthropic_api_key="your_key"
)

# 사용자 코드 분석
vulnerable_code = '''
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
'''

result = workflow.analyze_user_code(
    code_content=vulnerable_code,
    language="python",
    file_name="user_code.py"
)

# 결과 확인
print(f"보안 점수: {result['summary']['security_score']}/100")
print(f"발견된 취약점: {result['summary']['total_findings']}개")
```

## 🔧 지원하는 보안 도구

### SAST (정적 분석)
- **Python**: Bandit
- **Java**: SpotBugs, PMD
- **C/C++**: cppcheck, Clang Static Analyzer
- **JavaScript**: ESLint Security Plugin
- **PHP**: PHP Security Checker

### DAST (동적 분석)
- **웹 애플리케이션**: OWASP ZAP, Burp Suite
- **API**: Postman Security Testing
- **모바일**: MobSF

### 추가 도구
- **SCA**: Dependency Check, Snyk
- **IAST**: Contrast, Hdiv

## 📊 보안 점수 시스템

- **0-39**: CRITICAL (즉시 수정 필요)
- **40-59**: HIGH (우선 수정 필요)
- **60-79**: MEDIUM (계획적 수정)
- **80-100**: LOW (정기 점검)

## 🎯 주요 취약점 탐지

### OWASP Top 10
1. **Injection** (SQL, NoSQL, OS Command)
2. **Broken Authentication**
3. **Sensitive Data Exposure**
4. **XML External Entities (XXE)**
5. **Broken Access Control**
6. **Security Misconfiguration**
7. **Cross-Site Scripting (XSS)**
8. **Insecure Deserialization**
9. **Using Components with Known Vulnerabilities**
10. **Insufficient Logging & Monitoring**

### CWE/SANS Top 25
- **CWE-79**: Cross-site Scripting
- **CWE-89**: SQL Injection
- **CWE-200**: Information Exposure
- **CWE-22**: Path Traversal
- **CWE-78**: OS Command Injection

## 🔒 보안 기능

- **입력 검증**: 사용자 입력의 안전성 검증
- **출력 인코딩**: XSS 방지를 위한 출력 이스케이핑
- **인증/권한**: 강력한 인증 및 권한 관리
- **암호화**: 민감한 데이터 암호화
- **에러 처리**: 정보 노출을 방지하는 안전한 에러 처리
- **로깅**: 보안 이벤트 추적 및 모니터링

## 📚 학습 자료

- **OWASP Cheat Sheet Series**: 실용적인 보안 가이드
- **CWE Database**: 취약점 분류 및 설명
- **SANS Top 25**: 가장 위험한 소프트웨어 취약점
- **NIST Cybersecurity Framework**: 보안 표준 및 모범 사례

## 🤝 기여하기

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 📞 지원

- **이슈 리포트**: GitHub Issues
- **문서**: 프로젝트 Wiki
- **커뮤니티**: GitHub Discussions

---

**FortiCode** - AI 기반 보안 코딩으로 더 안전한 소프트웨어를 만들어갑니다! 🔒✨ 

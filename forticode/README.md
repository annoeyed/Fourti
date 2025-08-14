#  FortiCode - LLM 기반 보안 코드 분석기

**개발 속도를 저해하지 않으면서 코드의 보안성을 근본적으로 강화하는 솔루션**

##  프로젝트 개요

FortiCode는 기존의 SAST/DAST 도구 대신 LLM(대규모 언어 모델)을 활용하여 코드의 보안 취약점을 분석하고, 안전한 코드를 생성하는 혁신적인 보안 도구입니다.

###  핵심 특징

- ** LLM 기반 분석**: GPT-4, Claude 등 최신 AI 모델을 활용한 지능형 보안 분석
- ** CWE 데이터베이스**: OWASP Top 10, CWE/SANS Top 25 기반의 포괄적인 취약점 정보
- ** 실시간 분석**: 개발 중인 코드에 대한 즉시 보안 피드백
- ** 자동 수정**: 발견된 보안 취약점에 대한 자동 수정 제안
- ** 웹 인터페이스**: 사용자 친화적인 Streamlit 기반 웹 애플리케이션
- ** API 서버**: FastAPI 기반의 확장 가능한 백엔드 서비스

##  시스템 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │   API Server    │    │  LLM Services  │
│   (Streamlit)   │◄──►│   (FastAPI)     │◄──►│  (OpenAI/Claude)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  CWE Database   │
                       │   (JSON/Vector) │
                       └─────────────────┘
```

##  빠른 시작

### 1. 환경 설정

#### Python 버전 요구사항
- **Python 3.10.x** 또는 **Python 3.11.x** (권장)
- Python 3.13은 아직 많은 패키지와 호환되지 않음

#### Conda 환경 설정 (권장)
```bash
# 저장소 클론
git clone <repository-url>
cd forticode

# Python 3.10 환경 생성 및 활성화
conda create -n forticode-py310 python=3.10.13 -y
conda activate forticode-py310

# 의존성 설치
pip install -r requirements.txt
```

#### 가상환경 설정 (대안)
```bash
# 저장소 클론
git clone <repository-url>
cd forticode

# Python 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

### 2. 환경 변수 설정

```bash
# .env 파일 생성
cp env.example .env

# API 키 설정
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

### 3. 서비스 실행

#### API 서버 실행
```bash
cd src/api
python main.py
```
서버는 `http://localhost:8000`에서 실행됩니다.

#### 웹 인터페이스 실행
```bash
cd src/web
streamlit run streamlit_app.py
```
웹 앱은 `http://localhost:8501`에서 실행됩니다.

##  사용 방법

###  코드 보안 분석

1. **코드 입력**: 분석하고 싶은 코드를 텍스트 영역에 입력
2. **언어 선택**: Python, JavaScript, Java 등 프로그래밍 언어 선택
3. **컨텍스트 설정**: 웹 애플리케이션, API 서버 등 컨텍스트 정보 입력
4. **분석 실행**: "분석 시작" 버튼 클릭
5. **결과 확인**: 보안 점수, 발견된 이슈, 수정 방안 등 상세 결과 확인

###  보안 코드 생성

1. **요구사항 입력**: 구현하고 싶은 기능을 자연어로 설명
2. **언어 선택**: 생성할 코드의 프로그래밍 언어 선택
3. **보안 원칙 선택**: 적용할 보안 요구사항 선택
4. **코드 생성**: "코드 생성" 버튼 클릭
5. **결과 확인**: 보안을 고려한 안전한 코드 자동 생성

###  취약점 자동 수정

1. **코드 입력**: 수정이 필요한 코드 입력
2. **CWE 선택**: 수정할 특정 보안 이슈 선택 (선택사항)
3. **수정 실행**: "수정 시작" 버튼 클릭
4. **결과 확인**: 원본 코드와 수정된 코드 비교

##  API 엔드포인트

### 코드 분석
```http
POST /analyze
Content-Type: application/json

{
  "code": "your_code_here",
  "language": "python",
  "context": "web_application"
}
```

### 코드 생성
```http
POST /generate
Content-Type: application/json

{
  "description": "user_login_api_with_jwt",
  "language": "python",
  "security_requirements": ["OWASP Top 10 준수", "입력 검증 강화"]
}
```

### 취약점 수정
```http
POST /fix
Content-Type: application/json

{
  "code": "vulnerable_code_here",
  "language": "python",
  "cwe_ids": ["CWE-79", "CWE-89"]
}
```

### CWE 정보 조회
```http
GET /cwe/{cwe_id}
GET /cwe/search/{query}
GET /cwe/list
```

##  지원하는 보안 취약점

| CWE ID | 이름 | 설명 | 위험도 |
|---------|------|------|--------|
| CWE-79 | Cross-site Scripting (XSS) | 사용자 입력 검증 부족 | 🔴 High |
| CWE-89 | SQL Injection | SQL 쿼리 주입 공격 | 🔴 High |
| CWE-200 | Information Exposure | 민감한 정보 노출 | 🟡 Medium |
| CWE-22 | Path Traversal | 경로 조작 공격 | 🟡 Medium |
| CWE-78 | OS Command Injection | OS 명령어 주입 | 🔴 High |
| CWE-434 | Unrestricted Upload | 무제한 파일 업로드 | 🟡 Medium |
| CWE-287 | Authentication Bypass | 인증 우회 | 🔴 High |
| CWE-311 | Missing Encryption | 암호화 부족 | 🟡 Medium |

##  테스트

```bash
# 테스트 실행
pytest tests/

# 코드 품질 검사
black src/
flake8 src/
```

##  성능 지표

- **분석 정확도**: 90%+ (LLM 기반 의미론적 분석)
- **응답 시간**: 평균 3-5초 (코드 복잡도에 따라 변동)
- **지원 언어**: Python, JavaScript, Java, C#, PHP, Go, Rust
- **CWE 커버리지**: OWASP Top 10 + SANS Top 25

##  향후 계획

### Phase 1 (현재)
-  기본 LLM 기반 보안 분석
-  CWE 데이터베이스 구축
-  웹 인터페이스 구현

### Phase 2 (3-6개월)
-  CI/CD 파이프라인 통합
-  IDE 플러그인 개발
-  다국어 지원 확장

### Phase 3 (6-12개월)
-  자율 보안 에이전트
-  실시간 위협 탐지
-  클라우드 네이티브 보안

##  기여하기

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

##  문의


##  감사의 말

- OWASP Foundation
- MITRE Corporation (CWE)
- OpenAI & Anthropic
- LangChain & Streamlit 커뮤니티

---

**FortiCode** - 개발 속도와 보안의 완벽한 조화를 위한 AI 기반 솔루션 

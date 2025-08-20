# FortiCode - LLM RAG 기반 보안 패치 생성 시스템

FortiCode는 LLM(대규모 언어 모델)과 RAG(Retrieval-Augmented Generation) 기술을 활용하여 보안 취약점을 자동으로 탐지하고 수정 패치를 생성하는 AI 기반 보안 코딩 시스템입니다.

##  핵심 기능

### 1. LLM 기반 보안 분석
- **AI 보안 분석기**: OpenAI GPT와 Anthropic Claude를 활용한 코드 취약점 탐지
- **자동 패치 생성**: 발견된 보안 이슈에 대한 구체적인 수정 코드 자동 생성
- **다국어 지원**: Python, Java, C++, JavaScript, PHP, Ruby, Go, Rust 등 다양한 프로그래밍 언어 지원

### 2. RAG 기반 컨텍스트 검색
- **CWE 데이터베이스**: Common Weakness Enumeration 데이터베이스와 연동
- **OWASP 치트시트**: 실용적인 보안 가이드 및 모범 사례 검색
- **FAISS 벡터 검색**: 고성능 유사도 검색을 통한 관련 보안 정보 수집

### 3. GitHub 자동 패치 적용
- **자동 브랜치 생성**: 보안 패치를 위한 새로운 브랜치 자동 생성
- **코드 자동 수정**: GitHub API를 통한 파일 내용 자동 업데이트
- **Pull Request 생성**: 수정된 코드에 대한 자동 PR 생성

##  시스템 아키텍처

```
사용자 코드 입력
        ↓
   LLM 보안 분석
        ↓
   RAG 컨텍스트 검색
        ↓
   보안 패치 생성
        ↓
   GitHub 자동 적용
        ↓
   Pull Request 생성
```

##  프로젝트 구조

### LLM 모듈 (`backend/llm/`)
```
backend/llm/
├── __init__.py
├── patch_generator.py          # AI 기반 보안 패치 생성기
├── README_TESTING.md           # 테스트 가이드
└── faiss_unified_index/       # 통합 FAISS 인덱스
    ├── index.faiss            # 벡터 인덱스 파일
    └── index.pkl              # 메타데이터 파일
```

### RAG 모듈 (`backend/rag/`)
```
backend/rag/
├── __init__.py
├── rag_builder.py             # RAG 시스템 구축 및 관리
├── rag_search_adapter.py      # 검색 인터페이스
├── faiss_unified_index/       # 통합 FAISS 인덱스
│   ├── index.faiss            # 벡터 인덱스 파일
│   └── index.pkl              # 메타데이터 파일
└── cwe_seeds/                 # CWE 시드 데이터
    ├── python.json            # Python 관련 CWE
    ├── java.json              # Java 관련 CWE
    ├── cpp.json               # C++ 관련 CWE
    ├── javascript.json        # JavaScript 관련 CWE
    ├── php.json               # PHP 관련 CWE
    ├── ruby.json              # Ruby 관련 CWE
    ├── go.json                # Go 관련 CWE
    ├── rust.json              # Rust 관련 CWE
    ├── c.json                 # C 관련 CWE
    └── web.json               # 웹 보안 관련 CWE
```

### GitHub 패치 생성기
```
forticode/
├── github_patch_creator.py    # GitHub 자동 패치 생성 및 적용
└── apply_patches.py           # 패치 적용 유틸리티
```

##  빠른 시작

### 1. 환경 설정
```bash
# Conda 환경 생성 및 활성화
conda create -n forticode python=3.9
conda activate forticode

# 의존성 설치
pip install -r requirements.txt
```

### 2. 환경 변수 설정
```bash
export OPENAI_API_KEY="your_openai_api_key"
export ANTHROPIC_API_KEY="your_anthropic_api_key"
export GITHUB_TOKEN="your_github_personal_access_token"
```

### 3. LLM RAG 시스템 테스트
```bash
cd backend/security/analysis
python test_llm_rag_pipeline.py
```

### 4. GitHub 패치 생성기 실행
```bash
python github_patch_creator.py
```

##  사용 예시

### LLM 보안 분석 및 패치 생성
```python
from backend.llm.patch_generator import SecurityPatchGenerator
from backend.rag.rag_search_adapter import RAGSearchAdapter

# RAG 검색 어댑터 초기화
rag_adapter = RAGSearchAdapter()

# 보안 패치 생성기 초기화
patch_generator = SecurityPatchGenerator(
    openai_api_key="your_openai_key",
    anthropic_api_key="your_anthropic_key"
)

# 취약한 코드 예시
vulnerable_code = '''
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
'''

# RAG를 통한 컨텍스트 검색
context = rag_adapter.search_relevant_context(
    query="SQL injection vulnerability",
    language="python"
)

# AI 기반 패치 생성
patch = patch_generator.generate_security_patch(
    code=vulnerable_code,
    vulnerability_type="SQL_INJECTION",
    language="python",
    context=context
)

print("생성된 패치:")
print(patch['secure_code'])
```

### GitHub 자동 패치 적용
```python
from github_patch_creator import GitHubPatchCreator

# GitHub 패치 생성기 초기화
patcher = GitHubPatchCreator(
    token=os.getenv('GITHUB_TOKEN'),
    repo_owner="your_username",
    repo_name="your_repository"
)

# 새 브랜치 생성
branch_name = patcher.create_branch()

# 보안 패치 적용
result = patcher.apply_security_patches(
    secure_code_file="vulnbank_secure_code_generated.json",
    branch=branch_name
)

# Pull Request 생성
if result['applied_count'] > 0:
    pr_url = patcher.create_pull_request(
        title="보안 취약점 자동 패치 적용",
        body="FortiCode를 통해 자동 생성된 보안 패치",
        head_branch=branch_name
    )
    print(f"Pull Request 생성됨: {pr_url}")
```

##  주요 컴포넌트

### 1. SecurityPatchGenerator (`backend/llm/patch_generator.py`)
- **기능**: AI 모델을 활용한 보안 패치 자동 생성
- **지원 모델**: OpenAI GPT-4, Anthropic Claude
- **출력**: 취약한 코드와 안전한 코드 쌍, 수정 설명

### 2. RAGSearchAdapter (`backend/rag/rag_search_adapter.py`)
- **기능**: FAISS 벡터 검색을 통한 관련 보안 정보 검색
- **검색 소스**: CWE 데이터베이스, OWASP 치트시트
- **출력**: 검색된 보안 컨텍스트 및 관련 문서

### 3. RAGBuilder (`backend/rag/rag_builder.py`)
- **기능**: RAG 시스템 구축 및 인덱스 관리
- **벡터화**: 텍스트를 고차원 벡터로 변환
- **인덱싱**: FAISS를 통한 고성능 검색 인덱스 생성

### 4. GitHubPatchCreator (`github_patch_creator.py`)
- **기능**: GitHub 저장소에 보안 패치 자동 적용
- **API 연동**: GitHub REST API를 통한 저장소 관리
- **자동화**: 브랜치 생성, 파일 수정, PR 생성

##  데이터 흐름

1. **코드 입력**: 사용자가 분석할 코드 입력
2. **LLM 분석**: AI 모델이 코드의 보안 취약점 탐지
3. **RAG 검색**: 관련 CWE 및 OWASP 정보 검색
4. **컨텍스트 융합**: 검색된 정보와 코드 분석 결과 결합
5. **패치 생성**: AI가 안전한 코드로 수정된 버전 생성
6. **GitHub 적용**: 생성된 패치를 GitHub 저장소에 자동 적용
7. **PR 생성**: 수정된 코드에 대한 Pull Request 자동 생성

##  보안 기능

- **토큰 보안**: GitHub 토큰을 환경 변수로 관리
- **입력 검증**: 사용자 입력의 안전성 검증
- **API 보안**: GitHub API 요청에 대한 적절한 인증 및 권한 관리
- **에러 처리**: 민감한 정보 노출을 방지하는 안전한 에러 처리

##  관련 문서

- **API 계약**: `backend/API_CONTRACT.md`
- **테스트 가이드**: `backend/llm/README_TESTING.md`
- **보안 워크플로우**: `backend/security/analysis/README_VULNTEST.md`

##  기여하기

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

##  라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

---

**FortiCode** - AI 기반 보안 코딩으로 더 안전한 소프트웨어를 만들어갑니다! 🔒✨ 

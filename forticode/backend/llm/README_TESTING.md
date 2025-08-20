# LLM 패치 생성기 테스트 가이드

## 테스트 시작하기

### 1. 환경 변수 설정

#### 방법 1: 환경 변수로 직접 설정
```bash
# OpenAI API 키 설정
export OPENAI_API_KEY="your-openai-api-key-here"

# Anthropic API 키 설정 (선택사항)
export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
```

#### 방법 2: .env 파일 생성
```bash
# backend 디렉토리에 .env 파일 생성
cd forticode/backend

# .env 파일 내용
OPENAI_API_KEY=your-openai-api-key-here
ANTHROPIC_API_KEY=your-anthropic-api-key-here
DEFAULT_LLM_MODEL=gpt-4
```

### 2. 필요한 패키지 설치

```bash
cd forticode/backend
pip install -r requirements.txt

# 추가로 필요한 패키지들
pip install python-dotenv langchain-openai langchain-anthropic
```

### 3. 테스트 실행

```bash
cd forticode/backend/llm
python test_patch_generator.py
```

## 테스트 내용

### 테스트 1: OpenAI API 패치 생성
- **CWE-89 (SQL Injection)** - Python 언어
- **CWE-95 (Code Injection)** - JavaScript 언어
- 언어별 보안 가드레일 적용
- RAG 컨텍스트 기반 패치 생성

### 테스트 2: Anthropic API 패치 생성
- **CWE-89 (SQL Injection)** - Java 언어
- **CWE-95 (Code Injection)** - JavaScript 언어
- Claude 모델을 사용한 패치 생성

### 테스트 3: 배치 패치 생성
- 여러 발견 결과에 대한 일괄 패치 생성
- 패치 품질 검증 및 점수 계산

## 예상 출력 결과

```
LLM 패치 생성기 테스트 시작
============================================================
OpenAI API를 사용한 패치 생성 테스트
============================================================
OpenAI 패치 생성기 초기화 성공

패치 생성 중... (CWE: CWE-89, 언어: python)
   메시지: SQL injection via string concatenation

패치 생성 완료!
   설명: SQL injection 취약점은 사용자 입력을 직접 SQL 쿼리에 연결할 때 발생합니다...
   신뢰도: 0.85
   커밋 메시지: security: fix SQL injection in database.py

패치 내용:
--- a/app/database.py
+++ b/app/database.py
@@ -42,1 +42,1 @@
-query = f"SELECT * FROM users WHERE id = {user_id}"
+query = "SELECT * FROM users WHERE id = ?"
+params = (user_id,)

테스트 코드:
def test_sql_injection_prevention():
    # SQL injection 방지 테스트
    user_id = "1; DROP TABLE users; --"
    result = get_user_by_id(user_id)
    assert result is not None

패치 검증 결과:
   유효성: 성공
   점수: 0.90
```

## 문제 해결

### 1. API 키 오류
```
OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.
```
**해결방법**: 환경 변수 또는 .env 파일에 API 키를 설정하세요.

### 2. 모듈 임포트 오류
```
ModuleNotFoundError: No module named 'langchain_openai'
```
**해결방법**: 필요한 패키지를 설치하세요.
```bash
pip install langchain-openai langchain-anthropic
```

### 3. API 호출 실패
```
OpenAI 패치 생성 테스트 실패: Rate limit exceeded
```
**해결방법**: API 사용량 제한을 확인하고 잠시 후 다시 시도하세요.

## 커스터마이징

### 다른 모델 사용
```python
# GPT-3.5-turbo 사용
generator = LLMPatchGenerator(
    openai_api_key=api_key,
    model_name="gpt-3.5-turbo"
)

# Claude-3 Sonnet 사용
generator = LLMPatchGenerator(
    anthropic_api_key=api_key,
    model_name="claude-3-sonnet-20240229"
)
```

### 새로운 테스트 케이스 추가
```python
def create_custom_test_finding():
    return SecurityFinding(
        finding_id="custom_001",
        source="custom_tool",
        tool=ToolType.SAST,
        rule_id="CUSTOM_RULE",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        language=Language.PHP,
        file_path="app/upload.php",
        line_number=15,
        message="OS command injection vulnerability",
        evidence="system($_GET['cmd'])"
    )
```

## 성능 모니터링

### API 응답 시간 측정
```python
import time

start_time = time.time()
patch = generator.generate_patch(finding, rag_context, code_snippet)
end_time = time.time()

print(f"패치 생성 시간: {end_time - start_time:.2f}초")
```

### 토큰 사용량 확인
```python
# OpenAI API 응답에서 토큰 사용량 확인
response = generator.llm.invoke([...])
if hasattr(response, 'usage'):
    print(f"사용된 토큰: {response.usage}")
```

## 다음 단계

1. **실제 코드베이스에 적용**: 테스트가 성공하면 실제 프로젝트에 통합
2. **성능 최적화**: 배치 처리 및 캐싱 구현
3. **품질 향상**: 더 많은 테스트 케이스와 검증 로직 추가
4. **모니터링**: API 사용량 및 패치 품질 추적 시스템 구축

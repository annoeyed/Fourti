# FortiCode 보안 코드 생성 가이드

## 개요

이 가이드는 `forticode` 프로젝트를 사용하여 취약한 코드를 자동으로 분석하고 시큐어 코드를 생성하는 방법을 설명합니다.

## 사전 요구사항

1. **API 키 설정**
   - OpenAI API 키 또는 Anthropic API 키 필요
   - GitHub 토큰 (자동 PR 생성을 위해)

2. **환경 변수 설정**
   ```bash
   # OpenAI 사용 시
   export OPENAI_API_KEY='your_openai_api_key_here'
   
   # Anthropic 사용 시
   export ANTHROPIC_API_KEY='your_anthropic_api_key_here'
   
   # GitHub 자동 PR 생성을 위해
   export GITHUB_TOKEN='your_github_token_here'
   ```

## 단계별 진행

### 1단계: 취약점 분석 (완료됨)
```bash
cd forticode
python -m backend.security.analysis.test_vulnbank_workflow
```

### 2단계: 보안 코드 생성
```bash
cd forticode
python generate_secure_code.py
```

이 단계에서:
- VulnBank 프로젝트의 취약점을 분석
- RAG 시스템을 통한 보안 컨텍스트 수집
- LLM을 통한 시큐어 코드 생성
- 패치 제안 및 보안 가이드 생성

### 3단계: 패치 자동 적용
```bash
cd forticode
python apply_patches.py
```

이 단계에서:
- 생성된 패치를 자동으로 적용
- 새로운 보안 브랜치 생성
- 자동 커밋 및 푸시
- 고위험 취약점의 경우 자동 PR 생성

### 4단계: 결과 검증
```bash
# 보안 테스트 재실행
python -m backend.security.analysis.test_vulnbank_workflow

# 생성된 결과 파일 확인
cat vulnbank_security_analysis_with_patches.json
```

## 생성되는 파일들

1. **`vulnbank_security_analysis_with_patches.json`**
   - 전체 보안 분석 결과
   - 생성된 패치 정보
   - 보안 가이드

2. **Git 브랜치**
   - `secfix/{finding_id}` 형태의 보안 수정 브랜치
   - 각 취약점별로 별도 브랜치

3. **Pull Request** (고위험 취약점)
   - 자동으로 생성되는 보안 수정 PR
   - 코드 리뷰를 위한 자동화된 워크플로우

## 주요 기능

### 자동 패치 생성
- SAST/DAST 결과 기반 취약점 분석
- RAG 시스템을 통한 보안 컨텍스트 수집
- LLM 기반 시큐어 코드 제안

### 자동 패치 적용
- Git 기반 자동 패치 적용
- 보안 브랜치 자동 생성
- 자동 커밋 및 푸시

### 자동 PR 생성
- 고위험 취약점 자동 PR 생성
- 보안 수정 워크플로우 자동화
- 코드 리뷰 프로세스 지원

## 문제 해결

### API 키 오류
```bash
# 환경 변수 확인
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY

# 환경 변수 재설정
export OPENAI_API_KEY='your_key_here'
```

### 모듈 임포트 오류
```bash
# Python 경로 확인
python -c "import sys; print(sys.path)"

# 현재 디렉토리를 Python 경로에 추가
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Git 관련 오류
```bash
# Git 저장소 상태 확인
cd vulntest_total/vulnbank
git status

# Git 설정 확인
git config --list
```

## 다음 단계

1. **패치 검토**: 생성된 패치의 품질 검토
2. **보안 테스트**: 수정된 코드의 보안 검증
3. **성능 테스트**: 보안 수정 후 성능 영향 평가
4. **문서화**: 보안 수정 사항 문서화

## 지원 및 문의

문제가 발생하거나 추가 지원이 필요한 경우:
1. 로그 파일 확인
2. 에러 메시지 분석
3. 관련 모듈의 상태 확인

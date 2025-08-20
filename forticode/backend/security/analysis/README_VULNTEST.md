# VulnTest 보안 워크플로우

이 워크플로우는 `vulntest` 프로젝트와 `vulntest_analysis` 결과를 입력으로 받아서 LLM+RAG를 통해 안전한 코드를 생성하는 시스템입니다.

## 개요

VulnBank 보안 워크플로우는 다음과 같은 단계로 구성됩니다:

1. **프로젝트 구조 분석**: vulntest 프로젝트의 파일 구조 및 내용 분석
2. **분석 결과 파싱**: vulntest_analysis 결과 파일에서 취약점 정보 추출
3. **패턴 기반 스캔**: Python 코드에서 알려진 보안 취약점 패턴 검색
4. **RAG 컨텍스트 수집**: 보안 관련 정보를 RAG 시스템에서 검색
5. **LLM 기반 코드 생성**: 발견된 취약점을 수정한 안전한 코드 생성
6. **통합 리포트 생성**: 전체 분석 결과 및 권장사항 정리

## 주요 기능

### 1. 취약점 패턴 인식
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Unsafe Deserialization (CWE-502)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-328, CWE-338)
- Information Disclosure (CWE-200)
- Format String (CWE-134)
- File Upload (CWE-434)
- XXE (CWE-611)

### 2. LLM 기반 안전한 코드 생성
- 개별 취약점별 수정 코드 생성
- 전체 파일의 안전한 버전 생성
- 보안 모범 사례 적용
- 실용적이고 프로덕션 환경에서 사용 가능한 코드

### 3. RAG 기반 보안 컨텍스트
- CWE별 관련 보안 정보 검색
- Python 웹 애플리케이션 보안 가이드
- 취약점 방지 모범 사례

## 사용법

### 1. 환경 설정

```bash
# API 키 설정
export OPENAI_API_KEY="your_openai_api_key"
export ANTHROPIC_API_KEY="your_anthropic_api_key"

# 또는 .env 파일 생성
echo "OPENAI_API_KEY=your_openai_api_key" > .env
echo "ANTHROPIC_API_KEY=your_anthropic_api_key" >> .env
```

### 2. Python 코드에서 사용

```python
from security.analysis.vulnbank_security_workflow import VulnBankSecurityWorkflow

# 워크플로우 초기화
workflow = VulnBankSecurityWorkflow(
    openai_api_key="your_openai_api_key",
    anthropic_api_key="your_anthropic_api_key"
)

# VulnTest 분석 실행
results = workflow.analyze_vulntest_with_analysis(
    vulntest_path="/path/to/vulntest",
    vulntest_analysis_path="/path/to/vulntest_analysis.json"
)

# 결과 확인
print(f"발견된 취약점: {results['security_analysis']['total_findings']}")
print(f"보안 점수: {results['security_analysis']['security_score']}")
```

### 3. 테스트 스크립트 실행

```bash
cd forticode/backend/security/analysis
python test_vulntest_workflow.py
```

## 입력 형식

### vulntest 프로젝트
- Python 파일들이 포함된 디렉토리
- `tests/` 디렉토리 (선택사항)
- `requirements.txt`, `config.py`, `main.py` 등 설정 파일

### vulntest_analysis 결과
다음 형식 중 하나를 지원합니다:

#### 표준 형식
```json
{
  "findings": [
    {
      "source": "tool_name",
      "rule_id": "rule_identifier",
      "cwe": "CWE-89",
      "severity": "high",
      "file_path": "app/main.py",
      "line_number": 42,
      "message": "SQL Injection vulnerability",
      "evidence": "vulnerable code snippet",
      "reference": "https://example.com/reference"
    }
  ]
}
```

#### 결과 형식
```json
{
  "results": [
    {
      "id": "finding_id",
      "cwe_id": "CWE-89",
      "severity": "HIGH",
      "file": "app/main.py",
      "line": 42,
      "description": "SQL Injection vulnerability",
      "code": "vulnerable code snippet"
    }
  ]
}
```

#### 취약점 형식
```json
{
  "vulnerabilities": [
    {
      "rule_id": "rule_identifier",
      "cwe": "CWE-89",
      "severity": "high",
      "filename": "app/main.py",
      "lineno": 42,
      "message": "SQL Injection vulnerability",
      "snippet": "vulnerable code snippet"
    }
  ]
}
```

## 출력 형식

### 보안 분석 결과
```json
{
  "project_info": {
    "name": "VulnTest",
    "type": "Educational Security Project",
    "total_files": 10,
    "python_files": 8
  },
  "security_analysis": {
    "total_findings": 15,
    "security_score": 65.0,
    "risk_level": "HIGH",
    "severity_distribution": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    },
    "cwe_distribution": {
      "CWE-89": 8,
      "CWE-78": 4,
      "CWE-502": 3
    }
  },
  "findings_details": [...],
  "secure_code_versions": {
    "secure_files": {
      "app/main.py": {
        "original_file": "app/main.py",
        "secure_code": "수정된 안전한 코드...",
        "vulnerabilities_fixed": 5,
        "cwe_list": ["CWE-89", "CWE-78"]
      }
    }
  },
  "recommendations": [
    "SQL Injection 취약점이 다수 발견되었습니다. Parameterized Query를 사용하세요.",
    "Command Injection 취약점이 발견되었습니다. shell=True 사용을 피하세요."
  ],
  "next_steps": [
    "생성된 안전한 코드로 취약점을 수정하세요.",
    "OWASP Top 10 웹 애플리케이션 보안 가이드를 학습하세요."
  ]
}
```

## 보안 점수 계산

보안 점수는 0-100 범위로 계산되며, 높을수록 안전합니다:

- **CRITICAL**: 30점 차감
- **HIGH**: 25점 차감  
- **MEDIUM**: 20점 차감
- **LOW**: 10점 차감

## 위험 수준 판정

- **80-100**: LOW (낮음)
- **60-79**: MEDIUM (보통)
- **40-59**: HIGH (높음)
- **0-39**: CRITICAL (매우 높음)

## 주의사항

1. **API 키 보안**: API 키를 코드에 하드코딩하지 마세요.
2. **프로덕션 환경**: 이 도구는 교육 및 테스트 목적으로 설계되었습니다.
3. **결과 검증**: 생성된 안전한 코드는 반드시 검토 후 사용하세요.
4. **의존성**: OpenAI 또는 Anthropic API 키가 필요합니다.

## 문제 해결

### 일반적인 오류

1. **Import 오류**: Python 경로가 올바르게 설정되었는지 확인
2. **API 키 오류**: 환경 변수 또는 .env 파일 확인
3. **파일 경로 오류**: 입력 경로가 존재하는지 확인
4. **권한 오류**: 파일 읽기 권한 확인

### 로그 확인

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 라이선스

이 프로젝트는 교육 및 연구 목적으로 제공됩니다.

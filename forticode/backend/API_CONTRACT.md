# FortiCode API 계약서

## 개요
FortiCode는 SAST/DAST 결과를 통합하고 LLM 기반 자동 패치를 제안하는 보안 코드 분석 서비스입니다.

## 기본 정보
- **Base URL**: `http://localhost:8000`
- **API 버전**: v1.0.0
- **인증**: API 키 기반 (OpenAI/Anthropic)
- **응답 형식**: JSON

## 공통 응답 형식

### 성공 응답
```json
{
  "success": true,
  "data": { ... },
  "message": "성공적으로 처리되었습니다"
}
```

### 오류 응답
```json
{
  "success": false,
  "error": "오류 메시지",
  "detail": "상세 오류 정보"
}
```

## 엔드포인트

### 1. 보안 스캔 처리

#### POST `/scan`
SAST/DAST 도구 결과를 처리하고 보안 분석을 수행합니다.

**요청 본문:**
```json
{
  "tool_results": {
    "bandit": "/path/to/bandit-results.json",
    "zap": "/path/to/zap-results.json",
    "spotbugs": "/path/to/spotbugs-results.xml"
  },
  "include_patches": true,
  "auto_apply": false
}
```

**응답:**
```json
{
  "scan_id": "scan_123_0001",
  "timestamp": "2024-01-15T10:30:00",
  "findings_count": 15,
  "summary": {
    "total_findings": 15,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    },
    "by_language": {
      "python": 8,
      "java": 4,
      "web": 3
    },
    "by_cwe": {
      "CWE-89": 3,
      "CWE-79": 2,
      "CWE-259": 1
    }
  },
  "findings": [
    {
      "finding_id": "abc12345",
      "source": "bandit",
      "rule_id": "B105",
      "cwe": "CWE-259",
      "severity": "high",
      "language": "python",
      "file_path": "app/auth.py",
      "line_number": 42,
      "message": "Hardcoded password string",
      "evidence": "password = 'secret123'",
      "priority": {
        "score": 90,
        "level": "HIGH"
      },
      "business_impact": "HIGH"
    }
  ],
  "security_summary": {
    "total_findings": 15,
    "top_issues": [
      {
        "finding_id": "abc12345",
        "cwe": "CWE-259",
        "severity": "high",
        "message": "Hardcoded password string"
      }
    ]
  },
  "patches_generated": 8,
  "patches": [
    {
      "finding_id": "abc12345",
      "explanation": "하드코딩된 패스워드를 환경변수로 대체하여 보안을 강화합니다.",
      "diff": "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -42,7 +42,7 @@\n-    password = 'secret123'\n+    password = os.getenv('AUTH_PASSWORD')\n",
      "test_snippet": "def test_password_from_env():\n    assert os.getenv('AUTH_PASSWORD') is not None",
      "commit_message": "security: replace hardcoded password with environment variable",
      "commit_body": "하드코딩된 패스워드를 환경변수로 대체하여 보안 취약점을 수정합니다.",
      "confidence": 0.85,
      "risk_assessment": "패치 후 보안 위험도가 크게 감소합니다.",
      "alternative_approaches": ["설정 파일 사용", "시크릿 관리 서비스 연동"]
    }
  ]
}
```

### 2. 발견 결과 조회

#### GET `/findings`
보안 발견 결과를 필터링하여 조회합니다.

**쿼리 파라미터:**
- `severity`: 심각도 필터 (low, medium, high, critical)
- `tool`: 도구 필터 (bandit, zap, spotbugs, cppcheck)
- `language`: 언어 필터 (python, java, cpp, web)
- `cwe`: CWE ID 필터
- `limit`: 결과 제한 (기본값: 100)

**응답:**
```json
{
  "findings": [
    {
      "finding_id": "abc12345",
      "source": "bandit",
      "rule_id": "B105",
      "cwe": "CWE-259",
      "severity": "high",
      "language": "python",
      "file_path": "app/auth.py",
      "line_number": 42,
      "message": "Hardcoded password string",
      "evidence": "password = 'secret123'",
      "priority": {
        "score": 90,
        "level": "HIGH"
      },
      "business_impact": "HIGH"
    }
  ],
  "total_count": 15,
  "filters_applied": {
    "severity": "high",
    "language": "python"
  }
}
```

### 3. 패치 생성

#### POST `/patches/generate`
특정 발견 결과에 대한 패치를 생성합니다.

**요청 본문:**
```json
{
  "finding_ids": ["abc12345", "def67890"],
  "include_code_snippets": true
}
```

**응답:**
```json
{
  "findings_processed": 2,
  "patches_generated": 2,
  "patches": [
    {
      "finding_id": "abc12345",
      "explanation": "하드코딩된 패스워드를 환경변수로 대체합니다.",
      "diff": "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -42,7 +42,7 @@\n-    password = 'secret123'\n+    password = os.getenv('AUTH_PASSWORD')\n",
      "test_snippet": "def test_password_from_env():\n    assert os.getenv('AUTH_PASSWORD') is not None",
      "commit_message": "security: replace hardcoded password",
      "commit_body": "보안 취약점 수정",
      "confidence": 0.85,
      "risk_assessment": "보안 위험도 감소",
      "alternative_approaches": ["설정 파일 사용"]
    }
  ]
}
```

### 4. 패치 적용

#### POST `/patches/apply`
생성된 패치를 적용하고 PR을 생성합니다.

**요청 본문:**
```json
{
  "finding_id": "abc12345",
  "patch_id": "patch_001",
  "auto_create_pr": true
}
```

**응답:**
```json
{
  "success": true,
  "branch_name": "secfix/abc12345",
  "commit_hash": "a1b2c3d4e5f6",
  "pr_created": true,
  "pr_url": "https://github.com/user/repo/pull/123",
  "pr_number": 123,
  "message": "패치가 성공적으로 적용되었습니다"
}
```

### 5. 스캔 실행 결과 조회

#### GET `/runs/{run_id}`
특정 스캔 실행의 상세 결과를 조회합니다.

**응답:**
```json
{
  "run_id": "scan_123_0001",
  "timestamp": "2024-01-15T10:30:00",
  "status": "completed",
  "findings_count": 15,
  "patches_generated": 8,
  "patches_applied": 3,
  "summary": {
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    }
  }
}
```

### 6. 패치 제안 목록

#### GET `/proposals`
패치 제안 목록을 조회합니다.

**쿼리 파라미터:**
- `status`: 상태 필터 (pending, applied, rejected)
- `confidence_min`: 최소 신뢰도 (0.0 ~ 1.0)
- `limit`: 결과 제한 (기본값: 50)

**응답:**
```json
{
  "proposals": [
    {
      "finding_id": "abc12345",
      "patch_id": "patch_001",
      "status": "pending",
      "confidence": 0.85,
      "explanation": "하드코딩된 패스워드를 환경변수로 대체",
      "created_at": "2024-01-15T10:30:00",
      "review_status": "pending"
    }
  ],
  "total_count": 8,
  "status_distribution": {
    "pending": 5,
    "applied": 2,
    "rejected": 1
  }
}
```

### 7. CWE 정보 조회

#### GET `/cwe/{cwe_id}`
특정 CWE의 상세 정보를 조회합니다.

**응답:**
```json
{
  "id": "CWE-259",
  "name": "Use of Hard-coded Password",
  "description": "The software contains a hard-coded password...",
  "likelihood": "high",
  "severity": "high",
  "examples": ["Example 1: ...", "Example 2: ..."],
  "mitigations": ["Mitigation 1: ...", "Mitigation 2: ..."],
  "detection_methods": ["Method 1: ...", "Method 2: ..."],
  "risk_score": 8.5
}
```

### 8. CWE 검색

#### GET `/cwe/search/{query}`
CWE를 검색합니다.

**응답:**
```json
{
  "query": "password",
  "results_count": 3,
  "results": [
    {
      "id": "CWE-259",
      "name": "Use of Hard-coded Password",
      "description": "The software contains a hard-coded password...",
      "risk_score": 8.5
    }
  ]
}
```

## 데이터 모델

### SecurityFinding
```typescript
interface SecurityFinding {
  finding_id: string;
  source: string;
  tool: 'sast' | 'dast' | 'sca' | 'iast';
  rule_id: string;
  cwe?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  language: 'python' | 'java' | 'cpp' | 'c' | 'javascript' | 'web';
  file_path?: string;
  line_number?: number;
  endpoint?: string;
  message: string;
  evidence: string;
  links: string[];
  metadata: Record<string, any>;
}
```

### PatchProposal
```typescript
interface PatchProposal {
  finding_id: string;
  explanation: string;
  diff: string;
  test_snippet: string;
  commit_message: string;
  commit_body: string;
  confidence: number;
  risk_assessment: string;
  alternative_approaches: string[];
}
```

### ScanResult
```typescript
interface ScanResult {
  scan_id: string;
  timestamp: string;
  tool_results: SecurityFinding[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
    by_language: Record<string, number>;
    by_cwe: Record<string, number>;
  };
}
```

## 상태 코드

- `200`: 성공
- `201`: 생성됨
- `400`: 잘못된 요청
- `404`: 찾을 수 없음
- `500`: 서버 내부 오류

## 에러 처리

모든 API는 일관된 에러 응답 형식을 사용합니다:

```json
{
  "success": false,
  "error": "Validation failed",
  "detail": "tool_results field is required",
  "status_code": 400
}
```

## 인증

API 키는 헤더에 포함하여 전송합니다:

```
Authorization: Bearer YOUR_API_KEY
```

## 제한사항

- **요청 크기**: 최대 10MB
- **응답 시간**: 30초 이내
- **동시 요청**: 최대 10개
- **데이터 보존**: 30일

## 웹훅

패치 적용 완료 시 웹훅을 통해 알림을 받을 수 있습니다:

```json
{
  "event": "patch_applied",
  "data": {
    "finding_id": "abc12345",
    "patch_id": "patch_001",
    "pr_url": "https://github.com/user/repo/pull/123",
    "timestamp": "2024-01-15T10:30:00"
  }
}
```

## 예제 사용법

### Python 클라이언트
```python
import requests

# 보안 스캔 실행
response = requests.post('http://localhost:8000/scan', json={
    'tool_results': {
        'bandit': '/path/to/bandit-results.json'
    },
    'include_patches': True
})

scan_result = response.json()
print(f"발견된 취약점: {scan_result['findings_count']}개")
```

### JavaScript 클라이언트
```javascript
// 패치 생성
const response = await fetch('http://localhost:8000/patches/generate', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer YOUR_API_KEY'
    },
    body: JSON.stringify({
        finding_ids: ['abc12345'],
        include_code_snippets: true
    })
});

const result = await response.json();
console.log(`생성된 패치: ${result.patches_generated}개`);
```

## 지원 및 문의

- **문서**: [FortiCode Wiki](https://github.com/forticode/docs)
- **이슈**: [GitHub Issues](https://github.com/forticode/issues)
- **이메일**: support@forticode.dev

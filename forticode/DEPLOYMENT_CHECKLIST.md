# FortiCode 배포 후 확인 체크리스트

## 🚀 배포 완료 후 확인사항

### 1. 서비스 상태 확인
```bash
# 서비스 상태 확인
sudo systemctl status forticode

# 서비스 로그 확인
sudo journalctl -u forticode -f

# 서비스 자동 시작 확인
sudo systemctl is-enabled forticode
```

### 2. API 엔드포인트 테스트
```bash
# API 문서 접근
curl http://localhost:8000/docs

# 헬스체크
curl http://localhost:8000/health

# RAG 검색 테스트
curl -X POST "http://localhost:8000/rag/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "SQL injection prevention", "max_results": 5}'

# 보안 분석 테스트
curl -X POST "http://localhost:8000/security/analyze" \
  -H "Content-Type: application/json" \
  -d '{"code": "user_input = input()\nexec(user_input)", "language": "python"}'
```

### 3. 파일 및 디렉토리 확인
```bash
# 프로젝트 구조 확인
ls -la ~/forticode/
ls -la ~/forticode/backend/

# RAG 인덱스 파일 확인
ls -la ~/forticode/backend/rag/faiss_unified_index/
ls -la ~/forticode/backend/llm/faiss_unified_index/

# 데이터베이스 파일 확인
ls -la ~/forticode/backend/api/data/

# 가상환경 확인
ls -la ~/forticode/venv/
```

### 4. 환경 변수 확인
```bash
# .env 파일 확인
cat ~/forticode/.env

# 환경 변수 로드 확인
source ~/forticode/venv/bin/activate
python -c "import os; print('OPENAI_API_KEY:', 'SET' if os.getenv('OPENAI_API_KEY') else 'NOT SET')"
python -c "import os; print('ANTHROPIC_API_KEY:', 'SET' if os.getenv('ANTHROPIC_API_KEY') else 'NOT SET')"
```

### 5. 의존성 확인
```bash
# Python 패키지 확인
source ~/forticode/venv/bin/activate
pip list | grep -E "(fastapi|uvicorn|langchain|faiss|sentence-transformers)"

# 핵심 모듈 import 테스트
python -c "
try:
    from backend.api.main import app
    from backend.rag.rag_search_adapter import RAGSearchAdapter
    from backend.llm.patch_generator import LLMPatchGenerator
    from backend.security.analysis.integrated_security_workflow import WebSecurityWorkflow
    print('✅ 모든 모듈이 정상적으로 import됩니다.')
except ImportError as e:
    print(f'❌ 모듈 import 오류: {e}')
"
```

### 6. 포트 및 네트워크 확인
```bash
# 포트 리스닝 확인
netstat -tlnp | grep :8000
ss -tlnp | grep :8000

# 방화벽 확인 (필요시)
sudo ufw status
sudo iptables -L
```

### 7. 성능 및 리소스 확인
```bash
# 메모리 사용량 확인
free -h

# 디스크 사용량 확인
df -h

# 프로세스 확인
ps aux | grep forticode
```

## 🔧 문제 해결

### 서비스가 시작되지 않는 경우
```bash
# 로그 확인
sudo journalctl -u forticode -f

# 수동으로 실행 테스트
cd ~/forticode
source venv/bin/activate
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
```

### API 키 오류가 발생하는 경우
```bash
# .env 파일 수정
nano ~/forticode/.env

# 서비스 재시작
sudo systemctl restart forticode
```

### RAG 검색이 작동하지 않는 경우
```bash
# 인덱스 파일 권한 확인
ls -la ~/forticode/backend/rag/faiss_unified_index/
chmod 644 ~/forticode/backend/rag/faiss_unified_index/*

# Python 경로 확인
echo $PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

## 📊 모니터링 명령어

### 실시간 로그 모니터링
```bash
# 서비스 로그 실시간 모니터링
sudo journalctl -u forticode -f

# 시스템 로그에서 오류 확인
sudo journalctl -u forticode --since "1 hour ago" | grep ERROR
```

### 성능 모니터링
```bash
# CPU 및 메모리 사용량 모니터링
htop

# 네트워크 연결 모니터링
netstat -tlnp | grep :8000
```

## 🎯 성공 기준

- ✅ 서비스가 정상적으로 시작됨
- ✅ API 문서에 접근 가능 (http://localhost:8000/docs)
- ✅ RAG 검색 엔드포인트가 정상 작동
- ✅ 보안 분석 엔드포인트가 정상 작동
- ✅ 모든 필요한 파일과 디렉토리가 존재
- ✅ 환경 변수가 올바르게 설정됨
- ✅ 의존성 패키지가 모두 설치됨

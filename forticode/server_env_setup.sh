#!/bin/bash

# 서버 환경 설정 스크립트
echo "FortiCode 서버 환경 설정을 시작합니다..."

# 환경 변수 파일 생성
cat > .env << 'EOF'
# FortiCode API 서버 환경 설정

# LLM API 키 (필수)
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Hugging Face API 키 (선택사항)
HUGGINGFACE_API_KEY=your_huggingface_api_key_here

# 서버 설정
HOST=0.0.0.0
PORT=8000
DEBUG=false

# 로깅 설정
LOG_LEVEL=INFO
LOG_FILE=forticode.log

# RAG 설정
RAG_INDEX_PATH=backend/rag/faiss_unified_index
LLM_INDEX_PATH=backend/llm/faiss_unified_index

# 보안 설정
CORS_ORIGINS=["*"]
MAX_REQUEST_SIZE=10485760  # 10MB

# 캐시 설정
CACHE_TTL=3600  # 1시간
EOF

echo "환경 변수 파일(.env)이 생성되었습니다."
echo "API 키를 설정한 후 서비스를 재시작하세요:"
echo "sudo systemctl restart forticode"

# Python 경로 설정
echo "Python 경로를 설정합니다..."
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
echo "export PYTHONPATH=\"${PYTHONPATH}:$(pwd)\"" >> ~/.bashrc

# 필요한 디렉토리 권한 설정
echo "파일 권한을 설정합니다..."
chmod 644 backend/rag/faiss_unified_index/*
chmod 644 backend/llm/faiss_unified_index/*
chmod 644 backend/api/data/*
chmod 755 backend/rag/faiss_unified_index/
chmod 755 backend/llm/faiss_unified_index/
chmod 755 backend/api/data/

echo "환경 설정이 완료되었습니다!"
echo "다음 단계:"
echo "1. .env 파일에서 API 키를 설정하세요"
echo "2. sudo systemctl restart forticode"
echo "3. sudo systemctl status forticode"

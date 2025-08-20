#!/bin/bash

# FortiCode 완전 배포 스크립트 (RAG + LLM + 취약점 분석)
echo "FortiCode 완전 배포 시작 (RAG + LLM + 취약점 분석)..."

# 서버 정보
SERVER_HOST="128.134.233.158"
SERVER_USER="aiproject"
SERVER_PORT="7000"
SERVER_PATH="~/forticode"

# 배포할 파일들 (RAG 데이터와 LLM 모델 포함)
echo "배포할 파일들을 압축합니다..."
tar -czf forticode_complete.tar.gz \
    backend/ \
    requirements.txt \
    README.md \
    env.example \
    .gitignore \
    --exclude='backend/__pycache__' \
    --exclude='backend/**/__pycache__' \
    --exclude='backend/**/*.pyc' \
    --exclude='venv/' \
    --exclude='*.zip' \
    --exclude='CheatSheetSeries/'

echo "압축 완료: forticode_complete.tar.gz"
echo "압축 크기: $(du -h forticode_complete.tar.gz | cut -f1)"

# 서버에 파일 전송
echo "서버에 파일을 전송합니다..."
scp -P $SERVER_PORT forticode_complete.tar.gz $SERVER_USER@$SERVER_HOST:$SERVER_PATH/

# 서버에서 압축 해제 및 설정
echo "서버에서 압축을 해제하고 설정합니다..."
ssh -p $SERVER_PORT $SERVER_USER@$SERVER_HOST << 'EOF'
cd ~/forticode

# 기존 파일 백업 (있다면)
if [ -d "backend" ]; then
    echo "기존 backend 디렉토리를 백업합니다..."
    mv backend backend_backup_$(date +%Y%m%d_%H%M%S)
fi

# 새 파일 압축 해제
echo "새 파일을 압축 해제합니다..."
tar -xzf forticode_complete.tar.gz
rm forticode_complete.tar.gz

# Python 가상환경 생성/업데이트
if [ ! -d "venv" ]; then
    echo "Python 가상환경을 생성합니다..."
    python3 -m venv venv
else
    echo "기존 가상환경을 사용합니다..."
fi

source venv/bin/activate

# 의존성 설치
echo "의존성을 설치합니다..."
pip install --upgrade pip
pip install -r requirements.txt

# 환경 변수 파일 생성
if [ ! -f .env ]; then
    cp env.example .env
    echo "환경 변수 파일을 생성했습니다. .env 파일을 수정하여 API 키를 설정하세요."
    echo "필요한 환경 변수:"
    echo "  - OPENAI_API_KEY"
    echo "  - ANTHROPIC_API_KEY"
    echo "  - HUGGINGFACE_API_KEY (선택사항)"
fi

# RAG 인덱스 파일 권한 확인
echo "RAG 인덱스 파일 권한을 확인합니다..."
chmod 644 backend/rag/faiss_unified_index/*
chmod 644 backend/llm/faiss_unified_index/*

# 데이터베이스 파일 권한 확인
echo "데이터베이스 파일 권한을 확인합니다..."
chmod 644 backend/api/data/*

# 서비스 파일 생성
echo "시스템 서비스를 생성합니다..."
sudo tee /etc/systemd/system/forticode.service > /dev/null << 'SERVICE_EOF'
[Unit]
Description=FortiCode Security Analysis API (RAG + LLM)
After=network.target

[Service]
Type=exec
User=aiproject
WorkingDirectory=/home/aiproject/forticode
Environment=PATH=/home/aiproject/forticode/venv/bin
Environment=PYTHONPATH=/home/aiproject/forticode
ExecStart=/home/aiproject/forticode/venv/bin/python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# 서비스 활성화
echo "서비스를 활성화합니다..."
sudo systemctl daemon-reload
sudo systemctl enable forticode

# 기존 서비스 중지 (있다면)
if sudo systemctl is-active --quiet forticode; then
    echo "기존 서비스를 중지합니다..."
    sudo systemctl stop forticode
fi

# 새 서비스 시작
echo "새 서비스를 시작합니다..."
sudo systemctl start forticode

# 서비스 상태 확인
echo "서비스 상태를 확인합니다..."
sleep 3
sudo systemctl status forticode --no-pager

# API 테스트
echo "API가 정상적으로 작동하는지 테스트합니다..."
sleep 5
if curl -s http://localhost:8000/docs > /dev/null; then
    echo "✅ API가 정상적으로 작동합니다!"
    echo "📖 API 문서: http://localhost:8000/docs"
    echo "🔍 RAG 검색 엔드포인트: http://localhost:8000/rag/search"
    echo "🔒 보안 분석 엔드포인트: http://localhost:8000/security/analyze"
else
    echo "❌ API 시작에 문제가 있습니다. 로그를 확인하세요:"
    echo "sudo journalctl -u forticode -f"
fi

echo ""
echo "=== 배포 완료 ==="
echo "📁 프로젝트 위치: ~/forticode"
echo "🐍 Python 가상환경: ~/forticode/venv"
echo "🔧 서비스 관리:"
echo "  - 상태 확인: sudo systemctl status forticode"
echo "  - 로그 확인: sudo journalctl -u forticode -f"
echo "  - 서비스 재시작: sudo systemctl restart forticode"
echo "  - 서비스 중지: sudo systemctl stop forticode"
echo ""
echo "📊 포함된 기능:"
echo "  - RAG 검색 시스템 (FAISS 인덱스)"
echo "  - LLM 기반 패치 생성"
echo "  - 통합 보안 취약점 분석"
echo "  - CWE 데이터베이스"
echo "  - OWASP 치트시트"
EOF

echo ""
echo "🎉 FortiCode 완전 배포가 완료되었습니다!"
echo "서버에서 다음 명령어로 상태를 확인하세요:"
echo "sudo systemctl status forticode"
echo "curl http://localhost:8000/docs"

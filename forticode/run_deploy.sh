#!/bin/bash

# FortiCode 배포 실행 스크립트
echo "🚀 FortiCode 서버 배포를 시작합니다..."

# 스크립트 실행 권한 확인
chmod +x deploy_complete.sh
chmod +x server_env_setup.sh

# 배포 실행
echo "📦 완전 배포를 실행합니다..."
./deploy_complete.sh

echo ""
echo "✅ 배포가 완료되었습니다!"
echo ""
echo "🔧 다음 단계:"
echo "1. 서버에 SSH로 연결: ssh -p 7000 aiproject@128.134.233.158"
echo "2. 환경 설정 실행: cd ~/forticode && ./server_env_setup.sh"
echo "3. .env 파일에서 API 키 설정"
echo "4. 서비스 재시작: sudo systemctl restart forticode"
echo "5. 상태 확인: sudo systemctl status forticode"
echo ""
echo "🌐 API 접속: http://128.134.233.158:8000/docs"

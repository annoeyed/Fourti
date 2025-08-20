#!/usr/bin/env python3
"""
vulnbank 보안 분석 실행 스크립트
JSON 결과만 출력하여 다른 도구에서 활용할 수 있도록 합니다.
"""

import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# dotenv 로드
load_dotenv()

# 프로젝트 루트를 Python 경로에 추가
project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from forticode.backend.security.analysis.vulnbank_security_workflow import VulnbankSecurityWorkflow

def main():
    """메인 실행 함수"""
    # API 키 확인
    openai_api_key = os.getenv("OPENAI_API_KEY")
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    
    if not openai_api_key or not anthropic_api_key:
        print("Error: API keys are not configured.")
        print("Please set OPENAI_API_KEY and ANTHROPIC_API_KEY in your .env file")
        sys.exit(1)
    
    # 분석할 프로젝트 경로
    project_path = project_root / "vulntest_total" / "vulnbank"
    
    if not project_path.exists():
        print(f"Error: Project path not found: {project_path}")
        sys.exit(1)
    
    print(f"Starting security analysis for: {project_path}")
    
    try:
        # 워크플로우 초기화
        workflow = VulnbankSecurityWorkflow(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key
        )
        
        # 분석 실행
        report = workflow.analyze_source_directory(str(project_path))
        
        # JSON 결과만 출력 (stdout으로)
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        
    except Exception as e:
        error_report = {
            "error": str(e),
            "error_type": type(e).__name__,
            "status": "failed"
        }
        json.dump(error_report, sys.stdout, indent=2, ensure_ascii=False)
        sys.exit(1)

if __name__ == "__main__":
    main()

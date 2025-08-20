import unittest
import os
import json
from unittest.mock import MagicMock, patch

# dotenv 로드
from dotenv import load_dotenv
load_dotenv()

from forticode.backend.security.analysis.vulnbank_security_workflow import VulnbankSecurityWorkflow
from forticode.backend.security.analysis.sast_dast_schema import SecurityFinding, Severity
from pathlib import Path

class TestVulnbankSecurityWorkflow(unittest.TestCase):

    def setUp(self):
        """테스트 설정"""
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        
        # API 키가 없는 경우 테스트를 건너뛰도록 설정
        if not self.openai_api_key or not self.anthropic_api_key:
            self.skipTest("API keys are not configured.")
            
        self.workflow = VulnbankSecurityWorkflow(
            openai_api_key=self.openai_api_key,
            anthropic_api_key=self.anthropic_api_key
        )
        
        # 테스트할 프로젝트 경로 설정
        # 이 경로가 실제 `vulntest_total` 디렉토리를 가리키도록 해야 합니다.
        # 이 파일의 위치(forticode/backend/security/analysis)에서 상위 디렉토리로 이동해야 함
        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        self.test_project_path = str(base_dir / "vulntest_total" / "vulnbank")


    @patch('forticode.backend.security.analysis.llm_security_analyzer.LLMSecurityAnalyzer.analyze_code')
    @patch('forticode.backend.rag.rag_builder.RAGBuilder.search')
    def test_analyze_source_directory_mocked(self, mock_rag_search, mock_llm_analyze):
        """
        LLM과 RAG를 모의(mock)하여 소스 디렉토리 분석을 테스트합니다.
        """
        # 모의 응답 설정
        mock_rag_search.return_value = [{'content': 'Mocked RAG result for CWE-89'}]
        mock_llm_analyze.return_value = json.dumps([
            {
                "cwe_id": "CWE-89",
                "description": "Mocked SQL Injection",
                "line_number": 10,
                "evidence": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
                "severity": "High",
                "recommendation": "Use parameterized queries."
            }
        ])

        # 분석 실행
        report = self.workflow.analyze_source_directory(self.test_project_path)

        # 결과 검증
        self.assertIn("security_summary", report)
        self.assertEqual(report["security_summary"]["total_findings"], 1)
        self.assertEqual(report["security_summary"]["high_count"], 1)
        self.assertEqual(report["findings"][0]["cwe"], "CWE-89")
        print("\n--- Mocked Test Report ---")
        print(json.dumps(report, indent=2))

    def test_analyze_source_directory_real(self):
        """
        실제 LLM과 RAG를 사용하여 소스 디렉토리 분석을 통합 테스트합니다.
        (시간이 오래 걸릴 수 있습니다)
        """
        print(f"\n실제 분석 시작: {self.test_project_path}")
        
        # 분석 실행
        report = self.workflow.analyze_source_directory(self.test_project_path)

        # 결과 검증
        self.assertIsNotNone(report)
        self.assertIn("project_path", report)
        self.assertIn("security_summary", report)
        self.assertIn("findings", report)
        
        # 결과 출력
        print("\n--- 실제 분석 결과 ---")
        print(json.dumps(report, indent=2, ensure_ascii=False))
        
        # JSON 파일로 저장
        output_file = Path(__file__).parent.parent.parent.parent.parent / "vulnbank_security_analysis.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n결과가 JSON 파일로 저장되었습니다: {output_file}")
        
        # 적어도 하나의 결과가 있는지 확인 (프로젝트에 따라 달라질 수 있음)
        if report["security_summary"]["total_findings"] > 0:
            finding = report["findings"][0]
            self.assertIn("cwe", finding)
            self.assertIn("message", finding)
            self.assertIn("secure_coding_guide", finding)

if __name__ == '__main__':
    # 테스트 실행을 위한 메인 스크립트
    # 아래 코드는 `python -m unittest`로 실행할 때 필요 없음
    
    # 직접 이 파일을 실행하여 'test_analyze_source_directory_real'를 구동
    suite = unittest.TestSuite()
    suite.addTest(TestVulnbankSecurityWorkflow("test_analyze_source_directory_real"))
    runner = unittest.TextTestRunner()
    runner.run(suite)

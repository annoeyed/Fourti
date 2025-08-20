"""
RAG 기능이 통합된 리포트 생성기 사용 예제
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from rag.rag_builder import RAGBuilder
from rag.rag_search_adapter import RAGSearchAdapter
from security.analysis.report_generator import ReportGenerator
from security.analysis.sast_dast_schema import SecurityFinding, ScanResult, Severity, Language
from llm.patch_generator import PatchProposal

def create_sample_findings():
    """샘플 보안 발견 결과 생성"""
    findings = [
        SecurityFinding(
            finding_id="finding_001",
            rule_id="SQL_INJECTION_001",
            description="SQL Injection 취약점",
            severity=Severity.CRITICAL,
            language=Language.PYTHON,
            location={"file": "app/database.py", "line": 45},
            cwe="CWE-89",
            source="Bandit",
            evidence="user_input = request.args.get('id'); cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')",
            priority={"level": "HIGH", "score": 0.9},
            exploitability={"complexity": "LOW", "score": 0.8},
            remediation_effort={"time_required": "MEDIUM", "score": 0.6},
            false_positive_risk={"risk_level": "LOW", "score": 0.2}
        ),
        SecurityFinding(
            finding_id="finding_002",
            rule_id="XSS_001",
            description="Cross-Site Scripting 취약점",
            severity=Severity.HIGH,
            language=Language.JAVASCRIPT,
            location={"file": "frontend/app.js", "line": 23},
            cwe="CWE-79",
            source="ESLint",
            evidence="document.getElementById('output').innerHTML = userInput;",
            priority={"level": "HIGH", "score": 0.8},
            exploitability={"complexity": "MEDIUM", "score": 0.7},
            remediation_effort={"time_required": "LOW", "score": 0.4},
            false_positive_risk={"risk_level": "LOW", "score": 0.3}
        )
    ]
    return findings

def create_sample_patches():
    """샘플 패치 제안 생성"""
    patches = [
        PatchProposal(
            finding_id="finding_001",
            explanation="SQL Injection 방지를 위해 파라미터화된 쿼리 사용",
            confidence={"score": 0.95, "level": "HIGH"},
            test_coverage={"has_test": True, "coverage_percentage": 85.0},
            commit_info={
                "message": "Fix SQL injection vulnerability",
                "body": "Replace string concatenation with parameterized query"
            }
        )
    ]
    return patches

def main():
    """RAG 기능이 통합된 리포트 생성 예제"""
    print("🔍 RAG 기능이 통합된 보안 리포트 생성기 시작...")
    
    try:
        # 1. RAG 빌더 초기화
        print("📚 RAG 시스템 초기화 중...")
        rag_builder = RAGBuilder()
        
        # 2. RAG 검색 어댑터 생성
        print("🔍 RAG 검색 어댑터 생성 중...")
        rag_adapter = RAGSearchAdapter(rag_builder)
        
        # 3. RAG 기능이 통합된 리포트 생성기 생성
        print("📊 리포트 생성기 생성 중...")
        report_generator = ReportGenerator(rag_adapter=rag_adapter)
        
        # 4. 샘플 데이터 생성
        print("📝 샘플 데이터 생성 중...")
        findings = create_sample_findings()
        patches = create_sample_patches()
        
        scan_result = ScanResult(
            scan_id="scan_20241201_001",
            tool_results=findings,
            scan_metadata={
                "start_time": "2024-12-01T10:00:00Z",
                "end_time": "2024-12-01T10:30:00Z",
                "tools_used": ["Bandit", "ESLint"],
                "total_files_scanned": 150,
                "languages_detected": ["Python", "JavaScript"]
            }
        )
        
        # 5. RAG 기능이 포함된 리포트 생성
        print("🚀 RAG 기능이 포함된 리포트 생성 중...")
        report = report_generator.generate_report(scan_result, patches)
        
        # 6. 결과 출력
        print(f"\n✅ 리포트 생성 완료!")
        print(f"📋 리포트 ID: {report.report_id}")
        print(f"🔍 RAG 컨텍스트 활성화: {report.rag_context.get('enabled', False)}")
        print(f"📚 총 RAG 컨텍스트: {report.rag_context.get('total_contexts', 0)}개")
        print(f"📊 총 발견 결과: {report.summary['total_findings']}개")
        print(f"⚠️  전체 위험도 점수: {report.summary['overall_risk_score']:.2f}")
        
        # 7. RAG 컨텍스트 상세 정보 출력
        if report.rag_context.get("enabled") and report.rag_context.get("contexts"):
            print(f"\n🔍 RAG 컨텍스트 상세 정보:")
            for i, context in enumerate(report.rag_context["contexts"], 1):
                print(f"  {i}. {context['cwe_id']} - {len(context['rag_results'])}개 결과")
                if context.get('rag_results'):
                    top_result = context['rag_results'][0]
                    print(f"     최고 관련성: {top_result['name']} (점수: {top_result['relevance_score']:.1%})")
        
        # 8. 권장사항 출력
        print(f"\n💡 주요 권장사항:")
        for i, rec in enumerate(report.recommendations[:5], 1):
            print(f"  {i}. {rec}")
        
        # 9. 마크다운 형식으로 내보내기
        print(f"\n📄 마크다운 형식으로 내보내기 중...")
        markdown_report = report_generator.export_report(report, "markdown")
        
        # 마크다운 파일 저장
        output_file = "security_report_with_rag.md"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(markdown_report)
        
        print(f"💾 마크다운 리포트가 '{output_file}'에 저장되었습니다.")
        
        # 10. RAG 기능의 장점 설명
        print(f"\n🎯 RAG 기능의 장점:")
        print(f"  • 보안 취약점에 대한 풍부한 컨텍스트 제공")
        print(f"  • CWE 기반 구체적인 완화 방안 제시")
        print(f"  • 관련성 점수로 우선순위 결정 지원")
        print(f"  • 다국어 지원 및 도구별 최적화된 권장사항")
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

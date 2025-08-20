"""
설명 가능한 보안 리포트 생성기
FortiCode의 보안 분석 결과를 개발자가 이해하기 쉽게 설명하는 리포트 생성
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import json

from .sast_dast_schema import SecurityFinding, ScanResult, Severity
from ..llm.patch_generator import PatchProposal
from ...rag.rag_search_adapter import RAGSearchResult, RAGSearchAdapter

logger = logging.getLogger(__name__)

@dataclass
class SecurityReport:
    """보안 리포트 데이터 구조"""
    report_id: str
    scan_id: str
    generated_at: str
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    patches: List[Dict[str, Any]]
    recommendations: List[str]
    risk_assessment: Dict[str, Any]
    technical_details: Dict[str, Any]  # 기술적 세부사항
    security_trends: Dict[str, Any]    # 보안 트렌드 분석
    compliance_status: Dict[str, Any]  # 규정 준수 상태
    rag_context: Dict[str, Any]        # RAG 컨텍스트 정보

class ReportGenerator:
    """설명 가능한 보안 리포트 생성기"""
    
    def __init__(self, rag_adapter: Optional[RAGSearchAdapter] = None):
        self.severity_colors = {
            Severity.LOW: "🟢",
            Severity.MEDIUM: "🟡", 
            Severity.HIGH: "🟠",
            Severity.CRITICAL: "🔴"
        }
        self.rag_adapter = rag_adapter
    
    def generate_report(self, scan_result: ScanResult, patches: List[PatchProposal]) -> SecurityReport:
        """보안 리포트 생성"""
        try:
            # 1. 요약 정보 생성
            summary = self._generate_summary(scan_result, patches)
            
            # 2. 발견 결과 분석
            findings_analysis = self._analyze_findings(scan_result.tool_results)
            
            # 3. 패치 분석
            patches_analysis = self._analyze_patches(patches)
            
            # 4. RAG 컨텍스트 생성
            rag_context = self._generate_rag_context(scan_result.tool_results)
            
            # 5. 권장사항 생성 (RAG 컨텍스트 활용)
            recommendations = self._generate_recommendations(scan_result, patches, rag_context)
            
            # 6. 위험도 평가
            risk_assessment = self._assess_overall_risk(scan_result, patches)
            
            # 7. 기술적 세부사항 생성
            technical_details = self._generate_technical_details(scan_result, patches)
            
            # 8. 보안 트렌드 분석
            security_trends = self._analyze_security_trends(scan_result)
            
            # 9. 규정 준수 상태 평가
            compliance_status = self._assess_compliance_status(scan_result)
            
            # 10. 리포트 객체 생성
            report = SecurityReport(
                report_id=f"report_{scan_result.scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                scan_id=scan_result.scan_id,
                generated_at=datetime.now().isoformat(),
                summary=summary,
                findings=findings_analysis,
                patches=patches_analysis,
                recommendations=recommendations,
                risk_assessment=risk_assessment,
                technical_details=technical_details,
                security_trends=security_trends,
                compliance_status=compliance_status,
                rag_context=rag_context
            )
            
            return report
            
        except Exception as e:
            logger.error(f"리포트 생성 중 오류: {e}")
            raise
    
    def _generate_summary(self, scan_result: ScanResult, patches: List[PatchProposal]) -> Dict[str, Any]:
        """요약 정보 생성"""
        total_findings = len(scan_result.tool_results)
        critical_count = len([f for f in scan_result.tool_results if f.severity == Severity.CRITICAL])
        high_count = len([f for f in scan_result.tool_results if f.severity == Severity.HIGH])
        medium_count = len([f for f in scan_result.tool_results if f.severity == Severity.MEDIUM])
        low_count = len([f for f in scan_result.tool_results if f.severity == Severity.LOW])
        
        # 언어별 분포
        language_distribution = {}
        for finding in scan_result.tool_results:
            lang = finding.language.value if finding.language else "unknown"
            language_distribution[lang] = language_distribution.get(lang, 0) + 1
        
        # CWE별 분포
        cwe_distribution = {}
        for finding in scan_result.tool_results:
            if finding.cwe:
                cwe_distribution[finding.cwe] = cwe_distribution.get(finding.cwe, 0) + 1
        
        return {
            "total_findings": total_findings,
            "severity_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "language_distribution": language_distribution,
            "cwe_distribution": cwe_distribution,
            "patches_generated": len(patches),
            "overall_risk_score": self._calculate_overall_risk_score(scan_result)
        }
    
    def _analyze_findings(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """발견 결과 분석"""
        findings_analysis = []
        
        for finding in findings:
            finding_analysis = {
                "finding_id": finding.finding_id,
                "source": finding.source,
                "tool_type": finding.tool.value if finding.tool else "unknown",
                "rule_id": finding.rule_id,
                "severity": {
                    "level": finding.severity.value,
                    "color": self.severity_colors.get(finding.severity, "⚪"),
                    "numeric_score": self._severity_to_numeric(finding.severity)
                },
                "language": finding.language.value if finding.language else "unknown",
                "location": {
                    "file": finding.file_path,
                    "line": finding.line_number,
                    "endpoint": finding.endpoint,
                    "function_context": self._extract_function_context(finding)
                },
                "description": finding.message,
                "evidence": finding.evidence,
                "cwe": finding.cwe,
                "priority": self._calculate_finding_priority(finding),
                "business_impact": self._assess_business_impact(finding),
                "exploitability": self._assess_exploitability(finding),
                "remediation_effort": self._estimate_remediation_effort(finding),
                "false_positive_risk": self._assess_false_positive_risk(finding),
                "related_findings": self._find_related_findings(finding, findings)
            }
            
            findings_analysis.append(finding_analysis)
        
        # 우선순위별로 정렬
        findings_analysis.sort(key=lambda x: x["priority"]["score"], reverse=True)
        
        return findings_analysis
    
    def _analyze_patches(self, patches: List[PatchProposal]) -> List[Dict[str, Any]]:
        """패치 분석"""
        patches_analysis = []
        
        for patch in patches:
            patch_analysis = {
                "finding_id": patch.finding_id,
                "explanation": patch.explanation,
                "confidence": {
                    "score": patch.confidence,
                    "level": self._get_confidence_level(patch.confidence)
                },
                "risk_assessment": patch.risk_assessment,
                "test_coverage": {
                    "has_test": bool(patch.test_snippet),
                    "test_snippet": patch.test_snippet
                },
                "commit_info": {
                    "message": patch.commit_message,
                    "body": patch.commit_body
                }
            }
            
            patches_analysis.append(patch_analysis)
        
        # 신뢰도별로 정렬
        patches_analysis.sort(key=lambda x: x["confidence"]["score"], reverse=True)
        
        return patches_analysis
    
    def _generate_rag_context(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """RAG를 사용하여 보안 컨텍스트 생성"""
        if not self.rag_adapter:
            return {"enabled": False, "contexts": []}
        
        try:
            rag_contexts = []
            
            for finding in findings:
                # RAG 검색으로 보안 컨텍스트 가져오기
                rag_results = self.rag_adapter.search_security_context(finding)
                
                if rag_results:
                    context = {
                        "finding_id": finding.finding_id,
                        "cwe_id": finding.cwe,
                        "rag_results": [
                            {
                                "cwe_id": result.cwe_id,
                                "name": result.name,
                                "excerpt": result.excerpt,
                                "relevance_score": result.relevance_score,
                                "source": result.source,
                                "languages": result.languages,
                                "mitigations": result.mitigations
                            }
                            for result in rag_results
                        ]
                    }
                    rag_contexts.append(context)
            
            return {
                "enabled": True,
                "total_contexts": len(rag_contexts),
                "contexts": rag_contexts
            }
            
        except Exception as e:
            logger.error(f"RAG 컨텍스트 생성 중 오류: {e}")
            return {"enabled": False, "error": str(e), "contexts": []}
    
    def _generate_recommendations(self, scan_result: ScanResult, patches: List[PatchProposal], rag_context: Dict[str, Any]) -> List[str]:
        """권장사항 생성 (RAG 컨텍스트 활용)"""
        recommendations = []
        
        # 기본 권장사항
        if scan_result.tool_results:
            critical_findings = [f for f in scan_result.tool_results if f.severity == Severity.CRITICAL]
            if critical_findings:
                recommendations.append("🔴 Critical 취약점을 즉시 수정하세요. 이는 시스템 보안에 심각한 위협이 됩니다.")
            
            high_findings = [f for f in scan_result.tool_results if f.severity == Severity.HIGH]
            if high_findings:
                recommendations.append("🟠 High 취약점을 우선적으로 수정하세요. 이는 악용 가능성이 높습니다.")
        
        # RAG 기반 구체적 권장사항
        if rag_context.get("enabled") and rag_context.get("contexts"):
            for context in rag_context["contexts"]:
                if context.get("rag_results"):
                    # 가장 관련성 높은 RAG 결과 사용
                    top_result = max(context["rag_results"], key=lambda x: x["relevance_score"])
                    
                    if top_result["relevance_score"] > 0.7:  # 높은 관련성
                        cwe_name = top_result["name"]
                        mitigations = top_result["mitigations"]
                        
                        if mitigations:
                            # 구체적인 완화 방안 제시
                            for mitigation in mitigations[:2]:  # 상위 2개만
                                recommendations.append(f"📚 {cwe_name}: {mitigation}")
        
        # 패치 관련 권장사항
        if patches:
            high_confidence_patches = [p for p in patches if p.confidence.score > 0.8]
            if high_confidence_patches:
                recommendations.append("✅ 높은 신뢰도의 자동 생성 패치를 검토하고 적용하세요.")
        
        # 일반적인 보안 모범 사례
        recommendations.extend([
            "🔒 정기적인 보안 스캔을 수행하여 새로운 취약점을 조기에 발견하세요.",
            "📖 OWASP Top 10 가이드라인을 참고하여 보안 코딩을 실천하세요.",
            "🧪 수정 후 반드시 테스트를 수행하여 기존 기능이 정상 작동하는지 확인하세요."
        ])
        
        return recommendations[:10]  # 최대 10개로 제한
    
    def _assess_overall_risk(self, scan_result: ScanResult, patches: List[PatchProposal]) -> Dict[str, Any]:
        """전체 위험도 평가"""
        risk_score = self._calculate_overall_risk_score(scan_result)
        
        # 위험도 등급
        if risk_score >= 0.8:
            risk_level = "CRITICAL"
            risk_description = "치명적 위험 - 즉시 조치 필요"
        elif risk_score >= 0.6:
            risk_level = "HIGH"
            risk_description = "높은 위험 - 신속한 조치 필요"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
            risk_description = "중간 위험 - 계획적 조치 필요"
        else:
            risk_level = "LOW"
            risk_description = "낮은 위험 - 모니터링 필요"
        
        return {
            "overall_score": risk_score,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "immediate_actions_required": risk_score >= 0.6
        }
    
    # 헬퍼 메서드들
    
    def _calculate_finding_priority(self, finding: SecurityFinding) -> Dict[str, Any]:
        """발견 결과의 우선순위 계산"""
        severity_scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 80,
            Severity.MEDIUM: 50,
            Severity.LOW: 20
        }
        
        base_score = severity_scores.get(finding.severity, 50)
        
        # CWE가 있으면 추가 점수
        if finding.cwe:
            base_score += 10
        
        # 우선순위 등급
        if base_score >= 90:
            priority_level = "CRITICAL"
        elif base_score >= 70:
            priority_level = "HIGH"
        elif base_score >= 50:
            priority_level = "MEDIUM"
        else:
            priority_level = "LOW"
        
        return {
            "score": base_score,
            "level": priority_level
        }
    
    def _assess_business_impact(self, finding: SecurityFinding) -> str:
        """비즈니스 영향도 평가"""
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            return "HIGH"
        elif finding.severity == Severity.MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_confidence_level(self, confidence: float) -> str:
        """신뢰도 등급 반환"""
        if confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_overall_risk_score(self, scan_result: ScanResult) -> float:
        """전체 위험도 점수 계산"""
        if not scan_result.tool_results:
            return 0.0
        
        total_score = 0.0
        max_possible_score = 0.0
        
        for finding in scan_result.tool_results:
            severity_weights = {
                Severity.CRITICAL: 1.0,
                Severity.HIGH: 0.8,
                Severity.MEDIUM: 0.5,
                Severity.LOW: 0.2
            }
            
            weight = severity_weights.get(finding.severity, 0.5)
            total_score += weight
            max_possible_score += 1.0
        
        return total_score / max_possible_score if max_possible_score > 0 else 0.0
    
    # 새로운 분석 메서드들
    
    def _severity_to_numeric(self, severity: Severity) -> int:
        """심각도를 숫자 점수로 변환"""
        severity_scores = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1
        }
        return severity_scores.get(severity, 2)
    
    def _extract_function_context(self, finding: SecurityFinding) -> Dict[str, Any]:
        """함수 컨텍스트 정보 추출"""
        if not finding.file_path or not finding.line_number:
            return {"function_name": "unknown", "class_name": "unknown"}
        
        # 실제 구현에서는 파일을 읽어서 함수/클래스 컨텍스트를 파싱
        # 여기서는 기본값 반환
        return {
            "function_name": "unknown",
            "class_name": "unknown",
            "scope": "unknown"
        }
    
    def _assess_exploitability(self, finding: SecurityFinding) -> Dict[str, Any]:
        """취약점의 악용 가능성 평가"""
        exploitability_factors = {
            "complexity": "unknown",
            "authentication_required": False,
            "user_interaction_required": False,
            "attack_vector": "unknown"
        }
        
        # CWE 기반 악용 가능성 평가
        if finding.cwe:
            if "CWE-89" in finding.cwe:  # SQL Injection
                exploitability_factors.update({
                    "complexity": "low",
                    "authentication_required": False,
                    "user_interaction_required": True,
                    "attack_vector": "web"
                })
            elif "CWE-79" in finding.cwe:  # XSS
                exploitability_factors.update({
                    "complexity": "low",
                    "authentication_required": False,
                    "user_interaction_required": True,
                    "attack_vector": "web"
                })
        
        return exploitability_factors
    
    def _estimate_remediation_effort(self, finding: SecurityFinding) -> Dict[str, Any]:
        """수정 노력 추정"""
        effort_estimation = {
            "time_required": "unknown",
            "complexity": "unknown",
            "resources_needed": "unknown"
        }
        
        # 심각도 기반 노력 추정
        if finding.severity == Severity.CRITICAL:
            effort_estimation.update({
                "time_required": "4-8 hours",
                "complexity": "high",
                "resources_needed": "senior developer + security review"
            })
        elif finding.severity == Severity.HIGH:
            effort_estimation.update({
                "time_required": "2-4 hours",
                "complexity": "medium",
                "resources_needed": "developer + testing"
            })
        elif finding.severity == Severity.MEDIUM:
            effort_estimation.update({
                "time_required": "1-2 hours",
                "complexity": "low",
                "resources_needed": "developer"
            })
        else:
            effort_estimation.update({
                "time_required": "30 minutes - 1 hour",
                "complexity": "very low",
                "resources_needed": "developer"
            })
        
        return effort_estimation
    
    def _assess_false_positive_risk(self, finding: SecurityFinding) -> Dict[str, Any]:
        """거짓 양성 위험도 평가"""
        false_positive_indicators = {
            "risk_level": "unknown",
            "confidence": "unknown",
            "indicators": []
        }
        
        # 도구별 거짓 양성 위험도
        if finding.source == "bandit":
            if finding.rule_id in ["B101", "B102"]:  # assert_used, exec_used
                false_positive_indicators.update({
                    "risk_level": "medium",
                    "confidence": "medium",
                    "indicators": ["개발/테스트 환경에서만 사용", "의도적인 사용 가능성"]
                })
        
        return false_positive_indicators
    
    def _find_related_findings(self, finding: SecurityFinding, all_findings: List[SecurityFinding]) -> List[str]:
        """관련된 발견 결과 찾기"""
        related_ids = []
        
        for other_finding in all_findings:
            if other_finding.finding_id == finding.finding_id:
                continue
            
            # 같은 파일의 다른 라인
            if (other_finding.file_path == finding.file_path and 
                other_finding.rule_id == finding.rule_id):
                related_ids.append(other_finding.finding_id)
            
            # 같은 CWE
            elif other_finding.cwe == finding.cwe:
                related_ids.append(other_finding.finding_id)
        
        return related_ids[:3]  # 최대 3개
    
    def _generate_technical_details(self, scan_result: ScanResult, patches: List[PatchProposal]) -> Dict[str, Any]:
        """기술적 세부사항 생성"""
        technical_details = {
            "scan_coverage": self._analyze_scan_coverage(scan_result),
            "tool_effectiveness": self._analyze_tool_effectiveness(scan_result),
            "code_complexity_analysis": self._analyze_code_complexity(scan_result),
            "dependency_analysis": self._analyze_dependencies(scan_result),
            "architecture_insights": self._analyze_architecture_patterns(scan_result)
        }
        return technical_details
    
    def _analyze_scan_coverage(self, scan_result: ScanResult) -> Dict[str, Any]:
        """스캔 커버리지 분석"""
        total_files = len(set(f.file_path for f in scan_result.tool_results if f.file_path))
        languages_scanned = set(f.language.value for f in scan_result.tool_results if f.language)
        
        return {
            "total_files_scanned": total_files,
            "languages_covered": list(languages_scanned),
            "coverage_percentage": "unknown",  # 실제 구현에서는 전체 파일 수 대비 계산
            "unscanned_areas": []
        }
    
    def _analyze_tool_effectiveness(self, scan_result: ScanResult) -> Dict[str, Any]:
        """도구별 효과성 분석"""
        tool_stats = {}
        
        for finding in scan_result.tool_results:
            tool = finding.source
            if tool not in tool_stats:
                tool_stats[tool] = {
                    "findings_count": 0,
                    "severity_distribution": {},
                    "false_positive_estimate": 0.0
                }
            
            tool_stats[tool]["findings_count"] += 1
            
            sev = finding.severity.value
            tool_stats[tool]["severity_distribution"][sev] = tool_stats[tool]["severity_distribution"].get(sev, 0) + 1
        
        # 도구별 효과성 점수 계산
        for tool, stats in tool_stats.items():
            total_findings = stats["findings_count"]
            high_critical_count = sum(
                count for sev, count in stats["severity_distribution"].items() 
                if sev in ["high", "critical"]
            )
            
            # 높은 심각도 발견 비율로 효과성 점수 계산
            effectiveness_score = (high_critical_count / total_findings) if total_findings > 0 else 0.0
            stats["effectiveness_score"] = round(effectiveness_score, 2)
        
        return tool_stats
    
    def _analyze_code_complexity(self, scan_result: ScanResult) -> Dict[str, Any]:
        """코드 복잡도 분석"""
        complexity_analysis = {
            "high_complexity_files": [],
            "cyclomatic_complexity_estimate": "unknown",
            "maintainability_index": "unknown"
        }
        
        # 파일별 발견 결과 수로 복잡도 추정
        file_finding_counts = {}
        for finding in scan_result.tool_results:
            if finding.file_path:
                file_finding_counts[finding.file_path] = file_finding_counts.get(finding.file_path, 0) + 1
        
        # 발견 결과가 많은 파일을 복잡한 파일로 간주
        high_complexity_threshold = 5
        high_complexity_files = [
            file_path for file_path, count in file_finding_counts.items() 
            if count >= high_complexity_threshold
        ]
        
        complexity_analysis["high_complexity_files"] = high_complexity_files[:10]  # 상위 10개
        
        return complexity_analysis
    
    def _analyze_dependencies(self, scan_result: ScanResult) -> Dict[str, Any]:
        """의존성 분석"""
        return {
            "external_libraries": [],
            "known_vulnerabilities": [],
            "license_risks": [],
            "update_recommendations": []
        }
    
    def _analyze_architecture_patterns(self, scan_result: ScanResult) -> Dict[str, Any]:
        """아키텍처 패턴 분석"""
        return {
            "identified_patterns": [],
            "security_implications": [],
            "improvement_suggestions": []
        }
    
    def _analyze_security_trends(self, scan_result: ScanResult) -> Dict[str, Any]:
        """보안 트렌드 분석"""
        trends = {
            "common_vulnerability_patterns": self._identify_common_patterns(scan_result),
            "emerging_threats": self._identify_emerging_threats(scan_result),
            "historical_comparison": "데이터 부족",  # 실제 구현에서는 이전 스캔과 비교
            "industry_benchmarks": "데이터 부족"    # 실제 구현에서는 업계 평균과 비교
        }
        return trends
    
    def _identify_common_patterns(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """일반적인 취약점 패턴 식별"""
        patterns = []
        
        # CWE별 빈도 분석
        cwe_frequency = {}
        for finding in scan_result.tool_results:
            if finding.cwe:
                cwe_frequency[finding.cwe] = cwe_frequency.get(finding.cwe, 0) + 1
        
        # 빈도순으로 정렬하여 상위 패턴 식별
        sorted_cwes = sorted(cwe_frequency.items(), key=lambda x: x[1], reverse=True)
        
        for cwe_id, frequency in sorted_cwes[:5]:  # 상위 5개
            patterns.append({
                "cwe_id": cwe_id,
                "frequency": frequency,
                "percentage": round((frequency / len(scan_result.tool_results)) * 100, 1),
                "risk_level": self._get_cwe_risk_level(cwe_id)
            })
        
        return patterns
    
    def _identify_emerging_threats(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """새로운 위협 요소 식별"""
        emerging_threats = []
        
        # 최근에 추가된 CWE나 새로운 패턴 식별
        # 실제 구현에서는 시간 기반 분석 필요
        
        return emerging_threats
    
    def _get_cwe_risk_level(self, cwe_id: str) -> str:
        """CWE ID 기반 위험도 레벨 반환"""
        high_risk_cwes = ["CWE-89", "CWE-79", "CWE-78", "CWE-434", "CWE-287"]
        medium_risk_cwes = ["CWE-259", "CWE-327", "CWE-338", "CWE-295"]
        
        if cwe_id in high_risk_cwes:
            return "HIGH"
        elif cwe_id in medium_risk_cwes:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_compliance_status(self, scan_result: ScanResult) -> Dict[str, Any]:
        """규정 준수 상태 평가"""
        compliance_status = {
            "owasp_top_10": self._assess_owasp_compliance(scan_result),
            "cwe_sans_top_25": self._assess_cwe_sans_compliance(scan_result),
            "industry_standards": self._assess_industry_standards(scan_result),
            "overall_compliance_score": 0.0
        }
        
        # 전체 준수 점수 계산
        total_checks = 0
        passed_checks = 0
        
        for category, status in compliance_status.items():
            if category != "overall_compliance_score" and isinstance(status, dict):
                if "status" in status:
                    total_checks += 1
                    if status["status"] == "compliant":
                        passed_checks += 1
        
        if total_checks > 0:
            compliance_status["overall_compliance_score"] = round(passed_checks / total_checks, 2)
        
        return compliance_status
    
    def _assess_owasp_compliance(self, scan_result: ScanResult) -> Dict[str, Any]:
        """OWASP Top 10 준수 상태 평가"""
        owasp_categories = {
            "A01:2021 - Broken Access Control": ["CWE-200", "CWE-201", "CWE-202"],
            "A02:2021 - Cryptographic Failures": ["CWE-259", "CWE-327", "CWE-331"],
            "A03:2021 - Injection": ["CWE-89", "CWE-78", "CWE-79"],
            "A04:2021 - Insecure Design": ["CWE-209", "CWE-213", "CWE-400"],
            "A05:2021 - Security Misconfiguration": ["CWE-16", "CWE-2", "CWE-400"]
        }
        
        compliance_results = {}
        
        for category, cwe_list in owasp_categories.items():
            findings_in_category = [
                f for f in scan_result.tool_results 
                if f.cwe and any(cwe in f.cwe for cwe in cwe_list)
            ]
            
            if findings_in_category:
                compliance_results[category] = {
                    "status": "non_compliant",
                    "findings_count": len(findings_in_category),
                    "severity": max(f.severity.value for f in findings_in_category),
                    "description": f"{len(findings_in_category)}개 취약점 발견"
                }
            else:
                compliance_results[category] = {
                    "status": "compliant",
                    "findings_count": 0,
                    "description": "준수"
                }
        
        return compliance_results
    
    def _assess_cwe_sans_compliance(self, scan_result: ScanResult) -> Dict[str, Any]:
        """CWE/SANS Top 25 준수 상태 평가"""
        # CWE/SANS Top 25 카테고리별 평가
        # 실제 구현에서는 더 상세한 매핑 필요
        return {
            "status": "assessment_needed",
            "description": "CWE/SANS Top 25 평가를 위한 추가 분석 필요"
        }
    
    def _assess_industry_standards(self, scan_result: ScanResult) -> Dict[str, Any]:
        """업계 표준 준수 상태 평가"""
        return {
            "iso_27001": "assessment_needed",
            "nist_cybersecurity_framework": "assessment_needed",
            "pci_dss": "assessment_needed"
        }
    
    def export_report(self, report: SecurityReport, format: str = "json") -> str:
        """리포트를 지정된 형식으로 내보내기"""
        if format.lower() == "json":
            return json.dumps(report.__dict__, indent=2, ensure_ascii=False)
        elif format.lower() == "markdown":
            return self._export_markdown(report)
        elif format.lower() == "html":
            return self._export_html(report)
        elif format.lower() == "csv":
            return self._export_csv(report)
        else:
            raise ValueError(f"지원하지 않는 형식: {format}")
    
    def _export_html(self, report: SecurityReport) -> str:
        """HTML 형식으로 내보내기"""
        html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiCode 보안 분석 리포트</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .finding {{ border-left: 4px solid #007bff; padding: 10px; margin: 10px 0; background-color: #f8f9fa; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-card {{ background-color: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; min-width: 200px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>FortiCode 보안 분석 리포트</h1>
        <p><strong>리포트 ID:</strong> {report.report_id}</p>
        <p><strong>스캔 ID:</strong> {report.scan_id}</p>
        <p><strong>생성 시간:</strong> {report.generated_at}</p>
    </div>
    
    <div class="section">
        <h2>요약</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>총 발견 결과</h3>
                <p>{report.summary['total_findings']}개</p>
            </div>
            <div class="stat-card">
                <h3>전체 위험도 점수</h3>
                <p>{report.summary['overall_risk_score']:.2f}</p>
            </div>
            <div class="stat-card">
                <h3>패치 생성</h3>
                <p>{report.summary['patches_generated']}개</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>주요 발견 결과</h2>
"""
        
        for finding in report.findings[:5]:
            severity_class = finding['severity']['level'].lower()
            html += f"""
        <div class="finding {severity_class}">
            <h3>{finding['rule_id']} - {finding['description']}</h3>
            <p><strong>파일:</strong> {finding['location']['file'] or 'N/A'}</p>
            <p><strong>라인:</strong> {finding['location']['line'] or 'N/A'}</p>
            <p><strong>심각도:</strong> {finding['severity']['level']}</p>
            <p><strong>CWE:</strong> {finding['cwe'] or 'N/A'}</p>
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>위험도 평가</h2>
        <p><strong>전체 위험도:</strong> """ + report.risk_assessment['risk_level'] + """</p>
        <p><strong>설명:</strong> """ + report.risk_assessment['risk_description'] + """</p>
    </div>
"""
        
        # RAG 컨텍스트 섹션 추가
        if report.rag_context.get("enabled"):
            html += """
    <div class="section">
        <h2>🔍 RAG 보안 컨텍스트</h2>
        <p><strong>총 컨텍스트:</strong> """ + str(report.rag_context['total_contexts']) + """개</p>
"""
            
            for context in report.rag_context['contexts']:
                if context.get('rag_results'):
                    top_result = context['rag_results'][0]
                    html += f"""
        <div class="finding">
            <h3>{context['cwe_id']} - {top_result['name']}</h3>
            <p><strong>관련성 점수:</strong> {top_result['relevance_score']:.1%}</p>
            <p><strong>출처:</strong> {top_result['source']}</p>
            <p><strong>적용 언어:</strong> {', '.join(top_result['languages']) if top_result['languages'] else 'N/A'}</p>
            <p><strong>요약:</strong> {top_result['excerpt']}</p>
            <p><strong>완화 방안:</strong></p>
            <ul>
"""
                    
                    for mitigation in top_result['mitigations'][:3]:
                        html += f"                <li>{mitigation}</li>\n"
                    
                    html += """
            </ul>
        </div>
"""
            
            html += """
    </div>
"""
        
        html += """
</body>
</html>"""
        
        return html
    
    def _export_csv(self, report: SecurityReport) -> str:
        """CSV 형식으로 내보내기"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # 헤더
        writer.writerow([
            'Finding ID', 'Rule ID', 'Description', 'Severity', 'Language', 
            'File Path', 'Line Number', 'CWE', 'Source', 'Priority'
        ])
        
        # 데이터
        for finding in report.findings:
            writer.writerow([
                finding['finding_id'],
                finding['rule_id'],
                finding['description'],
                finding['severity']['level'],
                finding['language'],
                finding['location']['file'] or '',
                finding['location']['line'] or '',
                finding['cwe'] or '',
                finding['source'],
                finding['priority']['level']
            ])
        
        return output.getvalue()
    
    def _export_markdown(self, report: SecurityReport) -> str:
        """마크다운 형식으로 내보내기"""
        md = f"""# FortiCode 보안 분석 리포트

**리포트 ID**: {report.report_id}  
**스캔 ID**: {report.scan_id}  
**생성 시간**: {report.generated_at}

## 요약

- **총 발견 결과**: {report.summary['total_findings']}개
- **전체 위험도 점수**: {report.summary['overall_risk_score']:.2f}
- **패치 생성**: {report.summary['patches_generated']}개

### 심각도별 분포
"""
        
        for sev, count in report.summary['severity_distribution'].items():
            if count > 0:
                md += f"- **{sev.upper()}**: {count}개\n"
        
        md += f"""
### 언어별 분포
"""
        
        for lang, count in report.summary['language_distribution'].items():
            if count > 0:
                md += f"- **{lang}**: {count}개\n"
        
        md += f"""
## 주요 발견 결과

"""
        
        for finding in report.findings[:5]:  # 상위 5개만
            sev = finding['severity']
            md += f"""### {finding['rule_id']} - {finding['description']}

- **파일**: {finding['location']['file'] or 'N/A'}
- **라인**: {finding['location']['line'] or 'N/A'}
- **심각도**: {sev['level']}
- **우선순위**: {finding['priority']['level']}
- **CWE**: {finding['cwe'] or 'N/A'}
- **도구**: {finding['source']}

**증거:**
```
{finding['evidence']}
```

**기술적 세부사항:**
- 악용 가능성: {finding['exploitability']['complexity']}
- 수정 노력: {finding['remediation_effort']['time_required']}
- 거짓 양성 위험: {finding['false_positive_risk']['risk_level']}

"""
        
        md += f"""
## 패치 제안

"""
        
        for patch in report.patches[:3]:  # 상위 3개만
            conf = patch['confidence']
            md += f"""### {patch['finding_id']} - {conf['level']}

- **설명**: {patch['explanation']}
- **신뢰도**: {conf['score']:.1%}
- **테스트 커버리지**: {'있음' if patch['test_coverage']['has_test'] else '없음'}

**커밋 정보:**
- 메시지: {patch['commit_info']['message']}
- 본문: {patch['commit_info']['body']}

"""
        
        md += f"""
## 기술적 세부사항

### 스캔 커버리지
- **스캔된 파일 수**: {report.technical_details['scan_coverage']['total_files_scanned']}
- **언어 커버리지**: {', '.join(report.technical_details['scan_coverage']['languages_covered'])}

### 도구별 효과성
"""
        
        for tool, stats in report.technical_details['tool_effectiveness'].items():
            md += f"- **{tool}**: {stats['findings_count']}개 발견, 효과성 점수: {stats['effectiveness_score']}\n"
        
        md += f"""
### 코드 복잡도 분석
- **고복잡도 파일**: {len(report.technical_details['code_complexity_analysis']['high_complexity_files'])}개

## 보안 트렌드

### 일반적인 취약점 패턴
"""
        
        for pattern in report.security_trends['common_vulnerability_patterns']:
            md += f"- **{pattern['cwe_id']}**: {pattern['frequency']}회 ({pattern['percentage']}%), 위험도: {pattern['risk_level']}\n"
        
        # RAG 컨텍스트 섹션 추가
        if report.rag_context.get("enabled"):
            md += f"""
## 🔍 RAG 보안 컨텍스트

**총 컨텍스트**: {report.rag_context['total_contexts']}개

"""
            
            for context in report.rag_context['contexts']:
                if context.get('rag_results'):
                    top_result = context['rag_results'][0]  # 가장 관련성 높은 결과
                    md += f"""### {context['cwe_id']} - {top_result['name']}

**관련성 점수**: {top_result['relevance_score']:.1%}  
**출처**: {top_result['source']}  
**적용 언어**: {', '.join(top_result['languages']) if top_result['languages'] else 'N/A'}

**요약**:
{top_result['excerpt']}

**완화 방안**:
"""
                    
                    for i, mitigation in enumerate(top_result['mitigations'][:3], 1):
                        md += f"{i}. {mitigation}\n"
                    
                    md += "\n"
        
        md += f"""
## 규정 준수 상태

### OWASP Top 10 준수
"""
        
        for category, status in report.compliance_status['owasp_top_10'].items():
            if status['status'] == 'compliant':
                md += f"- ✅ {category}: {status['description']}\n"
            else:
                md += f"- ❌ {category}: {status['description']}\n"
        
        md += f"""
**전체 준수 점수**: {report.compliance_status['overall_compliance_score']:.1%}

## 권장사항

"""
        
        for rec in report.recommendations:
            md += f"- {rec}\n"
        
        md += f"""
## 위험도 평가

**전체 위험도**: {report.risk_assessment['risk_level']}  
**설명**: {report.risk_assessment['risk_description']}  
**즉시 조치 필요**: {'예' if report.risk_assessment['immediate_actions_required'] else '아니오'}

---
*이 리포트는 FortiCode 자동 보안 분석 시스템에 의해 생성되었습니다.*
"""
        
        return md

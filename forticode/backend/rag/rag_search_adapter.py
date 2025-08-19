"""
RAG 검색 어댑터
SAST/DAST 결과를 기반으로 CWE 정보를 검색하고 보안 컨텍스트를 제공
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import re

from .rag_builder import RAGBuilder
from ..security.analysis.sast_dast_schema import SecurityFinding, Language

logger = logging.getLogger(__name__)

@dataclass
class RAGSearchResult:
    """RAG 검색 결과"""
    cwe_id: str                    # CWE ID
    name: str                       # CWE 이름
    excerpt: str                    # 요약 내용 (200~700자)
    relevance_score: float          # 관련성 점수
    source: str                     # 출처 (CWE/OWASP)
    languages: List[str]            # 적용 가능한 언어
    mitigations: List[str]          # 완화 방안

class RAGSearchAdapter:
    """SAST/DAST 결과와 RAG를 연동하는 검색 어댑터"""
    
    def __init__(self, rag_builder: RAGBuilder):
        self.rag_builder = rag_builder
        self.vector_store = rag_builder.vector_store
        
    def search_security_context(self, finding: SecurityFinding) -> List[RAGSearchResult]:
        """
        보안 취약점에 대한 컨텍스트 검색
        
        Args:
            finding: SAST/DAST에서 발견된 보안 이슈
            
        Returns:
            RAG 검색 결과 리스트 (최대 3개)
        """
        try:
            # 1. CWE가 있으면 정합 검색
            if finding.cwe:
                results = self._exact_cwe_search(finding.cwe)
                if results:
                    return results[:3]
            
            # 2. CWE가 없거나 검색 결과가 부족하면 하이브리드 검색
            return self._hybrid_search(finding)[:3]
            
        except Exception as e:
            logger.error(f"RAG 검색 중 오류 발생: {e}")
            return []
    
    def _exact_cwe_search(self, cwe_id: str) -> List[RAGSearchResult]:
        """CWE ID로 정확한 검색"""
        try:
            # CWE ID 정규화 (CWE-89 -> CWE-89)
            if not cwe_id.startswith('CWE-'):
                cwe_id = f"CWE-{cwe_id}"
            
            # 메타데이터에서 CWE ID로 검색
            if self.vector_store:
                # CWE ID로 직접 검색
                query = cwe_id
                docs = self.vector_store.similarity_search(
                    query, 
                    k=3,
                    filter={"cwe_id": cwe_id}
                )
                
                results = []
                for doc in docs:
                    # CWE 정보 추출
                    cwe_id_from_doc = doc.metadata.get('cwe_id', '')
                    if cwe_id_from_doc == cwe_id:
                        excerpt = self._extract_excerpt(doc.page_content, 500)
                        results.append(RAGSearchResult(
                            cwe_id=cwe_id_from_doc,
                            name=doc.metadata.get('name', 'Unknown'),
                            excerpt=excerpt,
                            relevance_score=1.0,  # 정합 검색이므로 최고 점수
                            source=doc.metadata.get('source', 'CWE'),
                            languages=doc.metadata.get('languages', []),
                            mitigations=self._extract_mitigations(doc.page_content)
                        ))
                
                return results
                
        except Exception as e:
            logger.error(f"CWE 정합 검색 중 오류: {e}")
        
        return []
    
    def _hybrid_search(self, finding: SecurityFinding) -> List[RAGSearchResult]:
        """하이브리드 검색 (메시지 + 규칙 + 언어 기반)"""
        try:
            if not self.vector_store:
                return []
            
            # 검색 쿼리 구성
            query_parts = []
            
            # 1. 메시지에서 핵심 키워드 추출
            message_keywords = self._extract_keywords(finding.message)
            query_parts.extend(message_keywords)
            
            # 2. 규칙 ID에서 패턴 추출
            rule_keywords = self._extract_keywords(finding.rule_id)
            query_parts.extend(rule_keywords)
            
            # 3. 언어 정보 추가
            if finding.language:
                query_parts.append(finding.language.value)
            
            # 4. 심각도 기반 보안 카테고리 추가
            if finding.severity.value in ['high', 'critical']:
                query_parts.extend(['vulnerability', 'security', 'exploit'])
            
            # 검색 쿼리 생성
            search_query = " ".join(query_parts)
            
            # 벡터 검색 수행
            docs = self.vector_store.similarity_search(search_query, k=5)
            
            # 결과 변환 및 점수 계산
            results = []
            for i, doc in enumerate(docs):
                relevance_score = self._calculate_relevance_score(doc, finding, i)
                
                # 점수가 너무 낮으면 제외
                if relevance_score < 0.3:
                    continue
                
                excerpt = self._extract_excerpt(doc.page_content, 600)
                results.append(RAGSearchResult(
                    cwe_id=doc.metadata.get('cwe_id', 'Unknown'),
                    name=doc.metadata.get('name', 'Unknown'),
                    excerpt=excerpt,
                    relevance_score=relevance_score,
                    source=doc.metadata.get('source', 'Unknown'),
                    languages=doc.metadata.get('languages', []),
                    mitigations=self._extract_mitigations(doc.page_content)
                ))
            
            # 관련성 점수로 정렬
            results.sort(key=lambda x: x.relevance_score, reverse=True)
            return results
            
        except Exception as e:
            logger.error(f"하이브리드 검색 중 오류: {e}")
            return []
    
    def _extract_keywords(self, text: str) -> List[str]:
        """텍스트에서 핵심 키워드 추출"""
        if not text:
            return []
        
        # 일반적인 보안 관련 키워드
        security_keywords = [
            'injection', 'xss', 'sql', 'command', 'path', 'traversal',
            'authentication', 'authorization', 'encryption', 'validation',
            'input', 'output', 'buffer', 'overflow', 'race', 'condition',
            'deserialization', 'serialization', 'upload', 'download',
            'csrf', 'ssrf', 'xxe', 'ldap', 'nosql', 'orm'
        ]
        
        # 텍스트를 소문자로 변환하고 특수문자 제거
        clean_text = re.sub(r'[^\w\s]', ' ', text.lower())
        words = clean_text.split()
        
        # 보안 키워드와 매칭되는 단어들 추출
        keywords = []
        for word in words:
            if word in security_keywords or len(word) > 3:
                keywords.append(word)
        
        return keywords[:5]  # 최대 5개 키워드
    
    def _calculate_relevance_score(self, doc: Any, finding: SecurityFinding, rank: int) -> float:
        """문서와 발견 결과 간의 관련성 점수 계산"""
        score = 0.0
        
        # 1. 순위 점수 (높은 순위일수록 높은 점수)
        rank_score = max(0, 1.0 - (rank * 0.2))
        score += rank_score * 0.3
        
        # 2. 언어 매칭 점수
        if finding.language and doc.metadata.get('languages'):
            doc_languages = doc.metadata.get('languages', [])
            if finding.language.value in doc_languages:
                score += 0.4
        
        # 3. 메시지 키워드 매칭 점수
        message_keywords = self._extract_keywords(finding.message)
        doc_content = doc.page_content.lower()
        keyword_matches = sum(1 for keyword in message_keywords if keyword in doc_content)
        keyword_score = min(1.0, keyword_matches / max(1, len(message_keywords)))
        score += keyword_score * 0.3
        
        return min(1.0, score)
    
    def _extract_excerpt(self, content: str, max_length: int) -> str:
        """내용에서 요약 추출"""
        if len(content) <= max_length:
            return content
        
        # 문장 단위로 자르기
        sentences = content.split('. ')
        excerpt = ""
        
        for sentence in sentences:
            if len(excerpt + sentence) <= max_length:
                excerpt += sentence + ". "
            else:
                break
        
        return excerpt.strip()
    
    def _extract_mitigations(self, content: str) -> List[str]:
        """내용에서 완화 방안 추출"""
        mitigations = []
        
        # Mitigations 섹션 찾기
        if "Mitigations:" in content:
            mitigation_section = content.split("Mitigations:")[1]
            lines = mitigation_section.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('-') and '[' in line and ']' in line:
                    # [phase] description 형태 파싱
                    phase_end = line.find(']')
                    if phase_end > 0:
                        description = line[phase_end + 1:].strip()
                        if description:
                            mitigations.append(description)
        
        return mitigations[:3]  # 최대 3개
    
    def get_security_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """여러 발견 결과에 대한 보안 요약 생성"""
        summary = {
            "total_findings": len(findings),
            "cwe_distribution": {},
            "severity_distribution": {},
            "language_distribution": {},
            "top_issues": [],
            "recommendations": []
        }
        
        # CWE별 분포
        for finding in findings:
            if finding.cwe:
                summary["cwe_distribution"][finding.cwe] = summary["cwe_distribution"].get(finding.cwe, 0) + 1
        
        # 심각도별 분포
        for finding in findings:
            sev = finding.severity.value
            summary["severity_distribution"][sev] = summary["severity_distribution"].get(sev, 0) + 1
        
        # 언어별 분포
        for finding in findings:
            lang = finding.language.value
            summary["language_distribution"][lang] = summary["language_distribution"].get(lang, 0) + 1
        
        # 상위 이슈 (심각도 + 빈도 기준)
        issue_scores = {}
        for finding in findings:
            score = self._calculate_issue_score(finding)
            issue_scores[finding.finding_id] = {
                "finding": finding,
                "score": score
            }
        
        # 점수순으로 정렬하여 상위 이슈 추출
        sorted_issues = sorted(issue_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        summary["top_issues"] = [
            {
                "finding_id": finding_id,
                "cwe": data["finding"].cwe,
                "severity": data["finding"].severity.value,
                "message": data["finding"].message[:100] + "..." if len(data["finding"].message) > 100 else data["finding"].message
            }
            for finding_id, data in sorted_issues[:5]  # 상위 5개
        ]
        
        return summary
    
    def _calculate_issue_score(self, finding: SecurityFinding) -> float:
        """발견 결과의 중요도 점수 계산"""
        score = 0.0
        
        # 심각도 점수
        severity_scores = {
            "low": 1.0,
            "medium": 2.0,
            "high": 3.0,
            "critical": 4.0
        }
        score += severity_scores.get(finding.severity.value, 1.0)
        
        # CWE가 있으면 추가 점수
        if finding.cwe:
            score += 0.5
        
        return score

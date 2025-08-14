"""
CWE (Common Weakness Enumeration) Database Management Module
취약점 분류 및 정보를 관리하는 핵심 모듈
"""

import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

@dataclass
class CWEItem:
    """CWE 항목을 나타내는 데이터 클래스"""
    id: str
    name: str
    description: str
    likelihood: str
    severity: str
    examples: List[str]
    mitigations: List[str]
    detection_methods: List[str]
    risk_score: float

class CWEDatabase:
    """CWE 데이터베이스 관리 클래스"""
    
    def __init__(self, database_path: str = "./data/cwe_database.json"):
        self.database_path = Path(database_path)
        self.cwe_data: Dict[str, CWEItem] = {}
        self.load_database()
    
    def load_database(self) -> None:
        """CWE 데이터베이스 로드"""
        try:
            if self.database_path.exists():
                with open(self.database_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.cwe_data = {
                        cwe_id: CWEItem(**item) for cwe_id, item in data.items()
                    }
                logger.info(f"Loaded {len(self.cwe_data)} CWE items from database")
            else:
                logger.warning("CWE database not found, creating empty database")
                self.create_initial_database()
        except Exception as e:
            logger.error(f"Error loading CWE database: {e}")
            self.create_initial_database()
    
    def create_initial_database(self) -> None:
        """초기 CWE 데이터베이스 생성 (OWASP Top 10 기반)"""
        initial_cwes = {
            "CWE-79": CWEItem(
                id="CWE-79",
                name="Cross-site Scripting (XSS)",
                description="웹 애플리케이션에서 사용자 입력을 검증하지 않고 출력할 때 발생하는 취약점",
                likelihood="High",
                severity="High",
                examples=[
                    "사용자 입력을 HTML에 직접 삽입",
                    "JavaScript 코드 실행을 허용하는 사용자 입력",
                    "DOM 조작 시 사용자 입력 검증 부족"
                ],
                mitigations=[
                    "모든 사용자 입력 검증 및 이스케이핑",
                    "Content Security Policy (CSP) 적용",
                    "출력 인코딩 강제"
                ],
                detection_methods=[
                    "정적 분석: 사용자 입력 검증 코드 확인",
                    "동적 테스트: XSS 페이로드 주입 테스트",
                    "코드 리뷰: 출력 인코딩 확인"
                ],
                risk_score=9.0
            ),
            "CWE-89": CWEItem(
                id="CWE-89",
                name="SQL Injection",
                description="사용자 입력을 SQL 쿼리에 직접 삽입할 때 발생하는 데이터베이스 취약점",
                likelihood="High",
                severity="High",
                examples=[
                    "사용자 입력을 SQL 문자열에 직접 연결",
                    "동적 SQL 쿼리 생성 시 입력 검증 부족",
                    "ORM 사용 시 raw SQL 쿼리 사용"
                ],
                mitigations=[
                    "파라미터화된 쿼리(Prepared Statements) 사용",
                    "입력 검증 및 화이트리스트 적용",
                    "최소 권한 원칙 적용"
                ],
                detection_methods=[
                    "정적 분석: SQL 쿼리 생성 코드 확인",
                    "동적 테스트: SQL 인젝션 페이로드 테스트",
                    "코드 리뷰: 데이터베이스 접근 패턴 확인"
                ],
                risk_score=9.0
            ),
            "CWE-200": CWEItem(
                id="CWE-200",
                name="Information Exposure",
                description="민감한 정보가 의도치 않게 노출되는 취약점",
                likelihood="Medium",
                severity="Medium",
                examples=[
                    "에러 메시지에 시스템 정보 노출",
                    "로그 파일에 민감한 데이터 기록",
                    "디버그 정보가 프로덕션에 노출"
                ],
                mitigations=[
                    "에러 메시지 일반화",
                    "민감한 정보 로깅 금지",
                    "프로덕션 환경에서 디버그 모드 비활성화"
                ],
                detection_methods=[
                    "정적 분석: 에러 처리 코드 확인",
                    "동적 테스트: 에러 응답 확인",
                    "코드 리뷰: 로깅 및 디버그 코드 확인"
                ],
                risk_score=6.0
            )
        }
        
        self.cwe_data.update(initial_cwes)
        self.save_database()
        logger.info("Initial CWE database created with OWASP Top 10 items")
    
    def save_database(self) -> None:
        """CWE 데이터베이스 저장"""
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.database_path, 'w', encoding='utf-8') as f:
                json.dump(
                    {cwe_id: cwe_item.__dict__ for cwe_id, cwe_item in self.cwe_data.items()},
                    f, ensure_ascii=False, indent=2
                )
            logger.info("CWE database saved successfully")
        except Exception as e:
            logger.error(f"Error saving CWE database: {e}")
    
    def get_cwe(self, cwe_id: str) -> Optional[CWEItem]:
        """특정 CWE ID로 CWE 정보 조회"""
        return self.cwe_data.get(cwe_id)
    
    def search_cwe(self, query: str) -> List[CWEItem]:
        """키워드로 CWE 검색"""
        query = query.lower()
        results = []
        
        for cwe_item in self.cwe_data.values():
            if (query in cwe_item.name.lower() or 
                query in cwe_item.description.lower() or
                any(query in example.lower() for example in cwe_item.examples)):
                results.append(cwe_item)
        
        return results
    
    def get_all_cwes(self) -> List[CWEItem]:
        """모든 CWE 목록 반환"""
        return list(self.cwe_data.values())
    
    def add_cwe(self, cwe_item: CWEItem) -> None:
        """새로운 CWE 항목 추가"""
        self.cwe_data[cwe_item.id] = cwe_item
        self.save_database()
        logger.info(f"Added new CWE: {cwe_item.id}")
    
    def update_cwe(self, cwe_id: str, **kwargs) -> bool:
        """기존 CWE 항목 업데이트"""
        if cwe_id in self.cwe_data:
            cwe_item = self.cwe_data[cwe_id]
            for key, value in kwargs.items():
                if hasattr(cwe_item, key):
                    setattr(cwe_item, key, value)
            self.save_database()
            logger.info(f"Updated CWE: {cwe_id}")
            return True
        return False
    
    def get_risk_score(self, cwe_id: str) -> float:
        """CWE 위험도 점수 반환"""
        cwe_item = self.get_cwe(cwe_id)
        return cwe_item.risk_score if cwe_item else 0.0
    
    def get_high_risk_cwes(self, threshold: float = 7.0) -> List[CWEItem]:
        """높은 위험도 CWE 목록 반환"""
        return [cwe for cwe in self.cwe_data.values() if cwe.risk_score >= threshold]

# 사용 예시
if __name__ == "__main__":
    # 데이터베이스 초기화
    cwe_db = CWEDatabase()
    
    # 특정 CWE 조회
    xss_cwe = cwe_db.get_cwe("CWE-79")
    if xss_cwe:
        print(f"Found CWE: {xss_cwe.name}")
        print(f"Risk Score: {xss_cwe.risk_score}")
    
    # 검색 테스트
    results = cwe_db.search_cwe("injection")
    print(f"Found {len(results)} CWE items related to injection")

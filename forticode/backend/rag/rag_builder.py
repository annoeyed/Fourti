import os
import json
import zipfile
from bs4 import BeautifulSoup
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings


class RAGBuilder:
    def __init__(self, cwe_zip_path, owasp_json_path, vector_store_path="faiss_unified_index"):
        self.cwe_zip_path = cwe_zip_path
        self.owasp_json_path = owasp_json_path
        self.vector_store_path = vector_store_path
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        self.vector_store = None

    # -----------------------------
    # CWE XML -> Documents (강화: 언어/기술 메타 + 완화책까지)
    # -----------------------------
    def _extract_text_from_xml(self, xml_content):
        """Extract relevant text + metadata from CWE XML."""
        soup = BeautifulSoup(xml_content, "lxml-xml")
        documents = []

        for weakness in soup.find_all("Weakness"):
            cwe_id = "CWE-" + weakness.get("ID", "N/A")
            name = weakness.get("Name", "N/A")
            description = weakness.Description.text if weakness.Description else "N/A"
            extended_description = (
                weakness.Extended_Description.text
                if weakness.Extended_Description
                else ""
            )

            # Applicable_Platforms -> Languages/Technologies
            ap_langs, ap_techs = [], []
            ap = weakness.find("Applicable_Platforms")
            if ap:
                for lang in ap.find_all("Language"):
                    nm = (lang.get("Name") or "").strip().lower()
                    if nm:
                        ap_langs.append("cpp" if nm == "c++" else nm)
                for tech in ap.find_all("Technology"):
                    nm = (tech.get("Name") or "").strip().lower()
                    if nm:
                        ap_techs.append(nm)
            
            # Infer languages from text
            languages_inferred = set()
            text_for_inference = (name + " " + description + " " + extended_description).lower()
            if "django" in text_for_inference or "flask" in text_for_inference or "sqlalchemy" in text_for_inference: languages_inferred.add("python")
            if "spring" in text_for_inference or "hibernate" in text_for_inference or "jdbc" in text_for_inference: languages_inferred.add("java")
            if "express" in text_for_inference or "node.js" in text_for_inference: languages_inferred.add("javascript")
            if "rails" in text_for_inference: languages_inferred.add("ruby")

            # Potential_Mitigations
            mitigations = []
            for pm in weakness.find_all("Potential_Mitigations"):
                for mit in pm.find_all("Mitigation"):
                    phase = (mit.get("Phase") or "").lower()
                    if phase in ("implementation", "architecture", "requirements"):
                        txt = (mit.text or "").strip()
                        if txt:
                            mitigations.append(f"- [{phase}] {txt}")

            content = (
                f"{cwe_id}: {name}\n\n"
                f"Description:\n{description}\n\n"
                f"Extended Description:\n{extended_description}\n\n"
                f"Applicable Languages: {', '.join(ap_langs) if ap_langs else 'general'}\n"
                f"Applicable Technologies: {', '.join(ap_techs) if ap_techs else 'general'}\n\n"
                + ("Mitigations:\n" + "\n".join(mitigations) if mitigations else "")
            )

            doc = Document(
                page_content=content,
                metadata={
                    "cwe_id": cwe_id,
                    "name": name,
                    "languages": list(set(ap_langs)),
                    "technologies": list(set(ap_techs)),
                    "languages_inferred": list(languages_inferred),
                    "source": "CWE",
                    "security_category": "vulnerability_analysis"
                },
            )
            documents.append(doc)

        return documents

    # -----------------------------
    # OWASP JSON -> Documents
    # -----------------------------
    def _load_owasp_documents(self):
        """OWASP JSON 파일에서 문서를 로드합니다"""
        if not os.path.exists(self.owasp_json_path):
            print(f"Warning: OWASP data not found at {self.owasp_json_path}")
            return []
        
        try:
            with open(self.owasp_json_path, 'r', encoding='utf-8') as f:
                owasp_data = json.load(f)
            
            documents = []
            for item in owasp_data:
                # OWASP 데이터를 LangChain Document 형식으로 변환
                doc = Document(
                    page_content=item['content'],
                    metadata={
                        "title": item.get('title', ''),
                        "source": item.get('source', 'OWASP'),
                        "languages": item.get('languages', []),
                        "technologies": item.get('technologies', []),
                        "languages_inferred": item.get('languages_inferred', []),
                        "security_category": item.get('security_category', ''),
                        "file_path": item.get('file_path', ''),
                        "cwe_id": None  # OWASP은 CWE ID가 없음
                    }
                )
                documents.append(doc)
            
            print(f"Loaded {len(documents)} OWASP documents")
            return documents
            
        except Exception as e:
            print(f"Error loading OWASP data: {e}")
            return []

    # -----------------------------
    # Load & Split
    # -----------------------------
    def _load_and_split_data(self):
        """CWE와 OWASP 데이터를 모두 로드하고 분할합니다"""
        all_documents = []
        
        # 1. CWE 데이터 로드
        print(f"Loading CWE data from {self.cwe_zip_path}...")
        if os.path.exists(self.cwe_zip_path):
            with zipfile.ZipFile(self.cwe_zip_path, "r") as z:
                xml_filename = next(
                    (name for name in z.namelist() if name.endswith(".xml")), None
                )
                if not xml_filename:
                    raise ValueError("No XML file found in the zip archive.")

                with z.open(xml_filename) as xml_file:
                    content = xml_file.read()
                    cwe_documents = self._extract_text_from_xml(content)
                    all_documents.extend(cwe_documents)
                    print(f"  - {len(cwe_documents)} CWE documents loaded")
        else:
            print(f"Warning: CWE zip file not found at {self.cwe_zip_path}")
        
        # 2. OWASP 데이터 로드
        print(f"Loading OWASP data from {self.owasp_json_path}...")
        owasp_documents = self._load_owasp_documents()
        all_documents.extend(owasp_documents)
        
        # 3. 텍스트 분할
        print("Splitting documents into chunks...")
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1500, chunk_overlap=150
        )
        split_docs = text_splitter.split_documents(all_documents)
        print(f"Successfully loaded and split {len(split_docs)} documents.")
        
        # 4. 통계 출력
        self._print_data_statistics(all_documents)
        
        return split_docs

    def _print_data_statistics(self, documents):
        """데이터 소스별 통계를 출력합니다"""
        cwe_count = sum(1 for doc in documents if doc.metadata.get('source') == 'CWE')
        owasp_count = sum(1 for doc in documents if doc.metadata.get('source') == 'OWASP')
        
        print(f"\n=== Data Source Statistics ===")
        print(f"CWE documents: {cwe_count}")
        print(f"OWASP documents: {owasp_count}")
        print(f"Total documents: {len(documents)}")

    # -----------------------------
    # Build & Save Vector Store
    # -----------------------------
    def build_and_save_vector_store(self):
        """Builds the vector store from CWE and OWASP data and saves it to disk."""
        print("Loading and splitting unified data...")
        split_documents = self._load_and_split_data()

        print("Creating unified vector store with FAISS...")
        self.vector_store = FAISS.from_documents(split_documents, self.embeddings)

        print(f"Saving vector store to {self.vector_store_path}...")
        self.vector_store.save_local(self.vector_store_path)
        print("Unified vector store built and saved successfully.")

    # -----------------------------
    # Load Vector Store
    # -----------------------------
    def load_vector_store(self):
        """Loads the vector store from disk."""
        if os.path.exists(self.vector_store_path):
            print(f"Loading vector store from {self.vector_store_path}...")
            self.vector_store = FAISS.load_local(
                self.vector_store_path,
                self.embeddings,
                allow_dangerous_deserialization=True,  # 로컬 생성물이므로 허용
            )
            print("Vector store loaded successfully.")
            return self.vector_store
        else:
            print("No existing vector store found. Building a new one...")
            self.build_and_save_vector_store()
            return self.vector_store

    # -----------------------------
    # Retrieval Helpers
    # -----------------------------
    def _load_seeds(self, language: str):
        """Loads a set of CWE IDs for a given language to be used for boosting."""
        if not language:
            return set()
        
        seed_path = os.path.join(os.path.dirname(__file__), "cwe_seeds", f"{language.lower()}.json")
        if os.path.exists(seed_path):
            try:
                with open(seed_path, "r") as f:
                    return set(json.load(f))
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load or parse seed file {seed_path}: {e}")
                return set()
        return set()

    def find_by_cwe_id(self, cwe_id: str):
        """Return docs with exact metadata.cwe_id match."""
        if self.vector_store is None:
            self.load_vector_store()
        docs = []
        store = getattr(self.vector_store, "docstore", None)
        data = getattr(store, "_dict", {}) if store else {}
        for _, doc in data.items():
            if doc.metadata.get("cwe_id") == cwe_id:
                docs.append(doc)
        return docs

    def search(self, query: str, k: int = 5):
        """Semantic similarity search."""
        if self.vector_store is None:
            self.load_vector_store()
        return self.vector_store.similarity_search(query, k=k)

    def retrieve_for_finding(self, finding: dict, k: int = 5):
        """
        Hybrid retrieval:
        1) If CWE present -> fetch exact docs.
        2) Else semantic search by message/rule/tool.
        3) Re-rank by language/framework match and seed boosting.
        """
        # 1) CWE 우선
        cwe_id = (finding.get("cwe") or "").strip()
        if cwe_id.startswith("CWE-"):
            candidates = self.find_by_cwe_id(cwe_id)
            # CWE가 있어도 결과가 없으면 의미 검색으로 전환
            if not candidates:
                q = " ".join(filter(None, [finding.get("message"), finding.get("rule_id"), finding.get("tool")]))
                candidates = self.search(q or "secure coding", k=k * 3)
        else:
            q = " ".join(filter(None, [finding.get("message"), finding.get("rule_id"), finding.get("tool")]))
            candidates = self.search(q or "secure coding", k=k * 3)

        # 2) 언어/프레임워크 가중 재랭킹 (시드 부스팅 포함)
        lang = (finding.get("language") or "").lower()
        fw = (finding.get("framework") or "").lower()
        seeds = self._load_seeds(lang)

        def score(d):
            s = 0
            meta = d.metadata
            langs = meta.get("languages") or []
            techs = meta.get("technologies") or []
            infs = meta.get("languages_inferred") or []

            # 언어/추론언어
            if lang and lang in langs: s += 2
            if lang and lang in infs: s += 2

            # 프레임워크/기술
            if fw and fw in techs: s += 2

            # 시드 부스팅
            if meta.get("cwe_id") in seeds:
                s += 1.5
            
            # SQL/DB 관련 보정
            if lang and ("sql" in langs or "sql" in infs or "database server" in techs):
                s += 1
            return s

        ranked = sorted(candidates, key=score, reverse=True)
        return ranked[:k]


if __name__ == "__main__":
    # 파일 경로 설정
    cwe_zip_file_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "cwec_latest.xml.zip"
    )
    owasp_json_file_path = os.path.join(
        os.path.dirname(__file__), "owasp_markdown_data", "owasp_cheatsheets_parsed.json"
    )

    # 파일 존재 여부 확인
    if not os.path.exists(cwe_zip_file_path):
        print(f"Error: CWE zip file not found at {cwe_zip_file_path}")
    elif not os.path.exists(owasp_json_file_path):
        print(f"Error: OWASP JSON file not found at {owasp_json_file_path}")
    else:
        # 통합 RAG 빌더 생성 및 실행
        rag_builder = RAGBuilder(
            cwe_zip_path=cwe_zip_file_path,
            owasp_json_path=owasp_json_file_path
        )
        
        # 기존 인덱스 삭제 후 재생성
        if os.path.exists("faiss_unified_index"):
            import shutil
            shutil.rmtree("faiss_unified_index")
            print("Removed existing unified index")
        
        # 통합 벡터 저장소 구축
        rag_builder.build_and_save_vector_store()
        
        # 로드 테스트
        vs = rag_builder.load_vector_store()
        
        # 자유 질의 예제
        query = "SQL Injection vulnerability prevention"
        results = vs.similarity_search(query, k=3)
        print("\n=== 통합 검색 결과 예제 ===")
        for i, res in enumerate(results, start=1):
            print(f"\n--- Result {i} ---")
            print("Source:", res.metadata.get("source"))
            print("CWE ID:", res.metadata.get("cwe_id", "N/A"))
            print("Title:", res.metadata.get("title", "N/A"))
            print("Languages:", res.metadata.get("languages"))
            print("Technologies:", res.metadata.get("technologies"))
            print("Excerpt:", res.page_content[:300], "...")

        # finding 기반 검색 예제
        finding = {
            "cwe": "CWE-89",
            "language": "python",
            "framework": "django",
            "message": "SQL injection via string concatenation on query",
            "rule_id": "B608",
            "tool": "bandit",
        }
        rets = rag_builder.retrieve_for_finding(finding, k=3)
        print("\n=== finding 기반 검색 결과 (언어/프레임워크 재랭킹) ===")
        for i, res in enumerate(rets, start=1):
            print(f"\n--- Result {i} ---")
            print("Source:", res.metadata.get("source"))
            print("CWE ID:", res.metadata.get("cwe_id", "N/A"))
            print("Title:", res.metadata.get("title", "N/A"))
            print("Languages:", res.metadata.get("languages"))
            print("Technologies:", res.metadata.get("technologies"))
            print("Excerpt:", res.page_content[:300], "...")

"""
CABTA - RAG Knowledge Base (minimal, lightweight version)
============================================================

จุดประสงค์:
    เพิ่ม Retrieval-Augmented Generation (RAG) ให้ CABTA แบบเบาที่สุด
    เพื่อให้รันคู่กับ Ollama (Llama3.2 3B) ได้บนเครื่องที่มี VRAM จำกัด
    (RTX 2050, 4GB VRAM)

แนวคิดออกแบบ:
    - Vector store: ChromaDB แบบ PersistentClient (เก็บลง local file,
      ไม่ต้องมี server แยก, ไม่กิน VRAM)
    - Embedding model: sentence-transformers/all-MiniLM-L6-v2
      (~80MB, รันบน CPU ได้สบาย ไม่ไปแย่ง VRAM กับ LLM หลัก)
    - Knowledge source เริ่มต้น: Playbook + MITRE ATT&CK mapping ที่มีอยู่แล้ว
      ในโปรเจกต์ (เอามาทำเป็น seed data ตัวอย่าง — ในของจริงควรดึงจาก
      playbook_engine.py / mitre_navigator.py แทนการ hardcode)

การใช้งานคร่าวๆ:
    kb = RAGKnowledgeBase()
    kb.seed(load_playbooks_from_yaml())              # โหลดความรู้เข้า vector store (ครั้งแรกครั้งเดียว)
    hits = kb.query("newly registered domain DGA detected", n_results=3)
    prompt = kb.build_augmented_prompt(incident_context, hits)
    # ส่ง prompt ต่อให้ Ollama เพื่อ generate คำแนะนำที่อ้างอิง playbook จริง

ติดตั้ง dependency:
    pip install chromadb sentence-transformers --break-system-packages
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import chromadb
    from chromadb.utils import embedding_functions
    _CHROMADB_AVAILABLE = True
except ImportError:
    _CHROMADB_AVAILABLE = False
    logger.warning(
        "[RAG] chromadb / sentence-transformers ยังไม่ได้ติดตั้ง "
        "รัน: pip install chromadb sentence-transformers --break-system-packages"
    )


DEFAULT_PERSIST_DIR = Path.home() / ".blue-team-assistant" / "rag_store"
DEFAULT_COLLECTION_NAME = "cabta_knowledge_base"
DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # เบา รันบน CPU ได้ ไม่กิน VRAM


class RAGKnowledgeBase:
    """
    Vector-backed knowledge base สำหรับ playbook / MITRE mapping / past incidents.

    ออกแบบให้เป็น "ชั้นเสริม" คู่กับ deterministic scoring engine ที่มีอยู่แล้ว
    ไม่ใช่ตัวตัดสิน verdict — RAG มีหน้าที่แค่ retrieve บริบทที่เกี่ยวข้อง
    เพื่อให้ LLM อธิบาย/แนะนำได้แม่นยำขึ้น (เหมือนหลักการเดียวกับ
    verdict_validator.py ที่ scoring engine เป็น source of truth เสมอ)
    """

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        collection_name: str = DEFAULT_COLLECTION_NAME,
        embedding_model_name: str = DEFAULT_EMBEDDING_MODEL,
    ):
        if not _CHROMADB_AVAILABLE:
            raise ImportError(
                "chromadb / sentence-transformers not installed. "
                "Run: pip install chromadb sentence-transformers --break-system-packages"
            )

        self._persist_dir = Path(persist_dir) if persist_dir else DEFAULT_PERSIST_DIR
        self._persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(path=str(self._persist_dir))

        # Embedding function รันบน CPU โดย default (ไม่ต้องตั้ง device='cuda')
        # เพื่อไม่แย่ง VRAM กับ Ollama ที่รัน Llama3.2 3B อยู่แล้ว
        self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=embedding_model_name,
            device="cpu",
        )

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=self._embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )

        logger.info(
            f"[RAG] Knowledge base ready: {self._collection.count()} documents "
            f"indexed at {self._persist_dir}"
        )

    # ------------------------------------------------------------------ #
    # Indexing
    # ------------------------------------------------------------------ #

    def seed(self, documents: List[Dict], skip_if_populated: bool = True) -> int:
        """
        โหลดความรู้เข้า vector store (ทำครั้งแรกครั้งเดียว หรือตอน re-index)

        Args:
            documents: list ของ dict รูปแบบ
                {
                    "id": "playbook_phishing_001",
                    "text": "เนื้อหา playbook / procedure ที่จะใช้ retrieve",
                    "metadata": {"category": "playbook", "verdict": "SUSPICIOUS", ...}
                }
            skip_if_populated: ถ้า collection มีข้อมูลอยู่แล้ว จะข้ามการ seed ซ้ำ

        Returns:
            จำนวนเอกสารที่ถูก add เข้าไป
        """
        if skip_if_populated and self._collection.count() > 0:
            logger.info(
                f"[RAG] Collection already has {self._collection.count()} docs, skip seeding "
                f"(pass skip_if_populated=False to force re-seed)"
            )
            return 0

        self._collection.add(
            ids=[d["id"] for d in documents],
            documents=[d["text"] for d in documents],
            metadatas=[d.get("metadata", {}) for d in documents],
        )
        logger.info(f"[RAG] Indexed {len(documents)} documents into knowledge base")
        return len(documents)

    def add_incident(self, incident_id: str, summary: str, metadata: Dict) -> None:
        """
        เพิ่ม incident ที่จบแล้วเข้า knowledge base เพื่อให้ incident ในอนาคต
        ที่คล้ายกัน retrieve บริบทนี้ไปใช้ได้ (self-learning knowledge base)
        """
        self._collection.add(
            ids=[f"incident_{incident_id}"],
            documents=[summary],
            metadatas=[{**metadata, "category": "past_incident"}],
        )
        logger.info(f"[RAG] Added past incident {incident_id} to knowledge base")

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #

    def query(
        self,
        query_text: str,
        n_results: int = 3,
        category_filter: Optional[str] = None,
    ) -> List[Dict]:
        """
        ค้นหาเอกสารที่เกี่ยวข้องที่สุดกับ query_text (semantic similarity search)

        Args:
            query_text: ข้อความ query เช่น "phishing email with malicious attachment"
            n_results: จำนวนผลลัพธ์สูงสุดที่ต้องการ
            category_filter: กรองเฉพาะ category เช่น "playbook" หรือ "mitre_mapping"

        Returns:
            list ของ dict {"text": ..., "metadata": ..., "distance": ...}
            เรียงจาก relevant มากไปน้อย (distance ยิ่งน้อยยิ่งใกล้เคียง)
        """
        where = {"category": category_filter} if category_filter else None

        results = self._collection.query(
            query_texts=[query_text],
            n_results=n_results,
            where=where,
        )

        hits = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]

        for text, meta, dist in zip(docs, metas, dists):
            hits.append({"text": text, "metadata": meta, "distance": dist})

        logger.info(f"[RAG] Query '{query_text[:50]}...' -> {len(hits)} hits")
        return hits

    # ------------------------------------------------------------------ #
    # Prompt augmentation (ส่งต่อให้ Ollama)
    # ------------------------------------------------------------------ #

    @staticmethod
    def build_augmented_prompt(incident_context: str, retrieved_docs: List[Dict]) -> str:
        """
        ประกอบ prompt สำหรับส่งเข้า Ollama โดยแนบบริบทที่ retrieve มาได้
        ตามหลัก RAG: ให้ LLM อ้างอิงข้อมูลจริง แทนที่จะตอบจาก training data ล้วนๆ

        หมายเหตุ: verdict ยังคงมาจาก deterministic scoring engine เสมอ
        (ดู verdict_validator.py) — prompt นี้ใช้แค่ช่วย "อธิบาย/แนะนำ" เท่านั้น
        """
        if not retrieved_docs:
            context_block = "(ไม่พบ playbook หรือ knowledge ที่เกี่ยวข้องในฐานข้อมูล)"
        else:
            lines = []
            for i, doc in enumerate(retrieved_docs, start=1):
                source = doc["metadata"].get("category", "unknown")
                lines.append(f"[{i}] (source: {source}) {doc['text']}")
            context_block = "\n".join(lines)

        prompt = f"""คุณคือ SOC analyst assistant ตอบโดยอ้างอิง context ที่ retrieve มาด้านล่างเท่านั้น
ห้ามเดาข้อมูลที่ไม่มีอยู่ใน context หรือ incident_context

=== Retrieved Knowledge (จาก Knowledge Base) ===
{context_block}

=== Incident ปัจจุบัน ===
{incident_context}

จงสรุปแนวทางตอบสนองโดยอ้างอิง playbook ที่เกี่ยวข้องด้านบน (ระบุว่าอ้างอิงจากข้อไหน)
ในรูปแบบ 3-5 bullet point เหมาะสำหรับ SOC ticket:
"""
        return prompt

    def status(self) -> Dict:
        """สรุปสถานะ knowledge base สำหรับ debug / dashboard"""
        return {
            "persist_dir": str(self._persist_dir),
            "collection": self._collection.name,
            "document_count": self._collection.count(),
        }



import yaml

# ---------------------------------------------------------------------- #
# Knowledge Base Data Loader (from YAML playbooks)
# ---------------------------------------------------------------------- #

def load_playbooks_from_yaml(playbooks_dir: Optional[Path] = None) -> List[Dict]:
    """
    Scans a directory for YAML files, parses them, and returns a list of
    documents suitable for seeding the RAG knowledge base.

    Args:
        playbooks_dir: The directory containing YAML playbook files.
                       Defaults to 'data/rag_knowledge/' relative to project root.

    Returns:
        A list of dicts, where each dict represents a knowledge entry.
    """
    if playbooks_dir is None:
        # Assuming script is run from project root or src/rag
        project_root = Path(__file__).resolve().parents[2]
        playbooks_dir = project_root / "data" / "rag_knowledge"

    if not playbooks_dir.exists():
        logger.warning(f"[RAG Loader] Playbooks directory not found: {playbooks_dir}")
        return []

    all_documents = []
    loaded_files_count = 0
    for yaml_path in playbooks_dir.glob("*.yaml"):
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if not data:
                    logger.warning(f"[RAG Loader] Skipping empty YAML file: {yaml_path.name}")
                    continue

                # Each YAML file should contain a list of entries
                if not isinstance(data, list):
                    logger.warning(f"[RAG Loader] Skipping malformed YAML (expected a list): {yaml_path.name}")
                    continue

                for entry in data:
                    # Validate required fields
                    if "id" in entry and "text" in entry and "metadata" in entry:
                        all_documents.append(entry)
                    else:
                        logger.warning(f"[RAG Loader] Skipping entry with missing fields in {yaml_path.name}")
            loaded_files_count += 1
        except yaml.YAMLError as e:
            logger.error(f"[RAG Loader] Error parsing YAML file {yaml_path.name}: {e}")
        except Exception as e:
            logger.error(f"[RAG Loader] Error reading file {yaml_path.name}: {e}")

    logger.info(f"[RAG Loader] Loaded {len(all_documents)} knowledge entries from {loaded_files_count} playbook files.")
    return all_documents


# ---------------------------------------------------------------------- #
# Demo / smoke test
# ---------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    kb = RAGKnowledgeBase()
    kb.seed(load_playbooks_from_yaml())

    print("\n=== Knowledge Base Status ===")
    print(kb.status())

    # ตัวอย่าง query จำลอง incident จริง
    test_query = "newly registered domain with DGA pattern detected, score 65"
    print(f"\n=== Query: {test_query} ===")
    hits = kb.query(test_query, n_results=2)
    for h in hits:
        print(f"- (distance={h['distance']:.3f}) {h['text'][:80]}...")

    incident_context = (
        "IOC: xj2k9laz.biz | ioc_type: domain | threat_score: 65 | verdict: SUSPICIOUS\n"
        "domain_age: 12 days (newly registered) | dga_confidence: 62"
    )
    prompt = kb.build_augmented_prompt(incident_context, hits)
    print("\n=== Augmented Prompt (ส่งต่อให้ Ollama) ===")
    print(prompt)
"""
RAG Mixin for SKYNET Agents
============================

Mixin class to add RAG capabilities to any SKYNET agent.
"""

from typing import Any, Dict, List, Optional


class RAGMixin:
    """
    Mixin to add RAG knowledge querying to agents.

    Usage:
        class EnhancedAgent(MyAgent, RAGMixin):
            def my_method(self):
                knowledge = self.query_rag("my question")
                # Use knowledge...
    """

    def query_rag(
        self,
        question: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
        use_llm: bool = True,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Query RAG knowledge base.

        Args:
            question: Question to answer
            top_k: Number of sources to retrieve
            source_filter: Filter by source (e.g., "exploit-db")
            use_llm: Generate answer with LLM
            use_cache: Use query cache

        Returns:
            RAG result with answer and sources
        """
        from skynet.knowledge import query_knowledge
        from skynet.knowledge.query_cache import cache_query, get_cached_query

        # Check cache first
        if use_cache:
            cached = get_cached_query(question, top_k=top_k, source_filter=source_filter)
            if cached is not None:
                return cached

        # Query RAG
        result = query_knowledge(
            question, top_k=top_k, source_filter=source_filter, use_llm=use_llm
        )

        # Cache result
        if use_cache:
            cache_query(question, result, top_k=top_k, source_filter=source_filter)

        return result

    def get_exploits_for_service(
        self, service: str, version: Optional[str] = None, max_results: int = 5
    ) -> List[Dict]:
        """
        Get exploits for specific service from knowledge base.

        Args:
            service: Service name (e.g., "apache", "mysql")
            version: Optional version number
            max_results: Maximum results to return

        Returns:
            List of exploit sources
        """
        query = f"Exploits for {service}"
        if version:
            query += f" version {version}"

        result = self.query_rag(
            query,
            top_k=max_results,
            source_filter="exploit-db",
            use_llm=False,  # Just retrieval
        )

        return result.get("sources", [])

    def get_techniques(
        self, technique_type: str, platform: Optional[str] = None, max_results: int = 5
    ) -> List[Dict]:
        """
        Get techniques from knowledge base.

        Args:
            technique_type: Type (e.g., "privilege escalation", "SQL injection")
            platform: Optional platform filter
            max_results: Maximum results

        Returns:
            List of technique sources
        """
        query = technique_type
        if platform:
            query += f" on {platform}"

        result = self.query_rag(query, top_k=max_results, use_llm=False)

        return result.get("sources", [])

    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """
        Get information about specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-41773")

        Returns:
            CVE information or None
        """
        result = self.query_rag(cve_id, top_k=3, source_filter="nvd", use_llm=True)

        if result.get("sources"):
            return {
                "cve_id": cve_id,
                "answer": result.get("answer"),
                "sources": result.get("sources"),
            }

        return None

    def search_knowledge(self, keywords: List[str], max_results: int = 10) -> List[Dict]:
        """
        Search knowledge base with multiple keywords.

        Args:
            keywords: List of search keywords
            max_results: Maximum total results

        Returns:
            Combined results from all keywords
        """
        all_sources = []

        for keyword in keywords:
            result = self.query_rag(keyword, top_k=max_results // len(keywords), use_llm=False)
            all_sources.extend(result.get("sources", []))

        # Deduplicate by content hash
        seen = set()
        unique_sources = []

        for source in all_sources:
            content_hash = hash(source["content"][:100])  # Hash first 100 chars
            if content_hash not in seen:
                seen.add(content_hash)
                unique_sources.append(source)

        return unique_sources[:max_results]

    def get_rag_summary(self, question: str) -> str:
        """
        Get short summary answer from RAG.

        Args:
            question: Question

        Returns:
            Summary answer (LLM-generated)
        """
        result = self.query_rag(question, top_k=3, use_llm=True)
        return result.get("answer", "No answer available")

    def check_knowledge_available(self, query: str) -> bool:
        """
        Check if knowledge is available for query.

        Args:
            query: Search query

        Returns:
            True if relevant knowledge found
        """
        result = self.query_rag(query, top_k=1, use_llm=False)
        return len(result.get("sources", [])) > 0

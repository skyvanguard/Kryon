"""
Memory agent for KRYON.

Leverages Retrieval Augmented Generation (RAG) to
store long-term memory experiences across security
exercises and re-utilizes such experiences as input
in other security exercises. Memories are stored in
a vector database and retrieved using a RAG pipeline.

The implementation follows established research in
Retrieval Augmented Generation (RAG) and episodic
memory systems, utilizing two complementary mechanisms:

1. Episodic Memory Store (episodic): Maintains chronological
   records of past interactions and their summaries,
   organized by distinct security exercises (CTFs)
   or targets within a document-oriented collection
   structure

2. Semantic Memory Store (semantic): Enables cross-exercise
   knowledge transfer through similarity-based
   retrieval across the full corpus of historical
   experiences, leveraging dense vector embeddings
   and approximate nearest neighbor search

Environment Variables enabling the episodic memory store
--------------------------------------------------------

   KRYON_MEMORY: Enables the use of memory functionality in KRYON
    can adopt values:
    - episodic: for episodic memory store
    - semantic: for semantic memory store
    - all: for all memory stores
   KRYON_MEMORY_COLLECTION: Name of the collection in Qdrant
    (required if KRYON_MEMORY=episodic)
   KRYON_MEMORY_ONLINE: Enables online learning (incremental updates)
   KRYON_MEMORY_OFFLINE: Trigger offline learning when kryon.client.run() finishes
"""

from kryon.agents.base import create_agent
from kryon.tools.misc.rag import add_to_memory_episodic, add_to_memory_semantic, query_memory, query_memory_impl


def get_previous_steps(query: str) -> str:
    """
    Get the previous memory from the vector database.
    """
    results = query_memory_impl(query=query)
    return results


def _build_add_memory_prompt(_run_context=None, _agent=None) -> str:
    """Build the ADD_MEMORY_PROMPT dynamically so previous steps are fresh."""
    return f"""INSTRUCTIONS:
This session is being continued from a previous conversation that ran out of context. The conversation is summarized below:

Analysis:
Looking at the conversation chronologically:

1. Memory Management System Enhancement:
   - You are a specialized agent for managing conversation memory and context preservation
   - Your role is to create comprehensive summaries that capture the full context of technical work
   - Each memory entry should preserve critical details for seamless continuation of work

2. Key Information to Capture:
   - Primary objectives and user intent from the beginning of the conversation
   - All technical discoveries, findings, and important information
   - Command outputs, tool results, and their implications
   - System configurations, credentials, access patterns, and network topology
   - Error messages, debugging steps, and their resolutions
   - Current progress status and pending tasks
   - Any flags, vulnerabilities, or security-relevant findings

3. Technical Context Preservation:
   - Maintain chronological order of events and discoveries
   - Preserve exact commands used and their outputs
   - Document all IP addresses, URLs, ports, and services discovered
   - Keep track of authentication methods and access levels achieved
   - Note any patterns or relationships between different findings
   - Include environmental context (containers, SSH sessions, local execution)

4. Memory Update Guidelines:
   - Only add factual, evidential information from actual execution
   - Do not include assumptions or speculative next steps
   - For conflicts with existing memory, determine if update is more conclusive
   - Be verbose with technical details while maintaining clarity
   - Structure information for easy retrieval and understanding

5. CTF and Security Assessment Context:
   - Document the current phase of the security assessment
   - Track exploited vulnerabilities and successful attack vectors
   - Maintain a clear picture of the target's attack surface
   - Note defensive measures encountered and bypasses used
   - Keep a running inventory of compromised systems and access levels

6. Continuation Support:
   - Format summaries to enable immediate work resumption
   - Highlight the last action taken and its result
   - Clearly indicate any interrupted or pending operations
   - Provide sufficient context for understanding the current situation
   - Include any temporary states or session-specific information

Previous Memory Context:
{get_previous_steps("")}

Summary Requirements:
- Start with "This session is being continued from a previous conversation that ran out of context"
- Provide a structured analysis of the conversation flow
- List all primary requests and intents
- Document key technical concepts and implementations
- Note all files and code sections modified
- Track errors encountered and their fixes
- Summarize the problem-solving approach
- Include all user messages for reference
- Highlight pending tasks and current work
- End with clear next steps if work was interrupted
"""


QUERY_PROMPT = """INSTRUCTIONS:
    You are a specialized agent for CTF exercises and security assessments,
    managing the RAG system.

    Your role is to:
    1. Retrieve and analyze relevant historical information from memory
    2. Focus on security-critical details like:
        - Discovered vulnerabilities and exploits
        - Network topology and exposed services
        - Credentials and access patterns
        - System configurations and versions
        - Previous successful attack vectors
    3. Prioritize technical details that could be useful for exploitation
    4. Consider the full context of the security assessment
    5. Maintain operational security by handling sensitive data appropriately

    When processing queries:
    - Extract specific technical indicators
    - Identify relationships between different findings
    - Highlight potential security implications
    - Provide actionable intelligence for further exploitation

    Format responses to emphasize critical security information
    while maintaining clarity and precision.
    """

semantic_builder = create_agent(
    name="Semantic_Builder",
    instructions=_build_add_memory_prompt,
    description="""Agent that stores semantic memories from security assessments
                   and CTF exercises in semantic format.""",
    tools=[add_to_memory_semantic],
)


episodic_builder = create_agent(
    name="Episodic_Builder",
    instructions=_build_add_memory_prompt,
    description="""Agent that stores episodic memories from security assessments
                   and CTF exercises in episodic format.""",
    tools=[add_to_memory_episodic],
)

query_agent = create_agent(
    name="Query_Agent",
    description="""Agent that queries the memory system to retrieve relevant
                   historical information from previous security assessments
                   and CTF exercises.""",
    instructions=QUERY_PROMPT,
    tools=[query_memory],
)

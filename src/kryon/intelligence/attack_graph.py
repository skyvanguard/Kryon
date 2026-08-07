"""First-class attack-graph state — XBOW's "nodes = capabilities, edges =
exploits" model, grown DURING the engagement.

The old ``vulnerability_correlator._build_attack_graph`` only draws a post-hoc
D3 picture over already-closed findings by keyword-matching. This is different:
a live state the agent extends step by step, where

  - a NODE is a *capability* the agent has obtained (anonymous access, a leaked
    secret, a forged admin token, code execution on a host), and
  - an EDGE is a *proven* exploit that moved from one capability to another.

Only confirmed edges are added, so a discovered path is "real, not merely
plausible" (XBOW). The frontier — capabilities that opened new moves — is what a
reasoning planner uses to decide the next step instead of replaying fixed rules.

Pure + testable; no I/O, no LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Capabilities that constitute meaningful impact (a path that reaches one of
# these is a demonstrated attack path, the thing worth reporting).
IMPACT_KINDS = frozenset({"rce", "root", "admin", "data_exfil", "db_takeover", "account_takeover"})

ENTRY = ("entry", "", "")  # implicit start node


@dataclass(frozen=True)
class Capability:
    """A state/ability the agent holds. Identity is (kind, value, host)."""

    kind: str  # access | secret | token | rce | admin | user | data_exfil | ...
    value: str = ""  # e.g. the secret name, the username, the endpoint
    host: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.kind.lower(), self.value.lower(), self.host.lower())


@dataclass(frozen=True)
class Edge:
    src: tuple[str, str, str]
    dst: tuple[str, str, str]
    exploit: str  # what moved src -> dst (tool/technique)
    evidence: str = ""
    confirmed: bool = True


@dataclass
class AttackGraph:
    """A growing graph of obtained capabilities linked by proven exploits."""

    _caps: dict[tuple[str, str, str], Capability] = field(default_factory=dict)
    _edges: list[Edge] = field(default_factory=list)

    def add_capability(self, cap: Capability) -> tuple[str, str, str]:
        k = cap.key()
        self._caps.setdefault(k, cap)
        return k

    def add_edge(
        self,
        src: Capability | None,
        dst: Capability,
        exploit: str,
        *,
        evidence: str = "",
        confirmed: bool = True,
    ) -> bool:
        """Record a proven move src -> dst. Unconfirmed edges are rejected —
        the graph holds only demonstrated capabilities. Returns True if added."""
        if not confirmed:
            return False
        src_key = ENTRY if src is None else self.add_capability(src)
        dst_key = self.add_capability(dst)
        # Dedup identical (src, dst, exploit) edges so re-running the graph
        # builder each turn (folding new facts into a persistent graph) never
        # bloats the edge list — BFS/path-finding stays cheap over a long run.
        for e in self._edges:
            if e.src == src_key and e.dst == dst_key and e.exploit == exploit:
                return False
        self._edges.append(Edge(src=src_key, dst=dst_key, exploit=exploit, evidence=evidence, confirmed=True))
        return True

    def has_capability(self, kind: str, value: str | None = None, host: str | None = None) -> bool:
        kind = kind.lower()
        for cap in self._caps.values():
            if cap.kind.lower() != kind:
                continue
            if value is not None and cap.value.lower() != value.lower():
                continue
            if host is not None and cap.host.lower() != host.lower():
                continue
            return True
        return False

    def capabilities(self) -> list[Capability]:
        return list(self._caps.values())

    def edges(self) -> list[Edge]:
        return list(self._edges)

    def impact_reached(self) -> bool:
        return any(cap.kind.lower() in IMPACT_KINDS for cap in self._caps.values())

    def path_to(self, dst_key: tuple[str, str, str]) -> list[Edge]:
        """Shortest edge chain from ENTRY to ``dst_key`` (BFS). Empty if none."""
        if dst_key not in self._caps:
            return []
        # adjacency
        adj: dict[tuple, list[Edge]] = {}
        for e in self._edges:
            adj.setdefault(e.src, []).append(e)
        from collections import deque

        queue: deque[tuple[tuple, list[Edge]]] = deque([(ENTRY, [])])
        seen = {ENTRY}
        while queue:
            node, chain = queue.popleft()
            if node == dst_key:
                return chain
            for e in adj.get(node, []):
                if e.dst not in seen:
                    seen.add(e.dst)
                    queue.append((e.dst, chain + [e]))
        return []

    def impact_paths(self) -> list[list[Edge]]:
        """All proven chains from ENTRY to an impact capability."""
        out = []
        for cap in self._caps.values():
            if cap.kind.lower() in IMPACT_KINDS:
                chain = self.path_to(cap.key())
                if chain:
                    out.append(chain)
        return out

    def to_dict(self) -> dict:
        return {
            "capabilities": [
                {"kind": c.kind, "value": c.value, "host": c.host} for c in self._caps.values()
            ],
            "edges": [
                {"src": list(e.src), "dst": list(e.dst), "exploit": e.exploit, "evidence": e.evidence[:200]}
                for e in self._edges
            ],
            "impact_reached": self.impact_reached(),
        }

    def summary_for_prompt(self) -> str:
        """A compact textual state a reasoning planner can consume."""
        if not self._caps:
            return "No capabilities obtained yet (only entry access)."
        caps = "; ".join(
            f"{c.kind}={c.value}@{c.host}" if c.value or c.host else c.kind for c in self._caps.values()
        )
        return f"Obtained capabilities: {caps}. Impact reached: {self.impact_reached()}."


def graph_from_facts(facts: object) -> AttackGraph:
    """Snapshot the intel accumulated so far (``ExtractedFacts``) as attack-graph
    capabilities, so a reasoning planner can compose over them.

    Pragmatic bridge (duck-typed): maps hosts/users/creds/hashes/domains into
    capabilities. Edges are from ENTRY — a flat "obtained intel" view, not the
    full proven chain (that grows edge-by-edge as exploits are confirmed). Enough
    state to nudge the model to think "what do I have -> what does it unlock".
    """
    g = AttackGraph()
    for h in getattr(facts, "hosts", ()) or ():
        g.add_edge(None, Capability("access", "recon", str(h)), "recon")
    for u in getattr(facts, "users", ()) or ():
        g.add_edge(None, Capability("user", str(u)), "enum")
    for c in getattr(facts, "creds", ()) or ():
        user = c[0] if isinstance(c, (tuple, list)) and c else str(c)
        g.add_edge(None, Capability("cred", str(user)), "cred-capture")
    if getattr(facts, "hashes", ()):  # having hashes is one capability (offline crack)
        g.add_edge(None, Capability("secret", "hash"), "hash-capture")
    for d in getattr(facts, "domains", ()) or ():
        g.add_edge(None, Capability("domain", str(d)), "enum")
    return g

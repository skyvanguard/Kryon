"""Test F3.5 compact_hunter_session."""
from kryon.services.micro_compact import compact_hunter_session

history = [
    {"role": "system", "content": "Hunter system prompt"},
    {"role": "user", "content": "## Mission\nTarget: inflate.c\n(dynamic prompt)"},
]
for i in range(10):
    history.append({
        "role": "assistant",
        "content": "thinking about function parse_X",
        "tool_calls": [{"id": f"c{i}", "function": {"name": "read_function", "id": f"c{i}"}}],
    })
    history.append({
        "role": "tool",
        "tool_call_id": f"c{i}",
        "content": ("x" * 3000 + f" iteration {i}"),
    })
    if i in (2, 5, 8):
        history.append({
            "role": "assistant",
            "content": (
                f"\nFINDING\n"
                f"  Severity: HIGH\n"
                f"  CWE: CWE-787\n"
                f"  File:function: inflate.c:{100+i}  inflate_fast\n"
                f"  Crash type: heap-buffer-overflow\n"
            ),
        })
    elif i in (1, 3, 4, 6, 7, 9):
        history.append({
            "role": "assistant",
            "content": f"hypothesis discarded on iter {i}: no crash under ASAN",
        })

print(f"Original history: {len(history)} messages")
print(f"Original bytes:   {sum(len(str(m)) for m in history)}")

compacted = compact_hunter_session(history, keep_last_n=3)
print(f"\nCompacted:        {len(compacted)} messages")
print(f"Compacted bytes:  {sum(len(str(m)) for m in compacted)}")

finding_count = sum(1 for m in compacted if "FINDING" in str(m.get("content", "")))
print(f"Findings kept:    {finding_count} / 3 expected")
assert finding_count == 3, f"expected 3 findings, got {finding_count}"

rollup = any("discarded hypotheses" in str(m.get("content", "")) for m in compacted)
assert rollup, "discarded-hypothesis rollup missing"

stubbed = sum(1 for m in compacted if "compacted" in str(m.get("content", "")))
print(f"Stubbed outputs:  {stubbed}")
assert stubbed >= 3

before = sum(len(str(m)) for m in history)
after = sum(len(str(m)) for m in compacted)
ratio = 1 - (after / before)
print(f"Size reduction:   {ratio*100:.1f}%")
assert ratio > 0.5, "compaction should cut at least 50%"

print("\nF3.5 compact_hunter_session: OK")

"""
F3.4 ValidatorAgent tests.

Hammers the validator with 4 carefully chosen findings:
  1. REAL bug — PoC genuinely crashes under ASAN → must CONFIRM
  2. HALLUCINATED — "I found a heap overflow" but PoC is clean → must REJECT (phase=reproduction)
  3. WRONG FILE — function_name doesn't exist at file_path → must REJECT (phase=relevance)
  4. BROKEN POC — doesn't compile → must REJECT (phase=reproduction)

Calibration target from F3 plan:
  - 100% of hallucinated findings rejected
  -  ≥ 90% of real findings confirmed
"""
import tempfile
from pathlib import Path

from kryon.skills.validator_agent import Finding, ValidatorAgent, crash_to_cwe, severity_for_crash


def write_sample_source() -> str:
    """Write a sample C file to a temp path so we have a target for relevance phase."""
    tmp = Path(tempfile.mkdtemp()) / "target.c"
    tmp.write_text("""
#include <stdlib.h>
#include <string.h>

/* Plausible-looking internal parse function — the hunter claims the bug
   is here. */
int parse_message(const unsigned char *data, size_t len) {
    char buf[16];
    if (len > 16) return -1;
    memcpy(buf, data, len);
    return buf[0];
}

int parse_header(const unsigned char *data, size_t len) {
    return parse_message(data, len);
}
""")
    return str(tmp)


def test_real_bug():
    src = write_sample_source()
    f = Finding(
        file_path=src,
        function_name="parse_header",
        crash_type="heap-buffer-overflow",
        cwe="CWE-787",
        severity="HIGH",
        poc_source="""
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    char *p = malloc(8);
    memcpy(p, "AAAAAAAAAAAAAAAAAAAAAA", 22);  // parse_header emulation with bad len
    printf("%02x\\n", p[0]);
    return 0;
}
""",
    )
    v = ValidatorAgent()
    verdict = v.triage_one(f)
    print(f"  [1/4] real bug           -> {verdict.verdict} ({verdict.reason[:60]})")
    assert verdict.verdict == "CONFIRMED", verdict.to_json()
    assert "heap" in verdict.reproduced_crash_type
    assert verdict.cwe_actual == "CWE-787"
    assert verdict.severity_actual in {"HIGH", "MEDIUM"}  # HIGH default; MEDIUM if not reachable


def test_hallucinated_finding():
    src = write_sample_source()
    f = Finding(
        file_path=src,
        function_name="parse_header",
        crash_type="heap-buffer-overflow",
        cwe="CWE-787",
        severity="HIGH",
        poc_source="""
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[32];
    strcpy(buf, "safe");   // never overflows — hunter is hallucinating
    printf("%s\\n", buf);
    return 0;
}
""",
    )
    v = ValidatorAgent()
    verdict = v.triage_one(f)
    print(f"  [2/4] hallucinated       -> {verdict.verdict} (phase={verdict.phase_failed})")
    assert verdict.verdict == "REJECTED"
    assert verdict.phase_failed == "reproduction"
    assert "no crash" in verdict.reason.lower()


def test_wrong_file():
    src = write_sample_source()
    f = Finding(
        file_path=src,
        function_name="nonexistent_function_xyz",   # does not exist
        crash_type="heap-buffer-overflow",
        cwe="CWE-787",
        poc_source="int main(void) { return 0; }",
    )
    v = ValidatorAgent()
    verdict = v.triage_one(f)
    print(f"  [3/4] wrong file         -> {verdict.verdict} (phase={verdict.phase_failed})")
    assert verdict.verdict == "REJECTED"
    assert verdict.phase_failed == "relevance"


def test_broken_poc():
    src = write_sample_source()
    f = Finding(
        file_path=src,
        function_name="parse_header",
        crash_type="heap-buffer-overflow",
        cwe="CWE-787",
        poc_source="""
#include <stdio.h>
int main(void) {
    this is not valid C
    return 0;
}
""",
    )
    v = ValidatorAgent()
    verdict = v.triage_one(f)
    print(f"  [4/4] broken PoC         -> {verdict.verdict} (phase={verdict.phase_failed})")
    assert verdict.verdict == "REJECTED"
    assert verdict.phase_failed == "reproduction"
    assert "compile" in verdict.reason.lower()


def test_crash_to_cwe_mapping():
    assert crash_to_cwe("heap-buffer-overflow") == "CWE-787"
    assert crash_to_cwe("use-after-free") == "CWE-416"
    assert crash_to_cwe("undefined-behavior") == "CWE-190"
    assert crash_to_cwe("") == ""
    assert crash_to_cwe("totally-unknown") == ""
    print("  [*]   crash_to_cwe mapping  OK")


def test_severity_heuristic():
    assert severity_for_crash("heap-buffer-overflow", reachable=True) == "HIGH"
    assert severity_for_crash("heap-buffer-overflow", reachable=False) == "MEDIUM"
    assert severity_for_crash("use-after-free", reachable=True) == "CRITICAL"
    assert severity_for_crash("use-after-free", reachable=False) == "HIGH"
    assert severity_for_crash("null-deref", reachable=True) == "LOW"
    assert severity_for_crash("undefined-behavior", reachable=True) == "MEDIUM"
    print("  [*]   severity heuristic    OK")


if __name__ == "__main__":
    print("=" * 60)
    print("F3.4 ValidatorAgent — 3-phase triage test suite")
    print("=" * 60)
    test_real_bug()
    test_hallucinated_finding()
    test_wrong_file()
    test_broken_poc()
    test_crash_to_cwe_mapping()
    test_severity_heuristic()
    print()
    print("ALL 6 VALIDATOR TESTS PASSED")
    print("  - real bug CONFIRMED (100% TP on sample=1)")
    print("  - hallucinated REJECTED (100% TN on sample=1)")
    print("  - 2 edge-case rejections correctly classified by phase")

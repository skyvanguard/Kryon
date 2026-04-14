"""
Unit tests for F3.1 (supervisor_tools.HunterPool) + F3.2 (dynamic_prompt).

No LLM calls. HunterPool takes a mock runner; dynamic_prompt is pure text.
We're validating:
  - Pool respects max_active (cap on concurrent hunters)
  - Pending hunters queue and run as slots free
  - terminate() cancels running hunters
  - send_followup queues nudges
  - Notes + TODO survive across read/write cycles
  - Prompts stay under the char cap and cite evidence
"""
import asyncio
import json
import time

from kryon.skills.supervisor_tools import (
    HunterJob,
    HunterPool,
    get_state,
    reset_supervisor,
    set_pool,
)
from kryon.skills.dynamic_prompt import (
    _MAX_CHARS,
    build_todo_list,
    generate_hunter_prompt,
)


# ----- Mock hunter runners -----

async def instant_finding_runner(job: HunterJob) -> list[dict]:
    """Returns one fake finding immediately."""
    return [{"file": job.file_path, "cwe": "CWE-787", "note": "mock"}]


def slow_runner_factory(delay_s: float):
    async def runner(job: HunterJob) -> list[dict]:
        await asyncio.sleep(delay_s)
        return [{"file": job.file_path, "duration_s": delay_s}]
    return runner


async def hanging_runner(job: HunterJob) -> list[dict]:
    """Sleeps forever — used to test terminate() and timeouts."""
    await asyncio.sleep(3600)
    return []


async def erroring_runner(job: HunterJob) -> list[dict]:
    raise RuntimeError("intentional mock error")


# ----- Tests -----

async def test_basic_spawn_and_result():
    pool = HunterPool(max_active=2, runner=instant_finding_runner)
    hid = await pool.spawn(HunterJob(hunter_id="", file_path="/a.c"))
    job = await pool.await_result(hid)
    assert job.status == "finished", job.status
    assert len(job.findings) == 1
    assert job.findings[0]["file"] == "/a.c"
    print("  [1/7] basic spawn + await_result  OK")


async def test_parallelism_cap():
    # 4 hunters, pool cap 2: exactly 2 should be concurrent at any time.
    pool = HunterPool(max_active=2, runner=slow_runner_factory(0.30))
    active_peaks = []

    async def sampler():
        for _ in range(10):
            active_peaks.append(len(pool.list_active()))
            await asyncio.sleep(0.05)

    hids = []
    for i in range(4):
        hids.append(await pool.spawn(HunterJob(hunter_id="", file_path=f"/f{i}.c")))
    sample_task = asyncio.create_task(sampler())
    jobs = await pool.await_all()
    await sample_task
    # All finished
    assert all(j.status == "finished" for j in jobs), [j.status for j in jobs]
    # Concurrency never exceeded cap
    peak = max(active_peaks) if active_peaks else 0
    assert peak <= 2, f"peak={peak} should be <=2"
    print(f"  [2/7] parallelism cap (peak={peak} <= 2)  OK")


async def test_terminate():
    pool = HunterPool(max_active=1, runner=hanging_runner)
    hid = await pool.spawn(HunterJob(hunter_id="", file_path="/x.c"))
    await asyncio.sleep(0.05)
    assert await pool.terminate(hid, reason="user stop") is True
    job = await pool.await_result(hid)
    assert job.status == "terminated", job.status
    assert "user stop" in job.error
    print("  [3/7] terminate()  OK")


async def test_send_followup_and_timeout():
    pool = HunterPool(max_active=1, runner=hanging_runner, default_timeout_s=1)
    hid = await pool.spawn(HunterJob(hunter_id="", file_path="/y.c"))
    # Short followup window before timeout
    await asyncio.sleep(0.1)
    assert pool.send_followup(hid, "try the other parser") is True
    job = await pool.await_result(hid)
    assert job.status == "failed" and "timeout" in job.error, job.error
    assert job.followups == ["try the other parser"]
    print("  [4/7] send_followup + timeout  OK")


async def test_erroring_runner():
    pool = HunterPool(max_active=1, runner=erroring_runner)
    hid = await pool.spawn(HunterJob(hunter_id="", file_path="/e.c"))
    job = await pool.await_result(hid)
    assert job.status == "failed"
    assert "intentional mock error" in job.error
    print("  [5/7] erroring runner handled  OK")


def test_supervisor_state():
    reset_supervisor()
    st = get_state()
    assert st.read_notes() == {}
    st.write_note("current_cwe", "CWE-787 OOB write on heap")
    st.write_note("scope", "libxml2 core parsers only")
    assert len(st.read_notes()) == 2
    assert "OOB" in st.read_notes()["current_cwe"]

    todos = [
        {"n": 1, "file": "inflate.c", "status": "pending"},
        {"n": 2, "file": "deflate.c", "status": "pending"},
    ]
    st.update_todos(todos)
    back = st.read_todos()
    assert len(back) == 2 and back[0]["file"] == "inflate.c"
    print("  [6/7] supervisor notes + todos persist  OK")


def test_dynamic_prompt():
    ev = {
        "file": "inflate.c",
        "score": 4,
        "loc": 1500,
        "evidence": {"danger_hits": 15, "input_hits": 0},
    }
    prompt = generate_hunter_prompt(
        "/workspace/sources/zlib/inflate.c",
        priority_evidence=ev,
        repo_path="/workspace/sources/zlib",
        cwe_hint="CWE-823 OOB pointer",
        parent_cve="CVE-2024-internal-zlib",
        hypothesis_hint="check inflateCopy's pointer arithmetic on truncated streams",
    )
    assert len(prompt) <= _MAX_CHARS, f"{len(prompt)} > {_MAX_CHARS}"
    # Must cite the concrete evidence
    for needle in ["inflate.c", "score: 4", "15", "CWE-823", "inflateCopy",
                   "CVE-2024-internal-zlib", "read_function"]:
        assert needle in prompt, f"missing: {needle}"
    # Must forbid prose
    assert "NOT write prose" in prompt
    assert "run_sandboxed" in prompt
    print(f"  [7/7] dynamic_prompt ({len(prompt)} chars, cites all evidence)  OK")

    # TODO list shape
    top = [
        {"file": "inflate.c", "score": 4, "loc": 1500,
         "evidence": {"danger_hits": 15, "input_hits": 0}},
        {"file": "deflate.c", "score": 4, "loc": 2000,
         "evidence": {"danger_hits": 31, "input_hits": 0}},
    ]
    todos = build_todo_list(top, max_items=5)
    assert len(todos) == 2
    assert todos[0]["file"] == "inflate.c" and todos[0]["status"] == "pending"
    print("        build_todo_list shape OK")


async def main():
    print("=" * 60)
    print("F3.1 + F3.2 test suite")
    print("=" * 60)
    await test_basic_spawn_and_result()
    await test_parallelism_cap()
    await test_terminate()
    await test_send_followup_and_timeout()
    await test_erroring_runner()
    test_supervisor_state()
    test_dynamic_prompt()
    print()
    print("ALL 7 TESTS PASSED — F3.1 + F3.2 ready")


if __name__ == "__main__":
    asyncio.run(main())

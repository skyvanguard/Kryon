"""Parse a Cybench task's metadata.json into a typed CybenchTask.

Real Cybench task layout (verified against andyzorigin/cybench):
    benchmark/{source}/{competition}/{category}/[Difficulty] Name/
      metadata/metadata.json   <- prompts, subtasks (with answers), target_host
      challenge/               <- files given to the agent
      init_script.sh / stop_script.sh / requirements.sh

metadata.json fields we consume:
    easy_prompt, hard_prompt : str   (the task objective; hard = no hints)
    target_host              : str   ("" for file-only tasks; "host:port" for net)
    categories               : list[str]
    difficulty               : str   ("1".."6")
    subtasks[]               : each has question, answer, answer_format
The FINAL subtask's answer is the flag (the unguided-mode success criterion).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CybenchSubtask:
    question: str
    answer: str
    answer_format: str = ""


@dataclass(frozen=True)
class CybenchTask:
    name: str
    categories: tuple[str, ...]
    difficulty: str
    easy_prompt: str
    hard_prompt: str
    target_host: str
    subtasks: tuple[CybenchSubtask, ...] = field(default_factory=tuple)
    task_dir: Path | None = None

    @property
    def final_answer(self) -> str:
        """The flag — the last subtask's answer (unguided success criterion)."""
        return self.subtasks[-1].answer if self.subtasks else ""

    def prompt(self, *, hard: bool = True) -> str:
        """The objective to hand the agent. hard = no hints (the standard scoring
        mode); falls back to whichever prompt is present."""
        if hard:
            return self.hard_prompt or self.easy_prompt
        return self.easy_prompt or self.hard_prompt


def _task_name_from_dir(task_dir: Path) -> str:
    # ".../crypto/[Very Easy] Dynastic/metadata" -> "[Very Easy] Dynastic"
    p = task_dir
    if p.name == "metadata":
        p = p.parent
    return p.name


def load_task(metadata_path: str | Path) -> CybenchTask:
    """Load a CybenchTask from a metadata.json path (or its containing dir)."""
    path = Path(metadata_path)
    if path.is_dir():
        # accept either the task dir or its metadata/ subdir
        cand = path / "metadata" / "metadata.json"
        path = cand if cand.exists() else path / "metadata.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return from_dict(data, task_dir=path.parent)


def from_dict(data: dict, *, task_dir: Path | None = None) -> CybenchTask:
    """Build a CybenchTask from an already-parsed metadata dict (testable without I/O)."""
    subtasks = tuple(
        CybenchSubtask(
            question=str(s.get("subtask") or s.get("question") or ""),
            answer=str(s.get("answer", "")),
            answer_format=str(s.get("answer_format", "")),
        )
        for s in (data.get("subtasks") or [])
    )
    return CybenchTask(
        name=_task_name_from_dir(task_dir) if task_dir else str(data.get("name", "unknown")),
        categories=tuple(data.get("categories") or []),
        difficulty=str(data.get("difficulty", "")),
        easy_prompt=str(data.get("easy_prompt", "")),
        hard_prompt=str(data.get("hard_prompt", "")),
        target_host=str(data.get("target_host", "")),
        subtasks=subtasks,
        task_dir=task_dir,
    )

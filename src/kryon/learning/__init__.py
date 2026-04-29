"""KRYON self-improving loop — capture, score, and propose skills.

Public API surface for the learning subsystem. Three layers:

  1. Capture (legacy):
       build_profile, extract_chain_from_history, add_experience,
       recall_similar, list_experiences, get_experience,
       delete_experience, count_experiences

  2. Skill drafting (Fase 1):
       SkillDraft, synthesize_draft, try_synthesize_and_persist,
       get_drafts_dir, list_existing_names, read_draft, write_draft,
       delete_draft

  3. Scoring + bandit (Fase 2):
       SkillScore, wilson_lower_bound, score_skills,
       rank_skills_hybrid, rank_skills_score_only,
       log_selection, read_recent

  4. Auto-creation with eval gate (Fase 3):
       ChainCluster, detect_recurrent_chains,
       synthesize_from_cluster,
       EvalReport, evaluate_draft_against_corpus,
       load_cwe_map_override,
       PipelineResult, run_auto_pipeline

See `docs/LEARNING_LOOP.md` (and `CLAUDE.md` Self-improving loop section)
for architecture and data model.
"""

# ---- Capture layer (existing) ----
from kryon.learning.chain_extractor import extract_chain_from_history
from kryon.learning.experiences import (
    add_experience,
    count_experiences,
    delete_experience,
    get_experience,
    list_experiences,
    recall_similar,
)
from kryon.learning.profiler import build_profile

# ---- Drafting layer (Fase 1) ----
from kryon.learning.draft_writer import (
    delete_draft,
    get_drafts_dir,
    list_existing_names,
    read_draft,
    try_synthesize_and_persist,
    write_draft,
)
from kryon.learning.skill_synthesizer import (
    SkillDraft,
    synthesize_draft,
    synthesize_from_cluster,
)

# ---- Scoring + bandit (Fase 2) ----
from kryon.learning.selection_telemetry import (
    log_selection,
    read_recent,
)
from kryon.learning.skill_scorer import (
    SkillScore,
    rank_skills_hybrid,
    rank_skills_score_only,
    score_skills,
    wilson_lower_bound,
)

# ---- Auto-creation with eval gate (Fase 3) ----
from kryon.learning.auto_pipeline import (
    PipelineResult,
    run_auto_pipeline,
)
from kryon.learning.pattern_detector import (
    ChainCluster,
    chain_bigrams,
    chain_similarity,
    detect_recurrent_chains,
    jaccard,
    profile_similarity,
)
from kryon.learning.skill_evaluator import (
    EvalReport,
    evaluate_draft_against_corpus,
    load_cwe_map_override,
)


__all__ = [
    # Capture
    "add_experience",
    "build_profile",
    "count_experiences",
    "delete_experience",
    "extract_chain_from_history",
    "get_experience",
    "list_experiences",
    "recall_similar",
    # Drafting
    "SkillDraft",
    "synthesize_draft",
    "synthesize_from_cluster",
    "try_synthesize_and_persist",
    "get_drafts_dir",
    "list_existing_names",
    "read_draft",
    "write_draft",
    "delete_draft",
    # Scoring + bandit
    "SkillScore",
    "wilson_lower_bound",
    "score_skills",
    "rank_skills_hybrid",
    "rank_skills_score_only",
    "log_selection",
    "read_recent",
    # Auto-creation
    "ChainCluster",
    "chain_bigrams",
    "jaccard",
    "chain_similarity",
    "profile_similarity",
    "detect_recurrent_chains",
    "EvalReport",
    "evaluate_draft_against_corpus",
    "load_cwe_map_override",
    "PipelineResult",
    "run_auto_pipeline",
]

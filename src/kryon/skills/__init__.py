"""
KRYON Skill System — dynamic markdown-based playbooks.

Skills replace the 33 static Python agent files with hot-reloadable
markdown playbooks that are matched to targets by tech/port/keyword
triggers and injected into a single unified agent's prompt.

See docs/LEARNING_LOOP.md for the full architecture.

Usage:
    from kryon.skills import SkillLoader, create_unified_agent

    loader = SkillLoader()
    skills = loader.match(profile, user_msg="analizar seguridad")
    agent = create_unified_agent(skills=skills)
"""

from kryon.skills.loader import Skill, SkillLoader
from kryon.skills.unified_agent import create_unified_agent

__all__ = ["Skill", "SkillLoader", "create_unified_agent"]

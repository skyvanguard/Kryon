"""Core module for Skynet framework."""

from .config import get_config, load_config, SkynetConfig
from .logging import get_logger, SkynetLogger
from .executor import CommandExecutor, ExecutionResult
from .agent_manager import get_agent_manager, AgentManager, AgentStatus
from .flag_detector import get_flag_detector, FlagDetector, detect_flags_in_output

__all__ = [
    'get_config',
    'load_config',
    'SkynetConfig',
    'get_logger',
    'SkynetLogger',
    'CommandExecutor',
    'ExecutionResult',
    'get_agent_manager',
    'AgentManager',
    'AgentStatus',
    'get_flag_detector',
    'FlagDetector',
    'detect_flags_in_output',
]

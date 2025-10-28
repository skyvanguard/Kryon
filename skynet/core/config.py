"""
Configuration module for Skynet framework.
Handles environment variables, API keys, and system settings.
"""
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import json
from pathlib import Path


@dataclass
class SkynetConfig:
    """Main configuration class for Skynet framework."""

    # API Configuration
    anthropic_api_key: Optional[str] = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    openai_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))

    # Model Configuration
    default_model: str = "claude-sonnet-4"
    temperature: float = 0.7
    max_tokens: int = 4096

    # System Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data")
    vector_db_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data" / "vector_db")
    knowledge_base_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data" / "ctf_knowledge")

    # RAG Configuration
    embedding_model: str = "text-embedding-3-small"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    top_k_results: int = 5

    # Agent Configuration
    max_iterations: int = 25
    enable_human_in_loop: bool = True
    verbose: bool = True

    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[Path] = field(default_factory=lambda: Path(__file__).parent.parent.parent / "skynet.log")
    enable_tracing: bool = True

    # Security Configuration
    sandbox_mode: bool = True
    allowed_commands: list = field(default_factory=lambda: [
        "nmap", "gobuster", "nikto", "sqlmap", "hydra",
        "john", "hashcat", "binwalk", "strings", "file",
        "curl", "wget", "nc", "netcat", "dig", "nslookup"
    ])

    def __post_init__(self):
        """Ensure required directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vector_db_path.mkdir(parents=True, exist_ok=True)
        self.knowledge_base_path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_file(cls, config_path: str) -> "SkynetConfig":
        """Load configuration from JSON file."""
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        return cls(**config_data)

    def to_file(self, config_path: str):
        """Save configuration to JSON file."""
        config_data = {
            "default_model": self.default_model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "embedding_model": self.embedding_model,
            "chunk_size": self.chunk_size,
            "chunk_overlap": self.chunk_overlap,
            "top_k_results": self.top_k_results,
            "max_iterations": self.max_iterations,
            "enable_human_in_loop": self.enable_human_in_loop,
            "verbose": self.verbose,
            "log_level": self.log_level,
            "enable_tracing": self.enable_tracing,
            "sandbox_mode": self.sandbox_mode,
            "allowed_commands": self.allowed_commands
        }
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)

    def validate(self) -> bool:
        """Validate configuration settings."""
        if not self.anthropic_api_key and not self.openai_api_key:
            raise ValueError("At least one API key (ANTHROPIC_API_KEY or OPENAI_API_KEY) must be set")

        if self.temperature < 0 or self.temperature > 1:
            raise ValueError("Temperature must be between 0 and 1")

        if self.max_iterations < 1:
            raise ValueError("max_iterations must be at least 1")

        return True


# Global configuration instance
_config: Optional[SkynetConfig] = None


def get_config() -> SkynetConfig:
    """Get or create the global configuration instance."""
    global _config
    if _config is None:
        _config = SkynetConfig()
    return _config


def set_config(config: SkynetConfig):
    """Set the global configuration instance."""
    global _config
    _config = config


def load_config(config_path: str):
    """Load configuration from file and set as global."""
    config = SkynetConfig.from_file(config_path)
    set_config(config)
    return config

"""
Flag detection and validation system for Skynet.
Automatically detects and extracts flags from command outputs.
"""
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json

from .logging import get_logger


@dataclass
class Flag:
    """Represents a discovered flag."""
    value: str
    format_type: str
    source: str
    timestamp: float
    context: str  # Surrounding text for context


class FlagDetector:
    """Detects and tracks CTF flags across different formats."""

    # Common CTF flag patterns
    PATTERNS = {
        "htb": r"HTB\{[A-Za-z0-9_!@#$%^&*()-+=]{4,}\}",
        "ctfd": r"flag\{[A-Za-z0-9_!@#$%^&*()-+=]{4,}\}",
        "picoctf": r"picoCTF\{[A-Za-z0-9_!@#$%^&*()-+=]{4,}\}",
        "root_flag": r"root\.txt:\s*([A-Fa-f0-9]{32})",
        "user_flag": r"user\.txt:\s*([A-Fa-f0-9]{32})",
        "generic_curly": r"[A-Za-z0-9_-]+\{[A-Za-z0-9_!@#$%^&*()-+=]{8,}\}",
        "md5_hash": r"\b[A-Fa-f0-9]{32}\b",
        "sha256_hash": r"\b[A-Fa-f0-9]{64}\b",
        "uuid": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "base64_long": r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
    }

    def __init__(self, flags_file: Optional[Path] = None):
        self.logger = get_logger()
        self.found_flags: Set[str] = set()

        if flags_file is None:
            flags_file = Path.home() / ".skynet" / "flags.json"

        self.flags_file = flags_file
        self.flags_file.parent.mkdir(parents=True, exist_ok=True)

        self._load_flags()

    def _load_flags(self):
        """Load previously found flags."""
        if self.flags_file.exists():
            try:
                with open(self.flags_file, 'r') as f:
                    data = json.load(f)
                    self.found_flags = set(data.get('flags', []))
            except Exception as e:
                self.logger.warning(f"Could not load flags file: {e}")

    def _save_flag(self, flag: Flag):
        """Save a newly found flag."""
        # Load existing
        existing_data = {'flags': list(self.found_flags), 'details': []}
        if self.flags_file.exists():
            try:
                with open(self.flags_file, 'r') as f:
                    existing_data = json.load(f)
            except:
                pass

        # Add new flag
        existing_data['flags'].append(flag.value)
        existing_data['details'].append({
            'value': flag.value,
            'type': flag.format_type,
            'source': flag.source,
            'timestamp': flag.timestamp,
            'context': flag.context[:200]  # Truncate context
        })

        # Save
        with open(self.flags_file, 'w') as f:
            json.dump(existing_data, f, indent=2)

        self.found_flags.add(flag.value)

    def detect(self, text: str, source: str = "unknown") -> List[Flag]:
        """
        Detect flags in text.

        Args:
            text: Text to search for flags
            source: Source of the text (command name, file path, etc.)

        Returns:
            List of detected flags
        """
        detected_flags = []

        for flag_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                flag_value = match.group(0)

                # Skip if already found
                if flag_value in self.found_flags:
                    continue

                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                flag = Flag(
                    value=flag_value,
                    format_type=flag_type,
                    source=source,
                    timestamp=datetime.now().timestamp(),
                    context=context
                )

                detected_flags.append(flag)
                self._save_flag(flag)

                # Log the discovery
                self.logger.info(f"🚩 FLAG FOUND: {flag_value} (type: {flag_type}, source: {source})")

        return detected_flags

    def detect_in_file(self, file_path: Path) -> List[Flag]:
        """
        Detect flags in a file.

        Args:
            file_path: Path to file

        Returns:
            List of detected flags
        """
        try:
            content = file_path.read_text(errors='ignore')
            return self.detect(content, source=str(file_path))
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return []

    def is_flag(self, text: str) -> bool:
        """
        Quick check if text contains a flag.

        Args:
            text: Text to check

        Returns:
            True if flag pattern detected
        """
        for pattern in self.PATTERNS.values():
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def get_found_flags(self) -> List[Dict]:
        """Get all found flags with details."""
        if not self.flags_file.exists():
            return []

        try:
            with open(self.flags_file, 'r') as f:
                data = json.load(f)
                return data.get('details', [])
        except:
            return []

    def count_flags(self) -> int:
        """Get count of found flags."""
        return len(self.found_flags)

    def add_custom_pattern(self, name: str, pattern: str):
        """
        Add a custom flag pattern.

        Args:
            name: Name for the pattern
            pattern: Regex pattern
        """
        self.PATTERNS[name] = pattern
        self.logger.info(f"Added custom flag pattern: {name}")

    def clear_flags(self):
        """Clear all found flags (use with caution)."""
        self.found_flags.clear()
        if self.flags_file.exists():
            self.flags_file.unlink()
        self.logger.info("Cleared all found flags")


# Global flag detector instance
_flag_detector: Optional[FlagDetector] = None


def get_flag_detector() -> FlagDetector:
    """Get or create the global flag detector instance."""
    global _flag_detector
    if _flag_detector is None:
        _flag_detector = FlagDetector()
    return _flag_detector


def detect_flags_in_output(output: str, source: str = "command") -> List[Flag]:
    """
    Convenience function to detect flags in command output.

    Args:
        output: Command output to search
        source: Source identifier

    Returns:
        List of detected flags
    """
    detector = get_flag_detector()
    return detector.detect(output, source)

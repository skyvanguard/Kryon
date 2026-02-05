"""
Code Processor
==============

Process source code files for knowledge base.
"""

import re
from pathlib import Path
from typing import Any


class CodeProcessor:
    """
    Process source code files.

    Extracts:
    - Functions/methods
    - Classes
    - Comments/docstrings
    - Imports
    """

    def __init__(self):
        """Initialize code processor."""
        self.supported_extensions = [
            ".py",
            ".js",
            ".java",
            ".c",
            ".cpp",
            ".go",
            ".rb",
            ".php",
            ".sh",
            ".ps1",
        ]

    def process_file(self, file_path: str) -> list[dict[str, Any]]:
        """
        Process a code file.

        Args:
            file_path: Path to code file

        Returns:
            List of code snippets with metadata
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        extension = file_path.suffix.lower()

        if extension == ".py":
            return self._process_python(file_path)
        elif extension in [".sh", ".bash"]:
            return self._process_shell(file_path)
        else:
            # Generic code processing
            return self._process_generic(file_path)

    def _process_python(self, file_path: Path) -> list[dict[str, Any]]:
        """Process Python file."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            chunks = []

            # Extract functions
            func_pattern = r'def\s+(\w+)\s*\([^)]*\):\s*"""([^"]*)"""'
            for match in re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL):
                func_name = match.group(1)
                docstring = match.group(2).strip()

                # Get full function code
                start = match.start()
                func_code = self._extract_function_body(content, start)

                chunks.append(
                    {
                        "content": f"**Python Function: {func_name}**\n\nDocstring:\n{docstring}\n\nCode:\n```python\n{func_code[:500]}\n```",
                        "metadata": {
                            "file": str(file_path.name),
                            "type": "function",
                            "name": func_name,
                            "language": "python",
                            "file_type": "code",
                        },
                    }
                )

            # Extract classes
            class_pattern = r'class\s+(\w+).*?:\s*"""([^"]*)"""'
            for match in re.finditer(class_pattern, content, re.MULTILINE | re.DOTALL):
                class_name = match.group(1)
                docstring = match.group(2).strip()

                chunks.append(
                    {
                        "content": f"**Python Class: {class_name}**\n\nDocstring:\n{docstring}",
                        "metadata": {
                            "file": str(file_path.name),
                            "type": "class",
                            "name": class_name,
                            "language": "python",
                            "file_type": "code",
                        },
                    }
                )

            return chunks if chunks else self._process_generic(file_path)

        except Exception as e:
            print(f"Error processing Python {file_path}: {e}")
            return []

    def _process_shell(self, file_path: Path) -> list[dict[str, Any]]:
        """Process shell script."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            chunks = []

            # Extract functions
            func_pattern = r"function\s+(\w+)\s*\(\)\s*\{([^}]+)\}"
            for match in re.finditer(func_pattern, content):
                func_name = match.group(1)
                func_body = match.group(2).strip()

                chunks.append(
                    {
                        "content": f"**Shell Function: {func_name}**\n\nCode:\n```bash\n{func_body}\n```",
                        "metadata": {
                            "file": str(file_path.name),
                            "type": "function",
                            "name": func_name,
                            "language": "bash",
                            "file_type": "code",
                        },
                    }
                )

            return chunks if chunks else self._process_generic(file_path)

        except Exception as e:
            print(f"Error processing shell {file_path}: {e}")
            return []

    def _process_generic(self, file_path: Path) -> list[dict[str, Any]]:
        """Process code file generically."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Simple chunking
            lines = content.split("\n")
            chunk_size = 50  # Lines per chunk

            chunks = []
            for i in range(0, len(lines), chunk_size):
                chunk_lines = lines[i : i + chunk_size]
                chunk_content = "\n".join(chunk_lines)

                chunks.append(
                    {
                        "content": f"**Code from {file_path.name}**\n\n```\n{chunk_content[:1000]}\n```",
                        "metadata": {
                            "file": str(file_path.name),
                            "chunk": i // chunk_size,
                            "language": file_path.suffix[1:],  # Remove dot
                            "file_type": "code",
                        },
                    }
                )

            return chunks

        except Exception as e:
            print(f"Error processing generic code {file_path}: {e}")
            return []

    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """
        Extract full function body from position.

        Simple implementation - finds indented block.
        """
        lines = content[start_pos:].split("\n")
        func_lines = [lines[0]]  # Function definition

        if len(lines) < 2:
            return func_lines[0]

        # Find base indentation
        base_indent = len(lines[1]) - len(lines[1].lstrip())

        for line in lines[1:]:
            if line.strip():  # Non-empty line
                indent = len(line) - len(line.lstrip())
                if indent >= base_indent:
                    func_lines.append(line)
                else:
                    break  # Function ended
            else:
                func_lines.append(line)  # Empty line within function

        return "\n".join(func_lines)


# Convenience function
def process_code(file_path: str) -> list[dict]:
    """Process a code file."""
    processor = CodeProcessor()
    return processor.process_file(file_path)

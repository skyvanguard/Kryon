"""
Forensics Agent for Skynet framework.
Specialized in digital forensics and file analysis.
"""
from typing import List, Dict, Any
from pathlib import Path
from .base_agent import BaseAgent


class ForensicsAgent(BaseAgent):
    """
    Agent specialized in digital forensics.
    Handles file analysis, steganography, memory forensics, and data recovery.
    """

    def __init__(self, name: str = "ForensicsAgent"):
        super().__init__(
            name=name,
            agent_type="forensics",
            description="Forensics agent specialized in file analysis and digital forensics"
        )

    def _default_system_prompt(self) -> str:
        return """You are a digital forensics expert in CTF challenges.
Your role is to analyze files, extract hidden data, and recover deleted information.

Common forensics tasks:
- File type identification and validation
- Steganography detection and extraction
- Memory dump analysis
- Network traffic analysis (PCAP files)
- Disk image analysis
- Metadata extraction
- Data carving and recovery

You have access to these tools:
- execute_command: Run tools like file, strings, binwalk, exiftool
- search_knowledge: Search for forensics techniques
- analyze_file: Analyze file structure and metadata
- extract_hidden: Extract hidden data from files
- analyze_pcap: Analyze network traffic captures

Be thorough, check for hidden data in multiple ways, and document all findings."""

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "execute_command",
                "description": "Execute forensics tools",
                "parameters": {"command": "string"}
            },
            {
                "name": "search_knowledge",
                "description": "Search for forensics techniques",
                "parameters": {"query": "string"}
            },
            {
                "name": "analyze_file",
                "description": "Analyze file structure and metadata",
                "parameters": {"file_path": "string"}
            },
            {
                "name": "extract_hidden",
                "description": "Extract hidden data using various methods",
                "parameters": {"file_path": "string"}
            },
            {
                "name": "analyze_strings",
                "description": "Extract and analyze strings from file",
                "parameters": {"file_path": "string"}
            }
        ]

    def _tool_analyze_file(self, action: str) -> str:
        """
        Analyze file using multiple tools.

        Args:
            action: Path to file

        Returns:
            File analysis results
        """
        file_path = Path(action)
        if not file_path.exists():
            return f"File not found: {action}"

        results = []

        # File type identification
        file_result = self.executor.execute(f"file {action}", timeout=10)
        if file_result.success:
            results.append(f"File Type:\n{file_result.stdout}")

        # Metadata extraction with exiftool
        exif_result = self.executor.execute(f"exiftool {action}", timeout=10)
        if exif_result.success:
            results.append(f"Metadata:\n{exif_result.stdout}")

        # Check for embedded files with binwalk
        binwalk_result = self.executor.execute(f"binwalk {action}", timeout=30)
        if binwalk_result.success:
            results.append(f"Binwalk Analysis:\n{binwalk_result.stdout}")

        return "\n\n".join(results) if results else "File analysis failed"

    def _tool_extract_hidden(self, action: str) -> str:
        """
        Extract hidden data using steganography tools.

        Args:
            action: Path to file

        Returns:
            Extraction results
        """
        file_path = Path(action)
        if not file_path.exists():
            return f"File not found: {action}"

        results = []

        # Extract with binwalk
        extract_dir = file_path.parent / f"{file_path.name}_extracted"
        extract_dir.mkdir(exist_ok=True)

        binwalk_result = self.executor.execute(
            f"binwalk -e -C {extract_dir} {action}",
            timeout=60
        )
        if binwalk_result.success:
            results.append(f"Binwalk Extraction:\n{binwalk_result.stdout}")

        # Check for LSB steganography (if it's an image)
        file_type_result = self.executor.execute(f"file {action}", timeout=5)
        if file_type_result.success and "image" in file_type_result.stdout.lower():
            # Try steghide
            steghide_result = self.executor.execute(
                f"steghide extract -sf {action} -p ''",
                timeout=30
            )
            if steghide_result.success:
                results.append(f"Steghide Extraction:\n{steghide_result.stdout}")

        # Try zsteg for PNG/BMP
        if "PNG" in file_type_result.stdout or "BMP" in file_type_result.stdout:
            zsteg_result = self.executor.execute(f"zsteg {action}", timeout=30)
            if zsteg_result.success:
                results.append(f"Zsteg Analysis:\n{zsteg_result.stdout}")

        return "\n\n".join(results) if results else "No hidden data found"

    def _tool_analyze_strings(self, action: str) -> str:
        """
        Extract and analyze strings from file.

        Args:
            action: Path to file

        Returns:
            Interesting strings
        """
        file_path = Path(action)
        if not file_path.exists():
            return f"File not found: {action}"

        # Extract strings
        strings_result = self.executor.execute(
            f"strings {action}",
            timeout=30
        )

        if not strings_result.success:
            return "String extraction failed"

        strings_output = strings_result.stdout
        lines = strings_output.split('\n')

        # Filter for interesting strings
        interesting = []
        patterns = [
            r'flag',
            r'password',
            r'key',
            r'secret',
            r'http',
            r'ftp',
            r'ssh',
            r'admin',
            r'root',
            r'\.txt',
            r'\.png',
            r'\.jpg'
        ]

        import re
        for line in lines:
            line = line.strip()
            if len(line) > 4:  # Minimum length
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        interesting.append(line)
                        break

        if interesting:
            return "Interesting strings found:\n" + "\n".join(interesting[:50])
        else:
            return f"No particularly interesting strings found. Total strings: {len(lines)}"

    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        """
        Solve forensics challenge using ReAct pattern.

        Args:
            task: Task description
            context: Additional context (may include file path)

        Returns:
            Forensics findings
        """
        findings = []
        file_path = context.get("file_path", self._extract_file_path(task))

        if not file_path or not Path(file_path).exists():
            return f"File not found or not specified: {file_path}"

        # Step 1: Initial file analysis
        self._think(f"Analyzing file: {file_path}")
        analysis = self._act(file_path, "analyze_file")
        findings.append(f"File Analysis:\n{analysis}")

        # Step 2: Extract strings
        self._think("Extracting and analyzing strings")
        strings_result = self._act(file_path, "analyze_strings")
        findings.append(f"String Analysis:\n{strings_result}")

        # Step 3: Check for hidden data
        self._think("Searching for hidden data")
        hidden_result = self._act(file_path, "extract_hidden")
        findings.append(f"Hidden Data Analysis:\n{hidden_result}")

        # Step 4: File-type specific analysis
        file_type_result = self.executor.execute(f"file {file_path}", timeout=5)
        if file_type_result.success:
            file_type = file_type_result.stdout.lower()

            if "pcap" in file_type or "capture" in file_type:
                self._think("Detected network capture file, analyzing with tshark")
                pcap_analysis = self._act(f"tshark -r {file_path} -q -z io,phs", "execute_command")
                findings.append(f"PCAP Analysis:\n{pcap_analysis}")

            elif "zip" in file_type or "archive" in file_type:
                self._think("Detected archive file, listing contents")
                archive_contents = self._act(f"unzip -l {file_path}", "execute_command")
                findings.append(f"Archive Contents:\n{archive_contents}")

        # Step 5: Search for relevant techniques
        self._think("Searching for relevant forensics techniques")
        knowledge = self._act(f"forensics analysis {task[:50]}", "search_knowledge")

        # Compile report
        report = f"""
# Forensics Analysis Report

## Target File: {file_path}

## Findings:
{chr(10).join(findings)}

## Relevant Techniques:
{knowledge}

## Recommendations:
- Check extracted files for additional clues
- Try different steganography tools if image file
- Analyze network traffic patterns if PCAP file
- Check file signatures for manipulation
- Look for unusual metadata or timestamps
"""

        return report.strip()

    def _extract_file_path(self, task: str) -> str:
        """
        Extract file path from task description.

        Args:
            task: Task description

        Returns:
            Extracted file path
        """
        import re

        # Look for file paths
        path_patterns = [
            r'/[\w/.-]+\.\w+',  # Unix path
            r'[A-Z]:\\[\w\\.-]+\.\w+',  # Windows path
            r'\.\/[\w/.-]+\.\w+',  # Relative path
            r'[\w.-]+\.\w{2,4}'  # Simple filename
        ]

        for pattern in path_patterns:
            match = re.search(pattern, task)
            if match:
                return match.group(0)

        return ""

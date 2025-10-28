"""
Analysis and forensics tools wrapper for Skynet framework.
Provides convenient interfaces to file analysis and forensics tools.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from ..core.executor import CommandExecutor, ExecutionResult


@dataclass
class FileAnalysis:
    """Result of file analysis."""
    file_path: Path
    file_type: str
    size: int
    md5: str
    sha256: str
    metadata: Dict[str, Any]
    strings_found: List[str]


@dataclass
class HashCrackResult:
    """Result of hash cracking attempt."""
    hash_value: str
    hash_type: str
    cracked: bool
    plaintext: Optional[str]
    method: str


class AnalysisTools:
    """Wrapper for analysis and forensics tools."""

    def __init__(self):
        self.executor = CommandExecutor()

    def analyze_file(self, file_path: Path) -> FileAnalysis:
        """
        Comprehensive file analysis.

        Args:
            file_path: Path to file

        Returns:
            FileAnalysis with detailed information
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Get file type
        file_result = self.executor.execute(f"file {file_path}", timeout=10)
        file_type = file_result.stdout.strip() if file_result.success else "unknown"

        # Get file size
        size = file_path.stat().st_size

        # Calculate hashes
        md5_result = self.executor.execute(f"md5sum {file_path}", timeout=30)
        md5 = md5_result.stdout.split()[0] if md5_result.success else ""

        sha256_result = self.executor.execute(f"sha256sum {file_path}", timeout=30)
        sha256 = sha256_result.stdout.split()[0] if sha256_result.success else ""

        # Get metadata with exiftool
        metadata = {}
        exif_result = self.executor.execute(f"exiftool {file_path}", timeout=30)
        if exif_result.success:
            for line in exif_result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()

        # Extract strings
        strings_result = self.executor.execute(f"strings {file_path} | head -100", timeout=30)
        strings_found = []
        if strings_result.success:
            strings_found = [
                s.strip() for s in strings_result.stdout.split('\n')
                if s.strip() and len(s.strip()) > 4
            ]

        return FileAnalysis(
            file_path=file_path,
            file_type=file_type,
            size=size,
            md5=md5,
            sha256=sha256,
            metadata=metadata,
            strings_found=strings_found
        )

    def extract_strings(
        self,
        file_path: Path,
        min_length: int = 4,
        max_results: int = 1000
    ) -> List[str]:
        """
        Extract printable strings from file.

        Args:
            file_path: Path to file
            min_length: Minimum string length
            max_results: Maximum number of results

        Returns:
            List of extracted strings
        """
        command = f"strings -n {min_length} {file_path} | head -{max_results}"
        result = self.executor.execute(command, timeout=60)

        if result.success:
            return [s.strip() for s in result.stdout.split('\n') if s.strip()]

        return []

    def binwalk_analyze(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze file with binwalk for embedded files.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with analysis results
        """
        result = self.executor.execute(f"binwalk {file_path}", timeout=60)

        embedded_files = []
        if result.success:
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('DECIMAL'):
                    embedded_files.append(line.strip())

        return {
            "file": str(file_path),
            "embedded_files": embedded_files,
            "raw_output": result.stdout
        }

    def binwalk_extract(self, file_path: Path, output_dir: Optional[Path] = None) -> Path:
        """
        Extract embedded files with binwalk.

        Args:
            file_path: Path to file
            output_dir: Output directory (creates one if not specified)

        Returns:
            Path to extraction directory
        """
        if output_dir is None:
            output_dir = file_path.parent / f"{file_path.name}_extracted"

        output_dir.mkdir(exist_ok=True, parents=True)

        command = f"binwalk -e -C {output_dir} {file_path}"
        self.executor.execute(command, timeout=120)

        return output_dir

    def steghide_extract(
        self,
        file_path: Path,
        passphrase: str = "",
        output_file: Optional[Path] = None
    ) -> ExecutionResult:
        """
        Extract hidden data with steghide.

        Args:
            file_path: Path to file
            passphrase: Steghide passphrase
            output_file: Output file path

        Returns:
            ExecutionResult
        """
        command = f"steghide extract -sf {file_path} -p '{passphrase}'"

        if output_file:
            command += f" -xf {output_file}"

        return self.executor.execute(command, timeout=30)

    def zsteg_analyze(self, file_path: Path) -> ExecutionResult:
        """
        Analyze PNG/BMP with zsteg.

        Args:
            file_path: Path to image file

        Returns:
            ExecutionResult with zsteg analysis
        """
        command = f"zsteg -a {file_path}"
        return self.executor.execute(command, timeout=60)

    def crack_hash(
        self,
        hash_value: str,
        hash_type: Optional[str] = None,
        wordlist: Optional[Path] = None
    ) -> HashCrackResult:
        """
        Attempt to crack a password hash.

        Args:
            hash_value: Hash to crack
            hash_type: Hash type (md5, sha1, sha256, etc.)
            wordlist: Path to wordlist

        Returns:
            HashCrackResult
        """
        if wordlist is None:
            wordlist = Path("/usr/share/wordlists/rockyou.txt")

        # Auto-detect hash type if not specified
        if hash_type is None:
            hash_type = self._detect_hash_type(hash_value)

        # Try john the ripper
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write(hash_value)
            hash_file = f.name

        # Run john
        crack_command = f"john --wordlist={wordlist} --format={hash_type} {hash_file}"
        self.executor.execute(crack_command, timeout=120)

        # Try to get result
        show_result = self.executor.execute(f"john --show {hash_file}", timeout=5)

        cracked = False
        plaintext = None

        if show_result.success and ':' in show_result.stdout:
            parts = show_result.stdout.split(':')
            if len(parts) >= 2:
                plaintext = parts[1].strip()
                cracked = True

        return HashCrackResult(
            hash_value=hash_value,
            hash_type=hash_type,
            cracked=cracked,
            plaintext=plaintext,
            method="john"
        )

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length and format."""
        hash_len = len(hash_value.strip())

        if hash_len == 32:
            return "md5"
        elif hash_len == 40:
            return "sha1"
        elif hash_len == 64:
            return "sha256"
        elif hash_len == 128:
            return "sha512"
        elif hash_value.startswith("$2"):
            return "bcrypt"
        elif hash_value.startswith("$6$"):
            return "sha512crypt"

        return "raw-md5"  # Default

    def hex_dump(self, file_path: Path, length: int = 512) -> str:
        """
        Get hex dump of file.

        Args:
            file_path: Path to file
            length: Number of bytes to dump

        Returns:
            Hex dump output
        """
        command = f"hexdump -C {file_path} | head -n {length // 16}"
        result = self.executor.execute(command, timeout=30)

        return result.stdout if result.success else ""

    def diff_files(self, file1: Path, file2: Path) -> str:
        """
        Compare two files.

        Args:
            file1: First file
            file2: Second file

        Returns:
            Diff output
        """
        command = f"diff -u {file1} {file2}"
        result = self.executor.execute(command, timeout=30)

        return result.stdout

    def file_entropy(self, file_path: Path) -> float:
        """
        Calculate file entropy (useful for detecting encryption/compression).

        Args:
            file_path: Path to file

        Returns:
            Entropy value (0-8, higher = more random)
        """
        import math
        from collections import Counter

        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        # Calculate byte frequency
        counter = Counter(data)
        length = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def pcap_analyze(self, pcap_path: Path) -> Dict[str, Any]:
        """
        Analyze PCAP file with tshark.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            Analysis results
        """
        results = {}

        # Get statistics
        stats_result = self.executor.execute(
            f"tshark -r {pcap_path} -q -z io,phs",
            timeout=60
        )
        results['protocol_hierarchy'] = stats_result.stdout if stats_result.success else ""

        # Extract HTTP requests
        http_result = self.executor.execute(
            f"tshark -r {pcap_path} -Y 'http.request' -T fields -e http.request.full_uri",
            timeout=60
        )
        results['http_requests'] = (
            [line.strip() for line in http_result.stdout.split('\n') if line.strip()]
            if http_result.success else []
        )

        # Extract credentials
        creds_result = self.executor.execute(
            f"tshark -r {pcap_path} -Y 'http.request.method==POST' -T fields -e text",
            timeout=60
        )
        results['potential_credentials'] = (
            [line.strip() for line in creds_result.stdout.split('\n') if line.strip()]
            if creds_result.success else []
        )

        return results

    def volatility_analyze(self, memory_dump: Path, profile: str = "Win7SP1x64") -> Dict[str, Any]:
        """
        Analyze memory dump with Volatility.

        Args:
            memory_dump: Path to memory dump
            profile: Memory profile

        Returns:
            Analysis results
        """
        results = {}

        # List processes
        pslist = self.executor.execute(
            f"volatility -f {memory_dump} --profile={profile} pslist",
            timeout=300
        )
        results['processes'] = pslist.stdout if pslist.success else ""

        # Network connections
        netscan = self.executor.execute(
            f"volatility -f {memory_dump} --profile={profile} netscan",
            timeout=300
        )
        results['network'] = netscan.stdout if netscan.success else ""

        return results


# Convenience function
def get_analysis_tools() -> AnalysisTools:
    """Get AnalysisTools instance."""
    return AnalysisTools()

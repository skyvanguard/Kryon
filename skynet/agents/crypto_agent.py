"""
Cryptography Agent for Skynet framework.
Specialized in cryptanalysis and breaking encryption challenges.
"""
from typing import List, Dict, Any
from .base_agent import BaseAgent


class CryptoAgent(BaseAgent):
    """
    Agent specialized in cryptography and cryptanalysis.
    Handles classical ciphers, modern crypto, hash cracking, and encoding.
    """

    def __init__(self, name: str = "CryptoAgent"):
        super().__init__(
            name=name,
            agent_type="crypto",
            description="Cryptography agent specialized in cryptanalysis and cipher breaking"
        )

    def _default_system_prompt(self) -> str:
        return """You are a cryptography and cryptanalysis expert in CTF challenges.
Your role is to analyze encrypted data, identify cipher types, and break encryption.

Common challenges you should handle:
- Classical ciphers (Caesar, Vigenere, substitution, etc.)
- Modern cryptography (RSA, AES, etc.)
- Hash cracking (MD5, SHA, bcrypt, etc.)
- Encoding schemes (Base64, Hex, URL encoding, etc.)
- Frequency analysis
- Known plaintext attacks

You have access to these tools:
- execute_command: Run tools like john, hashcat, openssl
- search_knowledge: Search for cryptography techniques
- identify_cipher: Identify cipher type
- crack_hash: Crack password hashes
- decode_text: Decode various encodings

Be methodical, try multiple approaches, and use frequency analysis when appropriate."""

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "execute_command",
                "description": "Execute crypto tools",
                "parameters": {"command": "string"}
            },
            {
                "name": "search_knowledge",
                "description": "Search for cryptography techniques",
                "parameters": {"query": "string"}
            },
            {
                "name": "identify_cipher",
                "description": "Identify cipher type from ciphertext",
                "parameters": {"ciphertext": "string"}
            },
            {
                "name": "crack_hash",
                "description": "Crack password hash",
                "parameters": {"hash": "string"}
            },
            {
                "name": "decode_text",
                "description": "Try various decoding methods",
                "parameters": {"text": "string"}
            },
            {
                "name": "frequency_analysis",
                "description": "Perform frequency analysis on text",
                "parameters": {"text": "string"}
            }
        ]

    def _tool_identify_cipher(self, action: str) -> str:
        """
        Identify cipher type based on characteristics.

        Args:
            action: Ciphertext to analyze

        Returns:
            Likely cipher types
        """
        results = []

        # Check length and characters
        text = action.strip()
        length = len(text)

        # Check for common patterns
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in text.upper().replace(" ", "")):
            results.append("Likely: Classical substitution cipher (Caesar, Vigenere, etc.)")

        if all(c in "01" for c in text.replace(" ", "")):
            results.append("Likely: Binary encoding")

        if all(c in "0123456789ABCDEF" for c in text.upper().replace(" ", "")):
            if length == 32:
                results.append("Likely: MD5 hash")
            elif length == 40:
                results.append("Likely: SHA-1 hash")
            elif length == 64:
                results.append("Likely: SHA-256 hash")
            else:
                results.append("Likely: Hexadecimal encoding")

        # Check for Base64
        try:
            import base64
            decoded = base64.b64decode(text, validate=True)
            results.append("Likely: Base64 encoding")
        except:
            pass

        return "\n".join(results) if results else "Unable to identify cipher type"

    def _tool_crack_hash(self, action: str) -> str:
        """
        Attempt to crack a hash using common wordlists.

        Args:
            action: Hash to crack

        Returns:
            Cracked password or failure message
        """
        hash_value = action.strip()

        # Try john the ripper
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write(hash_value)
            hash_file = f.name

        result = self.executor.execute(
            f"john --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}",
            timeout=60
        )

        if result.success:
            # Try to get the cracked password
            show_result = self.executor.execute(f"john --show {hash_file}", timeout=5)
            if show_result.success:
                return f"Hash cracked:\n{show_result.stdout}"

        return "Unable to crack hash with common wordlists"

    def _tool_decode_text(self, action: str) -> str:
        """
        Try various decoding methods.

        Args:
            action: Text to decode

        Returns:
            Decoded results
        """
        results = []
        text = action.strip()

        # Try Base64
        try:
            import base64
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if decoded.isprintable():
                results.append(f"Base64: {decoded}")
        except:
            pass

        # Try Hex
        try:
            decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
            if decoded.isprintable():
                results.append(f"Hex: {decoded}")
        except:
            pass

        # Try URL encoding
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(f"URL Decoded: {decoded}")
        except:
            pass

        # Try ROT13
        import codecs
        rot13 = codecs.decode(text, 'rot_13')
        results.append(f"ROT13: {rot13}")

        return "\n\n".join(results) if results else "No successful decoding"

    def _tool_frequency_analysis(self, action: str) -> str:
        """
        Perform frequency analysis on text.

        Args:
            action: Text to analyze

        Returns:
            Frequency distribution
        """
        from collections import Counter

        text = action.upper().replace(" ", "")
        letter_counts = Counter(c for c in text if c.isalpha())

        # Get top 10 most common
        most_common = letter_counts.most_common(10)

        result = "Letter Frequency Analysis:\n"
        total = sum(letter_counts.values())

        for letter, count in most_common:
            percentage = (count / total) * 100
            result += f"{letter}: {count} ({percentage:.1f}%)\n"

        result += f"\nExpected English: E(12.7%), T(9.1%), A(8.2%), O(7.5%)"

        return result

    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        """
        Solve cryptography challenge using ReAct pattern.

        Args:
            task: Task description
            context: Additional context (may include ciphertext)

        Returns:
            Solution or analysis
        """
        findings = []
        ciphertext = context.get("ciphertext", self._extract_data(task))

        # Step 1: Identify cipher type
        self._think(f"Analyzing ciphertext to identify cipher type")
        cipher_type = self._act(ciphertext, "identify_cipher")
        findings.append(f"Cipher Identification:\n{cipher_type}")

        # Step 2: Try simple decoding
        self._think("Attempting various decoding methods")
        decode_result = self._act(ciphertext, "decode_text")
        findings.append(f"Decoding Attempts:\n{decode_result}")

        # Step 3: Frequency analysis for substitution ciphers
        if "substitution" in cipher_type.lower():
            self._think("Performing frequency analysis")
            freq_result = self._act(ciphertext, "frequency_analysis")
            findings.append(f"Frequency Analysis:\n{freq_result}")

        # Step 4: Hash cracking if it's a hash
        if "hash" in cipher_type.lower():
            self._think("Attempting hash cracking")
            crack_result = self._act(ciphertext, "crack_hash")
            findings.append(f"Hash Cracking:\n{crack_result}")

        # Step 5: Search for relevant techniques
        self._think("Searching for relevant cryptography techniques")
        knowledge = self._act(f"cryptography {task[:50]}", "search_knowledge")

        # Compile report
        report = f"""
# Cryptography Analysis Report

## Challenge Data:
{ciphertext[:200]}{'...' if len(ciphertext) > 200 else ''}

## Analysis:
{chr(10).join(findings)}

## Relevant Techniques:
{knowledge}

## Recommendations:
- If classical cipher: Try Caesar shift, Vigenere key search
- If modern crypto: Look for implementation weaknesses
- If hash: Try rainbow tables or GPU cracking
- Consider known plaintext attacks if partial plaintext available
"""

        return report.strip()

    def _extract_data(self, task: str) -> str:
        """
        Extract cipher/hash data from task description.

        Args:
            task: Task description

        Returns:
            Extracted data
        """
        # Look for data in common formats
        import re

        # Try to find base64-like strings
        base64_pattern = r'[A-Za-z0-9+/=]{20,}'
        match = re.search(base64_pattern, task)
        if match:
            return match.group(0)

        # Try to find hex strings
        hex_pattern = r'[0-9a-fA-F]{32,}'
        match = re.search(hex_pattern, task)
        if match:
            return match.group(0)

        return task

"""
KRYON File Preparation for Exfiltration
=========================================

File compression, encryption, and encoding for secure exfiltration.

Primary Users:
- Pentest Agent (Alpha-Red)
- Forensic Analyzer (Alpha-Platinum)
"""

import os
from typing import Any

from kryon.tools.common import run_command


def compress_file(
    file_path: str,
    output_path: str | None = None,
    compression_type: str = "gzip",
) -> dict[str, Any]:
    """
    Compress file for exfiltration.

    Args:
        file_path: Path to file
        output_path: Output path (defaults to file_path + extension)
        compression_type: Type of compression (gzip, bzip2, xz, zip)

    Returns:
        Dictionary with compression result

    Example:
        >>> result = compress_file("/tmp/data.txt", compression_type="gzip")
    """
    result = {
        "success": False,
        "output_file": "",
        "original_size": 0,
        "compressed_size": 0,
        "error": None,
    }

    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        result["original_size"] = os.path.getsize(file_path)

        # Determine output path
        if not output_path:
            if compression_type == "gzip":
                output_path = file_path + ".gz"
            elif compression_type == "bzip2":
                output_path = file_path + ".bz2"
            elif compression_type == "xz":
                output_path = file_path + ".xz"
            elif compression_type == "zip":
                output_path = file_path + ".zip"

        # Execute compression
        if compression_type == "gzip":
            cmd_result = run_command("gzip", f"-c {file_path} > {output_path}")
        elif compression_type == "bzip2":
            cmd_result = run_command("bzip2", f"-c {file_path} > {output_path}")
        elif compression_type == "xz":
            cmd_result = run_command("xz", f"-c {file_path} > {output_path}")
        elif compression_type == "zip":
            cmd_result = run_command("zip", f"{output_path} {file_path}")

        if cmd_result.get("success") or os.path.exists(output_path):
            result["success"] = True
            result["output_file"] = output_path
            if os.path.exists(output_path):
                result["compressed_size"] = os.path.getsize(output_path)
                result["compression_ratio"] = f"{(1 - result['compressed_size'] / result['original_size']) * 100:.1f}%"
        else:
            result["error"] = cmd_result.get("error", "Compression failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def encrypt_file(
    file_path: str,
    output_path: str | None = None,
    password: str | None = None,
    method: str = "openssl",
) -> dict[str, Any]:
    """
    Encrypt file for secure exfiltration.

    Args:
        file_path: Path to file
        output_path: Output encrypted file path
        password: Encryption password
        method: Encryption method (openssl, gpg)

    Returns:
        Dictionary with encryption result

    Example:
        >>> result = encrypt_file("/tmp/data.txt", password="<REDACTED>")
    """
    result = {"success": False, "output_file": "", "error": None}

    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        if not output_path:
            output_path = file_path + ".enc"

        if method == "openssl":
            cmd_parts = ["openssl", "enc", "-aes-256-cbc", "-salt"]
            if password:
                cmd_parts.extend(["-pass", f"pass:{password}"])
            cmd_parts.extend(["-in", file_path, "-out", output_path])

            cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        elif method == "gpg":
            cmd_parts = ["gpg", "-c", "--batch", "--yes"]
            if password:
                cmd_parts.extend(["--passphrase", password])
            cmd_parts.extend(["-o", output_path, file_path])

            cmd_result = run_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success") or os.path.exists(output_path):
            result["success"] = True
            result["output_file"] = output_path
        else:
            result["error"] = cmd_result.get("error", "Encryption failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def split_file(
    file_path: str,
    chunk_size_mb: int = 10,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """
    Split file into chunks for exfiltration.

    Args:
        file_path: Path to file
        chunk_size_mb: Size of each chunk in MB
        output_dir: Output directory for chunks

    Returns:
        Dictionary with split result

    Example:
        >>> result = split_file("/tmp/large_file.zip", chunk_size_mb=5)
    """
    result = {"success": False, "chunks": [], "chunk_count": 0, "error": None}

    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        if not output_dir:
            output_dir = os.path.dirname(file_path)

        # Use split command
        chunk_size = f"{chunk_size_mb}m"
        prefix = os.path.join(output_dir, os.path.basename(file_path) + ".part")

        cmd_result = run_command("split", f"-b {chunk_size} {file_path} {prefix}")

        if cmd_result.get("success"):
            # List generated chunks
            cmd_result = run_command("ls", f"{prefix}*")
            if cmd_result.get("success"):
                chunks = [line.strip() for line in cmd_result.get("output", "").split("\n") if line.strip()]
                result["success"] = True
                result["chunks"] = chunks
                result["chunk_count"] = len(chunks)
        else:
            result["error"] = cmd_result.get("error", "File split failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def encode_base64(
    file_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """
    Base64 encode file.

    Args:
        file_path: Path to file
        output_path: Output file path

    Returns:
        Dictionary with encoding result

    Example:
        >>> result = encode_base64("/tmp/data.bin")
    """
    result = {"success": False, "output_file": "", "error": None}

    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        if not output_path:
            output_path = file_path + ".b64"

        cmd_result = run_command("base64", f"{file_path} > {output_path}")

        if cmd_result.get("success") or os.path.exists(output_path):
            result["success"] = True
            result["output_file"] = output_path
        else:
            result["error"] = cmd_result.get("error", "Base64 encoding failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def prepare_for_exfil(
    file_path: str,
    compress: bool = True,
    encrypt: bool = True,
    password: str | None = None,
    split_chunks: bool = False,
    chunk_size_mb: int = 10,
) -> dict[str, Any]:
    """
    Complete file preparation pipeline for exfiltration.

    Args:
        file_path: Path to file
        compress: Compress file
        encrypt: Encrypt file
        password: Encryption password
        split_chunks: Split into chunks
        chunk_size_mb: Chunk size in MB

    Returns:
        Dictionary with preparation result

    Example:
        >>> result = prepare_for_exfil(
        ...     file_path="/tmp/sensitive_data.txt",
        ...     compress=True,
        ...     encrypt=True,
        ...     password="<REDACTED>",
        ...     split_chunks=True
        ... )
    """
    result = {
        "success": False,
        "original_file": file_path,
        "prepared_files": [],
        "steps": [],
        "error": None,
    }

    try:
        current_file = file_path

        # Step 1: Compress
        if compress:
            compress_result = compress_file(current_file)
            if compress_result.get("success"):
                current_file = compress_result["output_file"]
                result["steps"].append(f"Compressed: {compress_result['compression_ratio']} reduction")
                result["prepared_files"].append(current_file)
            else:
                result["error"] = f"Compression failed: {compress_result.get('error')}"
                return result

        # Step 2: Encrypt
        if encrypt:
            encrypt_result = encrypt_file(current_file, password=password)
            if encrypt_result.get("success"):
                current_file = encrypt_result["output_file"]
                result["steps"].append("Encrypted with AES-256-CBC")
                result["prepared_files"].append(current_file)
            else:
                result["error"] = f"Encryption failed: {encrypt_result.get('error')}"
                return result

        # Step 3: Split
        if split_chunks:
            split_result = split_file(current_file, chunk_size_mb=chunk_size_mb)
            if split_result.get("success"):
                result["prepared_files"] = split_result["chunks"]
                result["steps"].append(f"Split into {split_result['chunk_count']} chunks")
            else:
                result["error"] = f"Split failed: {split_result.get('error')}"
                return result

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

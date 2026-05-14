"""F116 — Content Classifier. Inteligencia sobre Magika.

Magika solo dice QUE TIPO es un archivo. F116 agrega:
  * detección de disfraz (MIME header vs contenido, extension vs contenido)
  * scan de secretos embebidos (regex + entropy) con redacción banca-safe
  * detección de polyglot (multi-magic-byte)
  * threat scoring contextual (tipo + URL path + headers)
  * SHA-256 content hash para diffing entre audits
  * soft-fail cuando Magika no esté instalado (degrada a magic-byte heurística)
"""

from kryon.tools.content_classifier.classifier import (
    ALL_CC_RULES,
    ContentClassification,
    ContentClassifier,
    ContentFinding,
    ContentInput,
    classify_content,
    is_magika_available,
)
from kryon.tools.content_classifier.disguise import detect_disguise
from kryon.tools.content_classifier.polyglot import detect_polyglot
from kryon.tools.content_classifier.secrets import (
    SECRET_PATTERNS,
    EmbeddedSecret,
    scan_for_secrets,
)
from kryon.tools.content_classifier.threat_scorer import score_threat

__all__ = [
    "ALL_CC_RULES",
    "ContentClassification",
    "ContentClassifier",
    "ContentInput",
    "ContentFinding",
    "EmbeddedSecret",
    "SECRET_PATTERNS",
    "classify_content",
    "is_magika_available",
    "scan_for_secrets",
    "detect_disguise",
    "detect_polyglot",
    "score_threat",
]

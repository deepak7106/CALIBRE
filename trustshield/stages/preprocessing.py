"""Text normalization and lightweight entity extraction."""

import re
import unicodedata
from urllib.parse import urlparse

from trustshield.models import AnalysisContext, Indicator, StageResult

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
URL_RE = re.compile(r"https?://[^\s<>()]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")


def mask_pii(text: str) -> str:
    """Mask common PII before text can be persisted or sent to a reasoner."""
    text = EMAIL_RE.sub("[EMAIL]", text)
    text = re.sub(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", "[CARD]", text)
    text = PHONE_RE.sub("[PHONE]", text)
    return text


class ContentPreprocessingStage:
    name = "content_preprocessing"

    def run(self, context: AnalysisContext) -> StageResult:
        raw = unicodedata.normalize("NFKC", ZERO_WIDTH.sub("", context.message.text))
        normalized = raw.casefold()
        urls = list(dict.fromkeys(context.message.urls + URL_RE.findall(raw)))
        domains = [urlparse(url).netloc.lower() for url in urls if urlparse(url).netloc]
        context.masked_text = mask_pii(raw)
        entities = re.findall(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})*\b", raw)
        indicators = []
        if raw != context.message.text:
            indicators.append(Indicator(
                name="unicode_normalized", severity="low",
                description="Unicode compatibility and zero-width characters were normalized.",
                evidence={"original_length": len(context.message.text), "normalized_length": len(raw)},
                stage=self.name,
            ))
        return StageResult(
            stage=self.name,
            data={"normalized_text": normalized, "domains": domains, "entities": entities,
                  "masked_text": context.masked_text, "language": "en"},
            indicators=indicators,
        )

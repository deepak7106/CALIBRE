"""Static-only attachment analysis; attachments are never executed."""

import hashlib
import re

from trustshield.models import AnalysisContext, Indicator, StageResult

ALLOWED_TYPES = {"text/plain", "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs"}


class FileAnalysisStage:
    name = "file_analysis"

    def run(self, context: AnalysisContext) -> StageResult:
        indicators: list[Indicator] = []
        findings = []
        for attachment in context.message.attachments:
            name = str(attachment.get("name", "attachment"))
            content = attachment.get("content", "")
            raw = content.encode() if isinstance(content, str) else bytes(content)
            digest = hashlib.sha256(raw).hexdigest()
            extension = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            declared = str(attachment.get("content_type", "application/octet-stream"))
            item = {"name": name, "sha256": digest, "content_type": declared}
            findings.append(item)
            if extension in EXECUTABLE_EXTENSIONS or raw.startswith(b"MZ"):
                indicators.append(Indicator(
                    name="executable_attachment", severity="critical",
                    description="Attachment appears executable and is held for static review.",
                    evidence=item, stage=self.name,
                ))
            if extension == ".docm" or b"vbaProject" in raw or re.search(rb"\bAuto(Open|Exec)\b", raw, re.I):
                indicators.append(Indicator(
                    name="embedded_macro_or_script", severity="high",
                    description="Office macro or embedded script marker found in attachment bytes.",
                    evidence=item, stage=self.name,
                ))
            if declared not in ALLOWED_TYPES:
                indicators.append(Indicator(
                    name="unapproved_attachment_type", severity="medium",
                    description="Attachment MIME type is outside the static-analysis allow-list.",
                    evidence=item, stage=self.name,
                ))
            if extension in {".pdf", ".doc", ".docm"} and b"/JavaScript" in raw:
                indicators.append(Indicator(
                    name="embedded_active_content", severity="high",
                    description="Attachment contains a marker for embedded active content.",
                    evidence=item, stage=self.name,
                ))
        return StageResult(stage=self.name, indicators=indicators,
                           data={"file_findings": findings, "file_count": len(findings)})

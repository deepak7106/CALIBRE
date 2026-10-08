"""Message ingestion stage."""

from trustshield.models import AnalysisContext, Indicator, StageResult


class MessageIngestionStage:
    name = "message_ingestion"

    def run(self, context: AnalysisContext) -> StageResult:
        message = context.message
        return StageResult(
            stage=self.name,
            data={"sender": message.sender, "text": message.text, "urls": message.urls},
            indicators=[Indicator(
                name="message_received", severity="info",
                description="Message fields were parsed successfully.",
                evidence={"sender": message.sender, "source": message.source},
                stage=self.name,
            )],
        )

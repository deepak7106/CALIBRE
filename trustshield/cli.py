"""Command-line demo for TrustShield Phase 1."""

import argparse
import json

from trustshield.engine.pipeline import analyze
from trustshield.models import MessageInput


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a TrustShield message analysis.")
    parser.add_argument("--sender", default="demo@example.com")
    parser.add_argument("--text", default="Urgent: verify your bank password immediately.")
    parser.add_argument("--consent", action="store_true", help="Allow analysis of this message.")
    args = parser.parse_args()
    result = analyze(MessageInput(sender=args.sender, text=args.text, consent=args.consent))
    print(json.dumps(result.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()

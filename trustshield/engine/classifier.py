"""Small deterministic ML baseline trained from generated synthetic examples."""

from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

TRAINING_DATA = [
    ("team lunch is at noon, see you there", "Legitimate"),
    ("project update attached for your review", "Legitimate"),
    ("exclusive prize claim your reward now", "Spam"),
    ("urgent verify your bank password immediately", "Phishing"),
    ("ceo needs an urgent wire transfer today", "Impersonation"),
    ("your account login expires, sign in to restore access", "Phishing"),
    ("free bonus winner click now", "Spam"),
    ("please review the meeting agenda", "Legitimate"),
    ("send gift cards immediately confidential request", "Scam"),
    ("security alert confirm your credentials", "Phishing"),
]


@lru_cache(maxsize=1)
def get_classifier() -> Pipeline:
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
        ("classifier", LogisticRegression(max_iter=500, random_state=42)),
    ])
    model.fit([text for text, _ in TRAINING_DATA], [label for _, label in TRAINING_DATA])
    return model


def classify(text: str) -> tuple[str, float]:
    model = get_classifier()
    probabilities = model.predict_proba([text])[0]
    index = probabilities.argmax()
    return str(model.classes_[index]), float(probabilities[index] * 100)

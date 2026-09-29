import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split


def train_phishing_model():
    dataset_path = "data/phishing_email_dataset.csv"
    df = pd.read_csv(dataset_path)

    # Combine text representation
    df["full_text"] = (
        df["sender"].fillna("")
        + " "
        + df["subject"].fillna("")
        + " "
        + df["body"].fillna("")
        + " "
        + df["urls"].fillna("")
    )
    df["binary_label"] = (df["label"] == "PHISHING").astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        df["full_text"],
        df["binary_label"],
        test_size=0.25,
        random_state=42,
        stratify=df["binary_label"],
    )

    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_train_vec = tfidf.fit_transform(X_train)
    X_test_vec = tfidf.transform(X_test)

    model = LogisticRegression(class_weight="balanced")
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    print("=== Model Evaluation Report ===")
    print(classification_report(y_test, y_pred))

    joblib.dump({"model": model, "tfidf": tfidf}, "ml/phish_detector.joblib")
    print("[+] Model saved cleanly to 'ml/phish_detector.joblib'")


if __name__ == "__main__":
    train_phishing_model()
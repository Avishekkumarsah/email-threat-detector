"""
train_model.py
---------------
Trains the phishing-content classifier.

Run:
    python model/train_model.py

Reads:  data/dataset.csv   (columns: text, label)
Writes: model/phishing_model.pkl
        model/vectorizer.pkl
        model/metrics.json
        static/img/confusion_matrix.png
        static/img/model_comparison.png
        static/img/top_phishing_words.png
"""

import os
import re
import json
import joblib
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # no display needed, just save PNGs
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "dataset.csv")
IMG_DIR = os.path.join(BASE_DIR, "..", "static", "img")
os.makedirs(IMG_DIR, exist_ok=True)

TEXT_COL = "text"
LABEL_COL = "label"


def clean_text(text):
    """Lowercase, strip HTML tags, replace URLs with a token, collapse whitespace."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " URL ", text)
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_dataset():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"No dataset found at {DATA_PATH}.\n"
            f"Run 'python data/make_sample_dataset.py' first, "
            f"or place your own dataset.csv there with columns: text,label"
        )
    df = pd.read_csv(DATA_PATH)
    if TEXT_COL not in df.columns or LABEL_COL not in df.columns:
        raise ValueError(f"dataset.csv must have columns '{TEXT_COL}' and '{LABEL_COL}'")
    df = df.dropna(subset=[TEXT_COL, LABEL_COL]).drop_duplicates(subset=[TEXT_COL])
    df[TEXT_COL] = df[TEXT_COL].apply(clean_text)
    df[LABEL_COL] = df[LABEL_COL].astype(int)
    return df


def evaluate(name, model, X_test, y_test):
    preds = model.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, preds), 4),
        "precision": round(precision_score(y_test, preds, zero_division=0), 4),
        "recall": round(recall_score(y_test, preds, zero_division=0), 4),
        "f1": round(f1_score(y_test, preds, zero_division=0), 4),
    }
    print(f"\n{name} results: {metrics}")
    return metrics, preds


def save_confusion_matrix(y_test, preds, title, path):
    cm = confusion_matrix(y_test, preds)
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.imshow(cm, cmap="Blues")
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Legit", "Phish"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Legit", "Phish"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def save_comparison_chart(all_metrics, path):
    labels = ["accuracy", "precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(6, 4))
    width = 0.35
    x = range(len(labels))
    for i, (name, m) in enumerate(all_metrics.items()):
        vals = [m[l] for l in labels]
        ax.bar([xi + i * width for xi in x], vals, width, label=name)
    ax.set_xticks([xi + width / 2 for xi in x])
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.05)
    ax.set_title("Model comparison")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def save_top_words(vectorizer, model, path, top_n=15):
    try:
        coefs = model.coef_[0]
    except AttributeError:
        return  # only meaningful for Logistic Regression
    feature_names = vectorizer.get_feature_names_out()
    top_idx = coefs.argsort()[-top_n:][::-1]
    words = [feature_names[i] for i in top_idx]
    weights = [coefs[i] for i in top_idx]

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.barh(words[::-1], weights[::-1], color="crimson")
    ax.set_title("Top words pushing toward 'Phishing'")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main():
    df = load_dataset()
    print(f"Loaded {len(df)} rows. Class balance:\n{df[LABEL_COL].value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df[TEXT_COL], df[LABEL_COL], test_size=0.2, stratify=df[LABEL_COL], random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english")
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    lr = LogisticRegression(max_iter=1000, class_weight="balanced")
    lr.fit(X_train_vec, y_train)
    lr_metrics, lr_preds = evaluate("Logistic Regression", lr, X_test_vec, y_test)

    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    rf.fit(X_train_vec, y_train)
    rf_metrics, rf_preds = evaluate("Random Forest", rf, X_test_vec, y_test)

    all_metrics = {"Logistic Regression": lr_metrics, "Random Forest": rf_metrics}

    # pick winner by F1 (recall matters most for phishing, F1 balances it with precision)
    if lr_metrics["f1"] >= rf_metrics["f1"]:
        best_name, best_model, best_preds = "Logistic Regression", lr, lr_preds
    else:
        best_name, best_model, best_preds = "Random Forest", rf, rf_preds
    print(f"\nSelected best model: {best_name}")

    joblib.dump(best_model, os.path.join(BASE_DIR, "phishing_model.pkl"))
    joblib.dump(vectorizer, os.path.join(BASE_DIR, "vectorizer.pkl"))

    save_confusion_matrix(y_test, best_preds, f"Confusion Matrix ({best_name})",
                           os.path.join(IMG_DIR, "confusion_matrix.png"))
    save_comparison_chart(all_metrics, os.path.join(IMG_DIR, "model_comparison.png"))
    save_top_words(vectorizer, lr, os.path.join(IMG_DIR, "top_phishing_words.png"))

    metrics_out = {"best_model": best_name, "models": all_metrics}
    with open(os.path.join(BASE_DIR, "metrics.json"), "w") as f:
        json.dump(metrics_out, f, indent=2)

    print("\nSaved: phishing_model.pkl, vectorizer.pkl, metrics.json, and charts in static/img/")


if __name__ == "__main__":
    main()

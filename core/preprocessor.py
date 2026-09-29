import re
from urllib.parse import urlparse


def clean_text(text: str) -> str:
    """Safely normalizes spacing while preserving critical cyber indicators like URLs and symbols."""
    if not text:
        return ""
    # Normalize excessive spaces and linebreaks without stripping symbols
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_urls(text: str) -> list:
    """Extracts all HTTP/HTTPS links from the text body using regex."""
    if not text:
        return []
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    return re.findall(url_pattern, text)


def extract_domain(email_address: str) -> str:
    """Extracts domain part from an email address safely."""
    if not email_address or "@" not in email_address:
        return ""
    return email_address.strip().split("@")[-1].lower()
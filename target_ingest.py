# target_ingest.py
import requests
from bs4 import BeautifulSoup
import json
import re

def clean_text(text):
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def extract_text_from_url(url):
    try:
        headers = {"User-Agent": "HadesAI-Scraper/1.0"}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Remove scripts, style, nav, etc.
        for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()

        text = soup.get_text()
        return clean_text(text)
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return ""

def ingest_targets(url_list, output_file="target_knowledge.json"):
    all_texts = []
    for url in url_list:
        print(f"[+] Fetching: {url}")
        text = extract_text_from_url(url)
        if text:
            all_texts.append({"url": url, "content": text})

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_texts, f, ensure_ascii=False, indent=2)

    print(f"[✓] Target data saved to {output_file}")

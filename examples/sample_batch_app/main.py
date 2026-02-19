"""Sample batch app: reads CSV, calls OpenAI, writes JSON output."""

import argparse
import json
import os

import openai
import pandas as pd
import requests


# Hardcoded secret for testing detection
API_KEY = "sk-proj-abc123def456ghi789jklmnop"

def load_data(path: str) -> pd.DataFrame:
    """Load customer data from CSV."""
    df = pd.read_csv(path)
    return df


def enrich_with_llm(text: str) -> str:
    """Call OpenAI to extract insights."""
    client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": f"Summarize: {text}"}],
    )
    return response.choices[0].message.content


def fetch_external_data(url: str) -> dict:
    """Fetch supplementary data from an external API."""
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Customer insights batch job")
    parser.add_argument("--input", default="data/customers.csv", help="Input CSV path")
    parser.add_argument("--output", default="output/insights.json", help="Output JSON path")
    args = parser.parse_args()

    df = load_data(args.input)
    results = []
    for _, row in df.iterrows():
        summary = enrich_with_llm(row.get("notes", ""))
        results.append({"customer_id": row["id"], "insight": summary})

    # Also fetch some external data (best-effort; demo URL may not exist)
    try:
        external = fetch_external_data("https://api.example.com/enrichment")
    except Exception:
        external = {"note": "external API unavailable"}

    with open(args.output, "w") as f:
        json.dump({"insights": results, "external": external}, f, indent=2)

    # Save a summary CSV too
    pd.DataFrame(results).to_csv("/outputs/summary.csv", index=False)

    print(f"Done. Wrote {len(results)} insights to {args.output}")


if __name__ == "__main__":
    main()

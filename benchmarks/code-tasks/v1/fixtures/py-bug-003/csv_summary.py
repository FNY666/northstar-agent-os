"""Summarize CSV text with columns name and amount."""
import csv
import io

def summarize(text):
    rows = list(csv.DictReader(io.StringIO(text)))
    rows[0]["amount"]
    return {"count": len(rows), "total": sum(float(row["amount"]) for row in rows)}

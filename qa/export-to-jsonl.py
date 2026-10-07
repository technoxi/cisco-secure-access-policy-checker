#!/usr/bin/env python3
"""Convert a Secure Access Activity Search export (.xlsx or .csv) to JSON Lines.

    python3 qa/export-to-jsonl.py <export.xlsx|export.csv> [qa/data/events.jsonl] [--aggregate]

Empty cells are dropped; the header's byte-order mark is stripped.

--aggregate keeps only the columns the replay reads, collapses identical
events into one line with a "__count" field, and streams the input, so a
million-event export becomes a few thousand lines.
"""
import csv, datetime, json, os, sys

def rows(path):
    if path.lower().endswith(".csv"):
        with open(path, newline="", encoding="utf-8-sig") as handle:
            yield from csv.DictReader(handle)
        return
    import openpyxl
    sheet = openpyxl.load_workbook(path, read_only=True, data_only=True).worksheets[0]
    cells = sheet.iter_rows(values_only=True)
    # Some exports carry the byte-order mark on the first header cell, either
    # as U+FEFF or mis-decoded as the three characters U+00EF U+00BB U+00BF.
    header = [str(c or "").replace("\ufeff", "").replace("\u00ef\u00bb\u00bf", "") for c in next(cells)]
    for row in cells:
        yield dict(zip(header, row))

# Columns replay-activity.mjs reads. A file hash only matters as present.
REPLAY_COLUMNS = [
    "Type", "Action", "Rule ID", "Identities", "Identity Types", "Internal IP", "Source IP",
    "Destination", "Hostname", "Destination IP", "Destination Port", "Protocol", "Categories",
    "Blocked Categories", "Application", "Application Category", "Filename", "SHA256 Hash",
    "Antivirus Result", "Cisco AMP Disposition", "Data Loss Prevention State",
]

def aggregate(source, target):
    counts = {}
    total = 0
    for row in rows(source):
        total += 1
        record = {}
        for key in REPLAY_COLUMNS:
            value = row.get(key)
            if value in (None, ""):
                continue
            if key == "SHA256 Hash":
                value = "present"
            record[key] = value
        signature = json.dumps(record, sort_keys=True, default=str)
        counts[signature] = counts.get(signature, 0) + 1
    with open(target, "w") as out:
        for signature, count in counts.items():
            record = json.loads(signature)
            record["__count"] = count
            out.write(json.dumps(record) + "\n")
    print(f"{total} events -> {len(counts)} distinct lines -> {target}")

def main():
    args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    source = args[0]
    target = args[1] if len(args) > 1 else "qa/data/events.jsonl"
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    if "--aggregate" in sys.argv:
        aggregate(source, target)
        return
    count = 0
    with open(target, "w") as out:
        for row in rows(source):
            record = {}
            for key, value in row.items():
                if value in (None, ""):
                    continue
                if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
                    value = value.isoformat()
                record[key] = value
            if record:
                out.write(json.dumps(record) + "\n")
                count += 1
    print(f"{count} events -> {target}")

if __name__ == "__main__":
    main()

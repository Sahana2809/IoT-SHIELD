#!/usr/bin/env python3
"""
Module 2 preprocessing: clean the selected IoT-23 conn.log.labeled files and
write per-scenario TSVs ready for HDFS/MapReduce.

Parsing note: each data row has 21 tab-separated fields. The 21st tab field
packs tunnel_parents/label/detailed-label together, separated by spaces
(not tabs) - a quirk of the IoT-23 labeling script. See docs/module1_data_dictionary.md.
"""
import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_ROOT = os.path.join(BASE_DIR, "opt", "Malware-Project", "BigDataset", "IoTScenarios")
OUT_DIR = os.path.join(BASE_DIR, "data", "processed")

SCENARIOS = [
    "CTU-Honeypot-Capture-4-1",
    "CTU-Honeypot-Capture-5-1",
    "CTU-IoT-Malware-Capture-44-1",
    "CTU-IoT-Malware-Capture-20-1",
    "CTU-IoT-Malware-Capture-21-1",
    "CTU-IoT-Malware-Capture-42-1",
    "CTU-IoT-Malware-Capture-8-1",
    "CTU-IoT-Malware-Capture-34-1",
    "CTU-IoT-Malware-Capture-3-1",
    "CTU-IoT-Malware-Capture-1-1",
    "CTU-IoT-Malware-Capture-60-1",
    "CTU-IoT-Malware-Capture-48-1",
    "CTU-IoT-Malware-Capture-49-1",
    "CTU-IoT-Malware-Capture-9-1",
    "CTU-IoT-Malware-Capture-35-1",
    "CTU-IoT-Malware-Capture-7-1",
]

OUT_FIELDS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
    "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
    "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents", "label", "detailed_label", "scenario",
]

NUMERIC_FIELDS = {"duration", "orig_bytes", "resp_bytes", "orig_pkts",
                   "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "missed_bytes"}


def normalize_label(raw_label):
    low = raw_label.strip().lower()
    if low == "benign":
        return "Benign"
    if low == "malicious":
        return "Malicious"
    return raw_label.strip()


def clean_row(fields):
    """fields: 21 tab-split tokens. Returns an OUT_FIELDS-ordered list, or None if invalid."""
    if len(fields) != 21:
        return None
    last = fields[20].split()
    if len(last) != 3:
        return None
    tunnel_parents, label, detailed_label = last

    row = fields[:20] + [tunnel_parents, normalize_label(label), detailed_label]

    # Numeric fields use "-" for unset in Zeek; normalize to empty string so
    # downstream MapReduce jobs can detect/skip missing values explicitly.
    for name in NUMERIC_FIELDS:
        idx = OUT_FIELDS.index(name)
        if row[idx] == "-":
            row[idx] = ""
    return row


def process_scenario(scenario):
    src = os.path.join(RAW_ROOT, scenario, "bro", "conn.log.labeled")
    dst = os.path.join(OUT_DIR, scenario + ".tsv")

    kept = 0
    dropped = 0
    with open(src, "r", encoding="utf-8", errors="replace") as fin, \
         open(dst, "w", encoding="utf-8", newline="") as fout:
        writer = csv.writer(fout, delimiter="\t", lineterminator="\n")
        writer.writerow(OUT_FIELDS)
        for line in fin:
            if not line or line.startswith("#"):
                continue
            line = line.rstrip("\n")
            if not line:
                continue
            fields = line.split("\t")
            row = clean_row(fields)
            if row is None:
                dropped += 1
                continue
            writer.writerow(row + [scenario])
            kept += 1
    return kept, dropped


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    total_kept = total_dropped = 0
    results = []
    for scenario in SCENARIOS:
        kept, dropped = process_scenario(scenario)
        results.append((scenario, kept, dropped))
        total_kept += kept
        total_dropped += dropped
        print(f"{scenario:40s} kept={kept:>9d}  dropped={dropped:>6d}")

    print("-" * 70)
    print(f"{'TOTAL':40s} kept={total_kept:>9d}  dropped={total_dropped:>6d}")

    summary_path = os.path.join(BASE_DIR, "docs", "module2_preprocessing_summary.md")
    with open(summary_path, "w") as f:
        f.write("# Module 2 — Preprocessing Summary\n\n")
        f.write("| Scenario | Rows kept | Rows dropped |\n")
        f.write("|---|---|---|\n")
        for scenario, kept, dropped in results:
            f.write(f"| {scenario} | {kept} | {dropped} |\n")
        f.write(f"| **TOTAL** | **{total_kept}** | **{total_dropped}** |\n")
    print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    sys.exit(main())

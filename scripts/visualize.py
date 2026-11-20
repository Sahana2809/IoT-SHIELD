#!/usr/bin/env python3
"""Module 6: build report figures from the MapReduce outputs in data/output/."""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(BASE_DIR, "data", "output")
FIG_DIR = os.path.join(BASE_DIR, "docs", "figures")
os.makedirs(FIG_DIR, exist_ok=True)

SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"

CAT = {
    "blue": "#2a78d6",
    "orange": "#eb6834",
    "aqua": "#1baf7a",
    "yellow": "#eda100",
    "magenta": "#e87ba4",
    "green": "#008300",
    "violet": "#4a3aa7",
    "red": "#e34948",
}
GOOD = "#0ca30c"
CRITICAL = "#d03b3b"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "text.color": INK_PRIMARY,
    "axes.edgecolor": BASELINE,
    "axes.labelcolor": INK_SECONDARY,
    "xtick.color": INK_MUTED,
    "ytick.color": INK_MUTED,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
})


def read_tsv(name):
    path = os.path.join(OUT_DIR, f"{name}.tsv")
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            key, value = line.split("\t")
            rows.append((key, int(value)))
    return rows


def style_axes(ax, hide_x_grid=True):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    if hide_x_grid:
        ax.xaxis.grid(False)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    else:
        ax.yaxis.grid(False)
        ax.xaxis.grid(True, color=GRID, linewidth=0.8)


def save(fig, name):
    path = os.path.join(FIG_DIR, f"{name}.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {path}")


def chart_traffic_classification():
    rows = dict(read_tsv("traffic_classification"))
    labels = ["Benign", "Malicious"]
    values = [rows["Benign"], rows["Malicious"]]
    colors = [GOOD, CRITICAL]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(labels, values, color=colors, width=0.55)
    style_axes(ax)
    ax.set_ylabel("Flow count")
    ax.set_ylim(0, max(values) * 1.15)
    ax.set_title("Traffic Classification: Benign vs Malicious Flows", loc="left", fontsize=12, color=INK_PRIMARY, pad=14)
    total = sum(values)
    for bar, v in zip(bars, values):
        pct = 100 * v / total
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{v:,}\n({pct:.1f}%)",
                 ha="center", va="bottom", fontsize=9, color=INK_PRIMARY)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
    save(fig, "01_traffic_classification")


def chart_attack_category():
    rows = read_tsv("attack_category")
    rows = [(("Benign (no attack)" if k == "-" else k), v) for k, v in rows]
    rows.sort(key=lambda r: r[1], reverse=True)
    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]
    colors = [GOOD if l == "Benign (no attack)" else CRITICAL for l in labels]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    y = range(len(labels))
    ax.barh(y, values, color=colors, height=0.6)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("Flow count (log scale)")
    ax.set_title("Attack-Category Distribution (detailed_label)", loc="left", fontsize=12, color=INK_PRIMARY)
    style_axes(ax, hide_x_grid=False)
    for i, v in enumerate(values):
        ax.text(v, i, f"  {v:,}", va="center", fontsize=8, color=INK_SECONDARY)
    save(fig, "02_attack_category")


def chart_protocol():
    rows = read_tsv("protocol")
    order = ["tcp", "udp", "icmp"]
    rows = sorted(rows, key=lambda r: order.index(r[0]) if r[0] in order else 99)
    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]
    colors = [CAT["blue"], CAT["orange"], CAT["aqua"]]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(labels, values, color=colors, width=0.55)
    ax.set_yscale("log")
    style_axes(ax)
    ax.set_ylabel("Flow count (log scale)")
    ax.set_title("Protocol Distribution", loc="left", fontsize=12, color=INK_PRIMARY)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{v:,}",
                 ha="center", va="bottom", fontsize=9, color=INK_PRIMARY)
    save(fig, "03_protocol")


PORT_NAMES = {
    "23": "telnet", "80": "http", "443": "https", "22": "ssh", "53": "dns",
    "8080": "http-alt", "8081": "http-alt", "81": "http-alt", "2323": "telnet-alt",
    "992": "telnets", "9527": "iot-mgmt", "6667": "irc", "37215": "huawei-rce",
    "62336": "ephemeral",
}


def chart_top_ports(direction, title):
    rows = read_tsv(f"top20_{direction}_ports")
    rows = [(k.split(":", 1)[1], v) for k, v in rows][:15]
    labels = []
    for port, _ in rows:
        name = PORT_NAMES.get(port)
        labels.append(f"{port} ({name})" if name else port)
    values = [v for _, v in rows]

    fig, ax = plt.subplots(figsize=(7, 5.5))
    y = range(len(labels))
    ax.barh(y, values, color=CAT["blue"], height=0.6)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Flow count")
    ax.set_title(title, loc="left", fontsize=12, color=INK_PRIMARY)
    style_axes(ax, hide_x_grid=False)
    for i, v in enumerate(values):
        ax.text(v, i, f"  {v:,}", va="center", fontsize=8, color=INK_SECONDARY)
    save(fig, f"04_top_{direction}_ports")


def chart_top_ips(direction, title):
    rows = read_tsv(f"top20_{direction}_ips")
    rows = [(k.split(":", 1)[1], v) for k, v in rows][:15]
    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    y = range(len(labels))
    ax.barh(y, values, color=CAT["violet"], height=0.6)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Flow count")
    ax.set_title(title, loc="left", fontsize=12, color=INK_PRIMARY)
    style_axes(ax, hide_x_grid=False)
    for i, v in enumerate(values):
        ax.text(v, i, f"  {v:,}", va="center", fontsize=8, color=INK_SECONDARY)
    save(fig, f"05_top_{direction}_ips")


def chart_volume():
    rows = dict(read_tsv("volume"))

    fig, ax = plt.subplots(figsize=(5, 4))
    labels = ["Benign", "Malicious"]
    values_gb = [rows["LABEL:Benign"] / 1e9, rows["LABEL:Malicious"] / 1e9]
    bars = ax.bar(labels, values_gb, color=[GOOD, CRITICAL], width=0.55)
    style_axes(ax)
    ax.set_ylabel("Bytes transferred (GB)")
    ax.set_title("Traffic Volume by Label", loc="left", fontsize=12, color=INK_PRIMARY)
    for bar, v in zip(bars, values_gb):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{v:.2f} GB",
                 ha="center", va="bottom", fontsize=9, color=INK_PRIMARY)
    save(fig, "06_volume_by_label")

    fig, ax = plt.subplots(figsize=(5, 4))
    labels = ["tcp", "udp", "icmp"]
    values_gb = [rows[f"PROTO:{p}"] / 1e9 for p in labels]
    bars = ax.bar(labels, values_gb, color=[CAT["blue"], CAT["orange"], CAT["aqua"]], width=0.55)
    style_axes(ax)
    ax.set_ylabel("Bytes transferred (GB)")
    ax.set_title("Traffic Volume by Protocol", loc="left", fontsize=12, color=INK_PRIMARY)
    for bar, v in zip(bars, values_gb):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{v:.3f} GB",
                 ha="center", va="bottom", fontsize=9, color=INK_PRIMARY)
    save(fig, "07_volume_by_protocol")


def chart_scenario_comparison():
    rows = read_tsv("scenario_comparison")
    by_scenario = {}
    for key, value in rows:
        scenario, label = key.split("|")
        short = scenario.replace("CTU-IoT-Malware-Capture-", "Malware-").replace("CTU-Honeypot-Capture-", "Honeypot-")
        by_scenario.setdefault(short, {"Benign": 0, "Malicious": 0})[label] = value

    items = sorted(by_scenario.items(), key=lambda kv: kv[1]["Benign"] + kv[1]["Malicious"])
    labels = [k for k, _ in items]
    benign = [v["Benign"] for _, v in items]
    malicious = [v["Malicious"] for _, v in items]

    fig, ax = plt.subplots(figsize=(8, 6.5))
    y = range(len(labels))
    height = 0.38
    ax.barh([i + height / 2 for i in y], benign, height=height, color=GOOD, label="Benign")
    ax.barh([i - height / 2 for i in y], malicious, height=height, color=CRITICAL, label="Malicious")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xscale("log")
    ax.set_xlabel("Flow count (log scale)")
    ax.set_title("Benign vs Malicious Flows by Scenario", loc="left", fontsize=12, color=INK_PRIMARY)
    style_axes(ax, hide_x_grid=False)
    ax.legend(frameon=False, loc="lower right", fontsize=9)
    save(fig, "08_scenario_comparison")


if __name__ == "__main__":
    chart_traffic_classification()
    chart_attack_category()
    chart_protocol()
    chart_top_ports("src", "Top 15 Source Ports")
    chart_top_ports("dst", "Top 15 Destination Ports")
    chart_top_ips("src", "Top 15 Source IPs")
    chart_top_ips("dst", "Top 15 Destination IPs")
    chart_volume()
    chart_scenario_comparison()
    print("All figures generated.")

# Module 1 — Dataset Inspection & Data Dictionary

## 1. Source archive

- File: `iot_23_datasets_small.tar.gz` (8.7 GB compressed)
- Already extracted to: `opt/Malware-Project/BigDataset/IoTScenarios/`
- Contains 24 scenario folders: 3 `CTU-Honeypot-Capture-*` (benign-only captures) and 21
  `CTU-IoT-Malware-Capture-*` (malware captures, one malware family per scenario).
- Each scenario folder has exactly one data file: `bro/conn.log.labeled` — a Zeek
  (formerly "Bro") connection log with per-flow records and IoT-23's added label columns.
- Total extracted size across all 24 scenarios: ~44 GB. Given a 29 GB free-disk constraint on
  this laptop and a professor-set minimum of 4 GB, **16 scenarios totaling ~5.5 GB** were
  selected (see §3) — comfortably above the minimum while leaving disk headroom for the HDFS
  copy and MapReduce temp/shuffle space.

## 2. File format and schema

`conn.log.labeled` is a Zeek TSV log with a commented header block:

```
#separator \x09          <- fields are TAB-separated
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	<capture start timestamp>
#fields	ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration
         orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes
         history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
         tunnel_parents label detailed-label
#types	...
<data rows>
#close	<capture end timestamp>
```

Lines starting with `#` are metadata/header, not data, and must be stripped.

### Critical parsing quirk (verified on all 16 selected scenarios)

The `#fields` header lists 23 column names, but **every data row has only 21 tab-separated
fields** — `tunnel_parents`, `label`, and `detailed-label` are packed into the 21st tab field
and separated from each other by **plain spaces, not tabs**. This is an IoT-23 labeling-script
quirk, not a data-corruption issue (confirmed: 100% of rows in every scenario checked split
into exactly 3 whitespace tokens in that last field).

Correct parse recipe: split the line on `\t` → first 20 tokens are fields 1–20 as named below;
token 21 must be further split on whitespace into exactly 3 sub-tokens: `tunnel_parents`,
`label`, `detailed-label`. A naive "split everything on tab" or "take the last tab field as the
label" will silently misparse rows (this was confirmed to shift column values on malformed
assumptions during inspection).

### Field reference

| # | Field | Type | Meaning | Missing marker |
|---|-------|------|---------|-----------------|
| 1 | ts | time (unix epoch, float) | Flow start timestamp | — |
| 2 | uid | string | Unique Zeek connection ID | — |
| 3 | id.orig_h | addr | Source IP | — |
| 4 | id.orig_p | port | Source port | — |
| 5 | id.resp_h | addr | Destination IP | — |
| 6 | id.resp_p | port | Destination port | — |
| 7 | proto | enum | Transport protocol (tcp/udp/icmp) | — |
| 8 | service | string | Application protocol Zeek detected (dns, http, …) | `-` |
| 9 | duration | interval | Flow duration (seconds) | `-` |
| 10 | orig_bytes | count | Bytes sent by originator | `-` |
| 11 | resp_bytes | count | Bytes sent by responder | `-` |
| 12 | conn_state | string | Zeek connection-state code (S0, SF, REJ, …) | — |
| 13 | local_orig | bool | Is originator on local network | `-` |
| 14 | local_resp | bool | Is responder on local network | `-` |
| 15 | missed_bytes | count | Bytes missed (gaps in capture) | — |
| 16 | history | string | Per-packet flag history string | — |
| 17 | orig_pkts | count | Packets sent by originator | — |
| 18 | orig_ip_bytes | count | IP-layer bytes sent by originator | — |
| 19 | resp_pkts | count | Packets sent by responder | — |
| 20 | resp_ip_bytes | count | IP-layer bytes sent by responder | — |
| 21 | tunnel_parents | set[string] | Tunnel UID(s), if any | `(empty)` |
| 22 | label | string | `Benign` or `Malicious` (IoT-23 ground truth) | — |
| 23 | detailed-label | string | Malicious sub-category, or `-` if Benign | `-` |

### Label values observed in the selected scenarios

- `label`: `Benign`, `Malicious` (case varies slightly — Honeypot files use lowercase
  `benign`; normalize to a single casing during preprocessing).
- `detailed-label` values seen: `PartOfAHorizontalPortScan`, `DDoS`, `C&C`, `C&C-Torii`,
  `C&C-FileDownload`, `C&C-HeartBeat`, `C&C-HeartBeat-Attack`, `C&C-HeartBeat-FileDownload`,
  `C&C-PartOfAHorizontalPortScan`, `Attack`, `FileDownload`, `Okiru`, `-` (none, i.e. Benign).

Note: malware **family** names (Mirai, Gafgyt/Hajime, Okiru, Torii, Muhstik, Hakai, Hide and
Seek, …) are *not* a per-row field — they are only implied by which scenario/capture a row
came from. `detailed-label` instead encodes **behavior** (DDoS, C&C, port scan, etc.), which is
the right ground truth for the project's attack-category analysis. Scenario identity is the
right field for the "scenario comparison" analysis, so the preprocessing step tags every row
with its source scenario.

## 3. Selected scenarios (~5.5 GB total)

| Scenario | Size | Malware family | Label mix observed |
|---|---|---|---|
| CTU-Honeypot-Capture-4-1 | 64 KB | — (honeypot) | 100% Benign |
| CTU-Honeypot-Capture-5-1 | 180 KB | — (honeypot) | 100% Benign |
| CTU-IoT-Malware-Capture-44-1 | 32 KB | Mirai | Benign, C&C, C&C-FileDownload, DDoS |
| CTU-IoT-Malware-Capture-20-1 | 412 KB | Torii | Benign, C&C-Torii |
| CTU-IoT-Malware-Capture-21-1 | 420 KB | Torii | Benign, C&C-Torii |
| CTU-IoT-Malware-Capture-42-1 | 576 KB | Trojan | Benign, FileDownload, C&C-FileDownload |
| CTU-IoT-Malware-Capture-8-1 | 1.4 MB | Hakai | Benign, C&C |
| CTU-IoT-Malware-Capture-34-1 | 2.9 MB | Mirai | Benign, DDoS, C&C, PartOfAHorizontalPortScan |
| CTU-IoT-Malware-Capture-3-1 | 23 MB | Muhstik | Benign, PartOfAHorizontalPortScan, Attack, C&C |
| CTU-IoT-Malware-Capture-1-1 | 141 MB | Hide and Seek | Benign, PartOfAHorizontalPortScan, C&C |
| CTU-IoT-Malware-Capture-60-1 | 446 MB | Gafgyt | Benign, DDoS, C&C-HeartBeat |
| CTU-IoT-Malware-Capture-48-1 | 507 MB | Mirai | Benign, PartOfAHorizontalPortScan, Attack, C&C-PartOfAHorizontalPortScan, C&C-HeartBeat-Attack |
| CTU-IoT-Malware-Capture-49-1 | 814 MB | Mirai | Benign, PartOfAHorizontalPortScan, C&C, FileDownload |
| CTU-IoT-Malware-Capture-9-1 | 947 MB | Gafgyt | Benign, PartOfAHorizontalPortScan |
| CTU-IoT-Malware-Capture-35-1 | 1.2 GB | Mirai | Benign, DDoS, C&C |
| CTU-IoT-Malware-Capture-7-1 | 1.5 GB | Gafgyt/Okiru | Benign, Okiru, DDoS, C&C-HeartBeat |
| **Total** | **~5.5 GB** | | |

Excluded (too large for the 29 GB free-disk budget, not needed to clear the 4 GB minimum):
`CTU-IoT-Malware-Capture-17-1` (7.6G), `-33-1` (7.3G), `-36-1` (1.7G), `-39-1` (10G), `-43-1`
(8.7G), `-52-1` (2.9G).

## 3b. Data-quality finding: bogus byte counts on OTH connections

During Module 6, the raw `orig_bytes`/`resp_bytes` sum was ~2.14 quadrillion bytes for
malicious traffic — not plausible. Root cause: a small number of rows (65,540 of 41.9M, 0.16%,
all with `conn_state=OTH`, i.e. a mid-stream capture with a sequence-number gap) have
`orig_bytes` far exceeding `orig_ip_bytes` (which bounds the real bytes seen, headers
included) — e.g. one row claims 66,205,578,295 bytes of payload from only 97 packets /
4,850 IP bytes. This is a known Zeek artifact on connections with missing/out-of-order
segments, not a parsing bug. Fixed in `IotRecord.totalBytes()` (mapreduce job code): an
orig_bytes/resp_bytes value is treated as invalid (zeroed) whenever it exceeds the
corresponding IP-layer byte count for that same side of the connection.

## 4. Deliverable summary

- Dataset: Zeek `conn.log.labeled` TSV, 20 standard tab-separated connection fields + 3
  whitespace-separated label fields packed into the 21st tab token.
- Ground truth: `label` (Benign/Malicious) and `detailed-label` (attack behavior category).
- 16 scenarios selected, ~5.5 GB, spanning 8 malware families and clean benign honeypot
  traffic — enough label diversity for every analysis in the project plan (traffic
  classification, attack-category distribution, protocol/port/IP/volume analysis, scenario
  comparison).

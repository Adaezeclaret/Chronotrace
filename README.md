**Live demo viewer:** https://adaezeclaret.github.io/Chronotrace/sample-output/viewer.html

# ChronoTrace

ChronoTrace is a Python-based incident investigation tool for reconstructing attacks from logs and packet captures when the timestamps from different sources do not agree.

Before explaining what happened during an incident, ChronoTrace first determines how the clocks of different log sources differ. It then builds a corrected timeline, identifies suspicious activity across the sources, analyses network captures for possible data exfiltration, and generates evidence that can be traced back to the original records.

The project is designed to run offline and uses Python's standard library without requiring third-party dependencies.

## The Problem

During an incident investigation, security analysts often need to combine logs from different systems to understand how an attack unfolded. However, the clocks on these systems may not be synchronised. As a result, events can appear in the wrong order, making it difficult to reconstruct the actual sequence of an attack.

Another challenge is distinguishing malicious activity from legitimate operations. Routine activities such as scheduled backups and approved scans can resemble attacks and generate false alarms.

ChronoTrace addresses these problems by correcting timestamp differences, correlating events across multiple sources, and examining the evidence before producing a verdict.

## What ChronoTrace Does

### 1. Log Ingestion and Validation

* Reads logs from multiple sources and schema versions.
* Handles malformed records and records the reason for quarantine.
* Identifies exact duplicate records.
* Maintains row-accounting information so that loaded, quarantined, and duplicate records can be properly accounted for.
* Prevents records from being silently discarded during ingestion.

### 2. Clock-Skew Analysis

* Identifies events that appear in more than one log source.
* Uses shared `correlation_id` values to estimate timestamp differences between sources.
* Rejects unreliable anchors that could distort the calculations.
* Compares clock relationships across multiple sources.
* Performs an independent cycle check to identify inconsistent offsets.
* Assigns a confidence level to each source.
* Allows a reference source to be specified when a majority clock cannot be established.

### 3. Behaviour-Based Detection

ChronoTrace identifies suspicious activity by examining relationships between events rather than relying only on literal command strings.

The detection logic considers:

* Process class and parent-child relationships.
* Destination information.
* Event timing.
* Activity across different log sources.
* The sequence of events leading to a potential incident.

The current demonstration follows an exfiltration chain across five sources.

### 4. Look-Alike Testing

The demonstration includes legitimate activities that resemble suspicious behaviour, such as a nightly backup and an approved scan.

ChronoTrace records why these activities were rejected rather than simply removing them from the results.

Approved changes must match identifying information and cover the activity being investigated. A time window alone is not sufficient to approve an event.

### 5. Packet Capture Analysis

ChronoTrace analyses classic PCAP files using Python's standard library.

The implementation handles:

* TCP sequence-number wrap-around.
* Retransmissions and overlapping segments.
* Out-of-order packet arrival.
* Missing segments and gaps.
* Reconstruction of transferred data.
* Automatic completeness checks for recovered archives.

The tool reports whether the transferred archive is complete without writing the recovered file contents to disk.

### 6. Evidence Generation

Every finding is linked to its original evidence.

Evidence locators contain the source file, line information, and SHA-256 hash of the relevant raw record. A verification test checks that each locator resolves to the expected evidence.

This makes it possible to trace investigation results back to the records that support them.

### 7. Investigation Report and Viewer

ChronoTrace generates:

* `report.md` — a plain-English summary of the investigation.
* `viewer.html` — an offline visualisation of the event timeline.
* `timeline.csv` — the reconstructed timeline.
* `evidence-index.csv` — references to the supporting evidence.
* `skew-report.json` — clock-correction results.
* `verdicts.json` — detection results and decisions.
* `exfil-analysis.json` — packet capture analysis.
* `quarantine.json` — records rejected during ingestion.
* `row-accounting.json` — ingestion accounting information.

The timeline viewer includes a slider that allows events to be viewed using their original timestamps and then with the calculated clock corrections applied. This makes it easier to see how events that initially appear scattered can form a short, connected attack sequence.

A completed demonstration is available in `sample-output/`. Open `sample-output/viewer.html` in a browser or read `sample-output/report.md` to inspect the results without running the project.

## Project Structure

```text
chronotrace/
├── chronotrace/
│   ├── skew.py
│   ├── detect.py
│   ├── pcap.py
│   └── ...
├── tests/
├── docs/
├── demo/
├── sample-output/
└── README.md
```

The main investigation stages are separated into clock analysis, detection, packet capture analysis, and evidence/report generation.

## Requirements

* Python 3.10 or newer.
* No third-party Python packages are required for the main project.
* An internet connection is not required to run the investigation.

The project was tested on Windows using Python 3.14.8.

For Windows users who do not have `make`, see `docs/RUN_ON_WINDOWS.md`.

## Running the Tests

Run the test suite with:

```powershell
python tests\run_tests.py
```

Latest test result:

```text
Ran 55 tests in 2.717s

OK
```

All 55 tests passed in this run.

## Running the Demo

First, generate the synthetic input:

```powershell
python -m chronotrace synth --out demo\input
```

Then build the investigation output:

```powershell
python -m chronotrace build --input demo\input --changes demo\input\changes.json --out demo\output
```

The latest demo run produced:

```text
built demo\output: 2 alert(s), 2 rejected look-alike(s)
```

To open the timeline viewer on Windows:

```powershell
start demo\output\viewer.html
```

The generated output contains the investigation report, timeline, evidence index, clock-skew results, verdicts, and offline viewer.

## Verifying Reproducibility

ChronoTrace includes a verification command that builds the same input twice and checks whether the generated outputs are identical.

Run:

```powershell
python -m chronotrace verify --input demo\input --changes demo\input\changes.json
```

Latest result:

```text
VERIFY OK: two clean builds are byte-identical
```

The verification process also produces SHA-256 hashes for the generated files. This helps confirm that repeated builds with the same input produce consistent results.

## Benchmark

A synthetic benchmark is included to evaluate how the project performs with a larger number of events.

Generate the benchmark data:

```powershell
python -m chronotrace synth --out demo\bench --scale 278
```

Build the investigation output:

```powershell
python -m chronotrace build --input demo\bench --changes demo\bench\changes.json --out demo\bench-out
```

To view the recorded metrics:

```powershell
type demo\bench-out\run-metrics.json
```

The latest benchmark processed **750,646 events**.

The result from the Windows test environment was:

```json
{
  "events_loaded": 750646,
  "peak_memory_mb": 638.4,
  "python": "3.14.8",
  "wall_seconds": 63.526
}
```

This corresponds to approximately **63.5 seconds of runtime and 638.4 MB peak memory** for the benchmark run.

These figures are provided as a reference from the test environment. Runtime and memory usage will vary depending on the machine and Python environment.

## Using ChronoTrace with Other Logs

For a normal investigation, the input directory can contain JSONL files from different log sources and, optionally, a classic PCAP file.

Example:

```bash
python -m chronotrace build \
    --input DIR \
    --out OUT \
    --changes changes.json \
    --reference SOURCE
```

Events that appear in more than one log source should contain a common `correlation_id`. This identifier is used to connect related events and is important for the clock-skew calculation.

## What Was Improved

ChronoTrace is a new codebase informed by lessons from earlier SOC analysis stages. No files were copied into this repository.

The main improvements include:

| Earlier approach                                                                          | ChronoTrace                                                                                             |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Clock offsets were calculated with limited precision and mainly against one pivot source. | Clock offsets are calculated with second-level precision using relationships across multiple sources.   |
| A source without anchors could fall back to an offset of zero.                            | Sources without usable anchors are flagged rather than silently treated as correct.                     |
| Clock offsets in the later stage were supplied manually.                                  | Clock offsets are calculated automatically.                                                             |
| PCAP analysis depended on Scapy, and completeness was checked manually.                   | PCAP processing uses the standard library and performs automatic gap, overlap, and completeness checks. |
| Detection rules operated mainly on individual events from one log source.                 | The current detection chain correlates activity across five sources.                                    |
| Evidence indexes were created manually.                                                   | Evidence locators are generated during the investigation and checked automatically.                     |
| Earlier parser work established row-accounting and quarantine concepts.                   | These principles were rebuilt and tested for the schemas used by ChronoTrace.                           |

Further details about the relationship between earlier work and this implementation are available in `docs/PROVENANCE.md`.

## Design Decisions

### Majority Clock

ChronoTrace uses the majority of available source relationships to establish a reference clock.

When only two usable sources are available, there is no clear majority. In that situation, the tool warns about the ambiguity, and a reference source can be supplied manually.

### Correlation IDs

The project uses `correlation_id` to connect events across sources.

Linking events only by hostname or username can produce many unrelated matches and make clock calculations unreliable. Using a shared identifier provides a more reliable basis for correlation.

### Duplicate Handling

Only exact duplicate records are treated as duplicates.

Duplicates are counted rather than silently discarded, allowing the final row accounting to be checked against the input.

### Approved Changes

An approved change is not accepted simply because an event occurred within an approved time period.

The identifying information must also match, and the approval must cover the activity being investigated.

### Confidence Levels

Findings supported by multiple independent sources can receive higher confidence than findings supported by a single source.

A single-source finding is capped at medium confidence.

### Recovered Data

The PCAP analysis does not save recovered exfiltrated content to disk.

Instead, ChronoTrace reports information such as content hashes, recovered size, archive/member names, record counts, and whether the transferred content is complete.

## Limitations

The current implementation has several limitations:

* The demonstration data is synthetic. It is based on lessons from earlier work but is not copied from previous assessments.
* The clock model assumes that the offset for a source remains constant. Clock drift is not modelled.
* A source needs usable anchors before its clock can be corrected. Sources without anchors remain uncorrected and are flagged.
* PCAP support currently covers classic PCAP with Ethernet or raw IPv4 and TCP traffic.
* IP fragments are skipped.
* Encrypted uploads such as HTTPS cannot be inspected as plaintext by the current implementation.
* The timestamp of the PCAP itself is treated as recorded; the tool does not independently correct the capture clock.
* The current detections focus on the demonstration attack chain, staging activity without an identified entry point, and authentication bursts. They demonstrate the detection design rather than provide a complete production rule set.
* A single-source finding is limited to medium confidence.
* Processing is performed in memory, so available system memory becomes an important limitation as the number of events increases.

## Documentation

Additional information about the project is available in the `docs/` directory:

* `docs/PROVENANCE.md` — documents the relationship between ChronoTrace and earlier project work, including the techniques reused and the improvements made.
* `docs/RUN_ON_WINDOWS.md` — provides instructions for running ChronoTrace on Windows without `make`.

## Current Demo Result

The current synthetic demonstration produces:

```text
2 alerts
2 rejected look-alikes
```

The rejected activities are included intentionally. The aim is not only to identify suspicious activity but also to distinguish it from legitimate operations and explain why those activities were rejected.

The generated report, viewer, and evidence files contain the detailed results of the investigation.

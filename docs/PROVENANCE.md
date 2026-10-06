# Provenance: what is reused, what is new

ChronoTrace was implemented as a new codebase for the finals. I reviewed my Stage 5 and Stage 9 submissions and carried over ideas, lessons and labels, not files.

## Taken from earlier stages

| Source (my earlier work)                                       | What I kept                                                                                                                                                                    |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Stage 5 `hunt_engine/clock.py`, `ClockCorrector.infer_offsets` | The core idea: events shared between sources can reveal clock differences                                                                                                      |
| Stage 5 README lessons                                         | Row accounting must balance; sorting should use full tie-breakers for determinism; sources should only be linked on `correlation_id`; run time should stay out of hashed files |
| Stage 9 `decision-log.md` D-001                                | The reasoning that two independent anchors agreeing closely is stronger evidence of a skewed clock than coincidence                                                            |
| Stage 9 `pipeline/archive.py`                                  | The approach of grouping packets into TCP flows, ordering them by sequence number, and finding the ZIP in the HTTP body                                                        |
| Stage 9 `detections/rules.py`                                  | The technique labels T1566/T1059, T1053.005, T1560, T1041, T1070.004, and the idea of staging followed by transfer followed by cleanup                                         |
| Stage 8 detection work                                         | Keying detection on classes of behaviour rather than literal strings or fixture IDs                                                                                            |

## Limits of the earlier work that motivated the new work

* Stage 5 inferred offsets in whole minutes against a single pivot source, using the most common delta, and defaulted unanchored sources to 0 with only a printed warning.
* Stage 9 passed the clock offset as a hand-derived flag.
* Stage 9 ordered streams by sorted flow key rather than time, ordered chunks by raw sequence number without handling wrap-around, retransmissions or gaps, depended on Scapy, wrote recovered files to disk, and judged completeness manually.
* Stage 9 rules ran on one log only.

## New in ChronoTrace

Second-level multi-source skew solving with outlier rejection, a best-supported spanning tree, a cycle check and confidence; majority-clock reference selection; standard-library PCAP reassembly with an automatic completeness verdict; a cross-source chain rule; rejection verdicts with reasons; generated and tested evidence locators; the offline timeline viewer; and the benchmark workflow.

## Deliberately NOT included

Sealed assessment evidence, recovered files, timelines and outputs from earlier stages, evidence markers, private assignment identifiers, and the specific hosts, addresses, domains and timings of those cases.

All demo data is synthetic and was changed so it does not reproduce the earlier cases. `make audit` scans for private identifiers.

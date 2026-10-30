# Capture evaluation

Generated 2026-10-19 10:37:17  |  confidence threshold 70%

> **These captures are SIMULATED by this project's traffic generator, not recorded from a real network. They show the tool works; re-run it on real recordings for real false-positive rates.**

## Benign captures (every alert is a false alarm)

| Capture | Packets | Flows | Flow alerts (guardrail on) | Flow FP rate | Confirmed incidents | Needs review | Flow alerts (guardrail off) | Flow FP rate (off) | Confirmed (off) |
|---|---|---|---|---|---|---|---|---|---|
| sim_home_wifi.pcap | 7,469 | 698 | 10 | 1.4% | **0**  | 3 | 34 | 4.9% | 0 |
| sim_quiet_network.pcap | 889 | 190 | 0 | 0.0% | **0**  | 0 | 13 | 6.8% | 0 |
| sim_streaming_download_unseen.pcap | 14,839 | 26 | 1 | 3.8% | **0**  | 1 | 2 | 7.7% | 0 |
| sim_video_call.pcap | 8,060 | 31 | 2 | 6.5% | **0**  | 2 | 3 | 9.7% | 0 |
| sim_video_call_hd_unseen.pcap | 15,320 | 38 | 2 | 5.3% | **0**  | 1 | 2 | 5.3% | 0 |

## Attack captures (detections)

| Capture | Expected | Detected | Missed | Unexpected confirmed | Needs review |
|---|---|---|---|---|---|
| sim_attacks.pcap | ARP_SPOOFING, PORT_SCAN, SLOWLORIS, SYN_FLOOD | ARP_SPOOFING, PORT_SCAN, SLOWLORIS, SYN_FLOOD | - | - | 0 |

**Overall (benign):** 15 of 983 flows flagged (1.5%); 0 confirmed incident(s) across 5 capture(s).

## Original code (before these changes) on the same simulated captures

| Capture | Flows | Flows flagged | % |
|---|---|---|---|
| sim_attacks.pcap | 404 | 404 | 100.0% |
| sim_home_wifi.pcap | 698 | 698 | 100.0% |
| sim_quiet_network.pcap | 190 | 190 | 100.0% |
| sim_streaming_download_unseen.pcap | 26 | 26 | 100.0% |
| sim_video_call.pcap | 31 | 31 | 100.0% |
| sim_video_call_hd_unseen.pcap | 38 | 38 | 100.0% |

The original model scored every flow as anomalous, so every flow was flagged.

Regenerate with: `python tools/evaluate_captures.py --simulate captures_sim/ captures_sim/ --markdown docs/evaluation_simulated.md`

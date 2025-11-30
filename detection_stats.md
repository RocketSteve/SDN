========================================
IDS DETECTION EFFECTIVENESS COMPARISON
========================================
Generated: Tue 11 Nov 2025 11:59:41 AM PST

Study: Traditional 3-Tier vs Proactive SDN 3-Tier
IDS: Suricata (custom rules only)
Attack Generator: Controlled (deterministic packet counts)

========================================
TIME-TO-DETECTION COMPARISON
========================================


TRADITIONAL NETWORK:
==================================================

Iteration 1:
  HTTP Flood: 3.107386s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.03307s → 10148 alerts (1014% detection rate)
  SYN Flood: 102.118264s → 1008 alerts (1% detection rate)
  → Total alerts: 11172

Iteration 10:
  HTTP Flood: 3.105828s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.019312s → 10148 alerts (1014% detection rate)
  SYN Flood: 102.059941s → 1009 alerts (1% detection rate)
  → Total alerts: 11173

Iteration 2:
  HTTP Flood: 3.113166s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 0.007353s → 10145 alerts (1014% detection rate)
  SYN Flood: 103.590216s → 1007 alerts (1% detection rate)
  → Total alerts: 11168

Iteration 3:
  HTTP Flood: 3.110324s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.02957s → 10145 alerts (1014% detection rate)
  SYN Flood: 102.139529s → 1009 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 4:
  HTTP Flood: 3.114089s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.026194s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.076912s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 5:
  HTTP Flood: 3.115469s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.036955s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.060625s → 1009 alerts (1% detection rate)
  → Total alerts: 11171

Iteration 6:
  HTTP Flood: 3.116579s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.035824s → 10147 alerts (1014% detection rate)
  SYN Flood: 102.197824s → 1007 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 7:
  HTTP Flood: 3.104164s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.026071s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.058508s → 1009 alerts (1% detection rate)
  → Total alerts: 11171

Iteration 8:
  HTTP Flood: 3.096725s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 0.013445s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.274422s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 9:
  HTTP Flood: 3.119449s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.037179s → 10147 alerts (1014% detection rate)
  SYN Flood: 103.18423s → 1008 alerts (1% detection rate)
  → Total alerts: 11171


PROACTIVE_SDN NETWORK:
==================================================

Iteration 1:
  HTTP Flood: 3.110982s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.021673s → 10147 alerts (1014% detection rate)
  SYN Flood: 102.129316s → 1008 alerts (1% detection rate)
  → Total alerts: 11171

Iteration 10:
  HTTP Flood: 3.112859s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.018673s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.150154s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 2:
  HTTP Flood: 3.113281s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.007778s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.351814s → 1009 alerts (1% detection rate)
  → Total alerts: 11171

Iteration 3:
  HTTP Flood: 3.101966s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.008258s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.094598s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 4:
  HTTP Flood: 3.111971s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.03131s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.163534s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 5:
  HTTP Flood: 3.106592s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.016863s → 10145 alerts (1014% detection rate)
  SYN Flood: 103.055561s → 1007 alerts (1% detection rate)
  → Total alerts: 11168

Iteration 6:
  HTTP Flood: 3.114994s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.01077s → 10146 alerts (1014% detection rate)
  SYN Flood: 102.158483s → 1008 alerts (1% detection rate)
  → Total alerts: 11170

Iteration 7:
  HTTP Flood: 3.1724s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.019897s → 10148 alerts (1014% detection rate)
  SYN Flood: 102.141465s → 1008 alerts (1% detection rate)
  → Total alerts: 11172

Iteration 8:
  HTTP Flood: 3.114506s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.033871s → 10148 alerts (1014% detection rate)
  SYN Flood: 102.086357s → 1008 alerts (1% detection rate)
  → Total alerts: 11172

Iteration 9:
  HTTP Flood: 3.1161s → 16 alerts (3% detection rate)
  ICMP Flood: NOT DETECTED (10000 packets sent)
  Port Scan: 1.033875s → 10147 alerts (1014% detection rate)
  SYN Flood: 100.644271s → 1008 alerts (1% detection rate)
  → Total alerts: 11171


========================================
STATISTICAL SUMMARY
========================================

TRADITIONAL:
  Iterations: 10
  Mean alerts: 11194
  Range: 11191 - 11197

PROACTIVE_SDN:
  Iterations: 10
  Mean alerts: 11194
  Range: 11192 - 11196


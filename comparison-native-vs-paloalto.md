# Per-Connection Visibility — Native AWS vs Palo Alto

Same traffic, inspected inline by both engines in one env. This is the per-flow field set each
exposes (join key = 5-tuple `src_ip,dst_ip,src_port,dst_port,proto` within a time window).
Reminder: **both see the same packets** — the difference is what each *derives and logs*, not raw visibility.

| Per-connection field | VPC Flow Logs | AWS Network Firewall | Palo Alto VM-Series |
|---|---|---|---|
| 5-tuple (IPs, ports, proto) | ✅ | ✅ | ✅ |
| bytes / packets / start-end | ✅ | ✅ (netflow) | ✅ |
| action (allow/deny) | ✅ | ✅ | ✅ |
| original src/dst (behind TGW/NAT) | ✅ `pkt-srcaddr/dstaddr` | – | ✅ (GENEVE TLV) |
| TLS SNI | ❌ | ✅ `tls.sni` | ✅ |
| TLS version / cipher | ❌ | ✅ | ✅ |
| JA3 / JA4 fingerprint | ❌ | ✅ | ✅ |
| HTTP host / URL / method / UA (decrypt) | ❌ | ✅ | ✅ |
| Domain / URL **category** | ❌ | ✅ `aws_category` (coarse) | ✅ **URL Filtering** (granular) |
| **Application identity** | ❌ (IP/port only) | `app_proto` + SNI-derived | ✅ **App-ID** (app **+ sub-function**, e.g. youtube-streaming vs -base) |
| **User identity** | ❌ | ❌ | ✅ **User-ID** (user, not just IP) |
| Threat / IPS verdict | ❌ | ✅ (AWS managed rules) | ✅ Threat Prevention |
| Malware / file sandbox | ❌ | partial (file rules) | ✅ **WildFire** |
| DLP / data patterns | ❌ | limited (regex) | ✅ Data Filtering |
| File info (name / hash) | ❌ | ✅ (decrypt) | ✅ |

## How to read it for the customer
- **Flow Logs** = the cheap, broad metadata layer (who-talked-to-whom + volume). No app identity.
- **Native NFW** already delivers strong **application identity** (SNI, HTTP, domain category, JA3/JA4) and decrypted L7 — this is "what AWS can see" end to end.
- **Palo Alto** sees the *same bytes* but adds **App-ID sub-functions, User-ID, granular URL categories, WildFire sandboxing, and DLP** — deeper *meaning*, not more raw data.
- **Shared ceiling:** mTLS-to-origin payload, ECH-hidden SNI, and QUIC payload are opaque to **both**.

## Co-sell framing
Step 1 (native) proves the full visible surface with AWS-only services. Step 2 (Palo Alto via GWLB)
is the "same data, richer classification + threat/DLP" upgrade — a natural subscription expansion.

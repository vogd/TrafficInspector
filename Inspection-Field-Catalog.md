# Inspection Field Catalog — what AWS can gather and what to feed a firewall

Purpose: enumerate every field available for inspection in the TGW → inspection-VPC design,
grouped by source, and define the exact inputs a 3rd-party NGFW (e.g., Palo Alto VM-Series)
needs to extract them. Visibility increases as you go down: **flow metadata → TLS handshake → decrypted L7**.

Legend: 👁 = visible without decryption · 🔓 = requires TLS termination/decryption · 🧩 = derived/behavioral

---

## 1. What arrives at the inspection appliance (via GWLB GENEVE, UDP 6081)

GWLB does **not** parse or decrypt. It encapsulates the **entire original packet** in GENEVE and
forwards it to the appliance, plus AWS-defined GENEVE **TLV metadata** (option class `0x0108`).
The appliance (Palo Alto VM-Series, Suricata, Network Firewall, etc.) is what extracts the fields below.

| Group | Fields | Vis |
|---|---|---|
| GENEVE metadata | GWLB endpoint ID, attachment/flow identifier (→ attribute flow to source GWLBE / consumer VPC) | 👁 |
| L3 (IP) | src IP, dst IP, IP protocol, TTL, DSCP/ToS, fragmentation flags, total length | 👁 |
| L4 TCP | src port, dst port, TCP flags (SYN/FIN/RST/PSH/URG), seq/ack, window size, options/MSS | 👁 |
| L4 UDP | src port, dst port, length | 👁 |
| TLS ClientHello | **SNI (server_name)**, TLS version, offered cipher suites, **ALPN (h2/http1.1/h3)**, extensions, **JA3 / JA4** fingerprint | 👁 |
| TLS ServerHello/cert | chosen cipher, server cert chain (CN/SAN/issuer/validity), **JA3S / JA4S** | 👁 |
| QUIC (UDP/443) | QUIC initial, SNI in QUIC ClientHello (👁 unless ECH); payload otherwise opaque | 👁/🧩 |
| DNS (if in path) | query name, qtype, response IPs, TTL | 👁 |
| HTTP (cleartext or after decrypt) | method, host/`:authority`, URI/path, request+response headers, **user-agent**, status, content-type, cookies, body, **transferred files** | 🔓 |
| Behavioral | bytes ↑/↓, packet count, packet-size distribution, inter-arrival timing, flow duration, direction, concurrent peer count | 🧩 |

> Key point: **without decryption you still get SNI + JA3/JA4 + ALPN + ports + behavior** — enough to
> identify most well-known apps. Decryption only adds the HTTP/payload layer (🔓).

---

## 2. VPC Flow Logs (metadata feed for AI — NOT for the appliance)

Enable on GWLBE / appliance ENIs / subnet / VPC. **Metadata only — no SNI, no domain, no payload.**

`version, account-id, interface-id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes,
start, end, action (ACCEPT/REJECT), log-status, vpc-id, subnet-id, instance-id, tcp-flags, type
(IPv4/IPv6/EFA), pkt-srcaddr, pkt-dstaddr, region, az-id, sublocation-type, sublocation-id,
pkt-src-aws-service, pkt-dst-aws-service, flow-direction, traffic-path, ecs-* (cluster/task/...),
reject-reason, resource-id, encryption-status`

Use a **custom format** including `pkt-srcaddr`/`pkt-dstaddr` — these preserve the **original**
client/app IPs behind the TGW/GWLB hops (the plain `srcaddr` is just the intermediate).

---

## 3. AWS Network Firewall logs (Suricata EVE JSON) — the L7 identity feed

Three event types: **flow** (uni-directional netflow), **alert** (rule match), **tls** (TLS engine).

| Field | Source event | Vis |
|---|---|---|
| `firewall_name`, `availability_zone`, `event_timestamp` | all | 👁 |
| `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `flow_id`, `direction` | all | 👁 |
| `app_proto` (`tls`, `http2`, `dns`, `quic`…) | flow/alert | 👁 |
| `tls.sni`, `tls.version`, JA3/JA4 | tls/alert | 👁 |
| `aws_category` (URL/domain category, e.g. `["Search Engines and Portals"]`) | alert | 👁 |
| `http.hostname`/`:authority`, `http.url`, `http.http_method`, `http.http_user_agent`, `request_headers` | alert (decrypted) | 🔓 |
| `alert.signature`, `signature_id`, `category`, `severity`, `action`, `verdict.action` | alert | 👁 |
| `netflow.pkts`, `netflow.bytes`, `age`, `min_ttl`/`max_ttl` | flow | 🧩 |
| `tls_inspected: true`, `revocation_check`, `tls_error` | tls | 🔓 |
| `pkt_src: "geneve encapsulation"` | when behind GWLB | 👁 |
| `fileinfo` (filename, size, md5/sha, magic) | alert (decrypted) | 🔓 |

---

## 4. Per-application identifying fields (Zoom / Teams / Chrome / torrent)

| App | Identifying fields (👁 no-decrypt) | Adds with 🔓 / 🧩 |
|---|---|---|
| **Zoom** | SNI `*.zoom.us`, `*.zoom.com`; media over UDP **8801–8810**; Zoom ASN dst IPs; JA3 | RTP-like constant bitrate, real-time jitter profile 🧩 |
| **MS Teams** | SNI `*.teams.microsoft.com`, `teams.events.data.microsoft.com`, `*.sfb.teams.microsoft.com`; Microsoft ASN; STUN/TURN media UDP **3478–3481**; JA3 | tenant ID in token, join type 🔓 |
| **Chrome** | **JA3/JA4** browser fingerprint, ALPN `h2`/`h3`, **QUIC** attempts on UDP 443, `user-agent` 🔓; broad SNI variety | headless/automation patterns, beaconing periodicity 🧩 |
| **Torrent / BitTorrent** | mostly **behavioral**: many concurrent peers, **DHT over UDP**, random/non-standard ports, uTP, high-entropy payload, tracker SNIs; rarely a clean SNI | peer fan-out, entropy score, swarm pattern 🧩 (signatures usually fail → ML) |

Note: torrent and other obfuscated/encrypted P2P are best caught by **behavioral/ML** features
(§1 behavioral + §3 netflow), not by SNI signatures.

---

## 5. Inputs required to feed a firewall

### AWS Network Firewall (native)
- TGW attachment in **appliance mode** + routing so traffic transits the firewall endpoints.
- For 🔓 outbound decryption: a **CA cert imported into ACM** (`CertificateAuthorityArn`), with that
  CA **trusted/installed on the end devices** (Aruba can push it).
- For 🔓 inbound: imported **server cert per domain**.
- TLS inspection **scope** (src/dst CIDRs + ports). Rule groups (incl. a rule to **block QUIC** so apps fall back to TCP/TLS).
- Logging config → CloudWatch/S3/Firehose for the §3 fields.

### Palo Alto VM-Series (or any 3rd-party NGFW) behind GWLB
- **GENEVE support** on the appliance (VM-Series supports it natively; Linux appliances use `gwlbtun`).
  Appliance reads §1 GENEVE TLVs for source attribution.
- GWLB target group registration + health checks; one-arm or two-arm mode.
- **App-ID / signature set** (built-in) — identifies apps from §1 👁 fields (SNI, JA3, ports, heuristics) even without decryption.
- For 🔓 deep visibility: **SSL Forward Proxy decryption** with its own CA cert (same device-trust requirement as NFW).
- Decryption exclusions for **mTLS / pinned** destinations (cannot transparently MITM client-cert flows).
- Log forwarding (syslog/HTTP) → S3/Security Lake (OCSF) for the AI layer.

### What the appliance fundamentally **cannot** get
- 🚫 Payload of **mTLS** flows to client-cert origins (no client key to present upstream).
- 🚫 **ECH / Encrypted SNI** — SNI is hidden; only IP/behavior remain.
- 🚫 **QUIC** payload unless QUIC is blocked to force TCP fallback.

---

## 6. Feed-to-AI summary

| Consumer | Feed | Best for |
|---|---|---|
| Tier 0 rules (no LLM) | §1 👁 SNI/JA3/JA4/ports | Bulk app tagging (Zoom/Teams/Chrome) |
| Tier 1 ML (SageMaker) | §1 behavioral + §2 flow logs | Obfuscated apps (torrent), anomaly scoring |
| Tier 2 LLM (Bedrock) | §3 NFW alert/tls/http logs (OCSF) | Triage, correlation, NL queries, rule-gen |

VPC Flow Logs alone (§2) = volume/beaconing/lateral-movement only. Application identity needs §1/§3.

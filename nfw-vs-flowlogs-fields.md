# Field Visibility Reference — VPC Flow Logs vs AWS Network Firewall

Complete list of fields each AWS service can emit per flow/connection.
**One-line difference:** Flow Logs = L3/L4 **metadata only**; Network Firewall = the same 5-tuple **plus the entire application layer** (TLS, HTTP, DNS, files) and rule-match detail.

---

## A. VPC Flow Logs — ALL available fields (metadata only; no SNI/domain/payload)

| Field | Meaning |
|---|---|
| version | flow log format version |
| account-id | AWS account of the source ENI |
| interface-id | network interface ID |
| **srcaddr** | source IP (intermediate if behind TGW/NAT) |
| **dstaddr** | destination IP |
| **srcport** | source port |
| **dstport** | destination port |
| **protocol** | IANA protocol number |
| packets | packets in the flow |
| bytes | bytes in the flow |
| start / end | flow start/end (epoch) |
| action | ACCEPT / REJECT |
| log-status | OK / NODATA / SKIPDATA |
| vpc-id | VPC ID |
| subnet-id | subnet ID |
| instance-id | instance ID (if yours) |
| tcp-flags | OR'd TCP flags (SYN/FIN/RST/SYN-ACK) |
| type | IPv4 / IPv6 / EFA |
| **pkt-srcaddr** | original packet source IP (real client behind TGW/NAT) |
| **pkt-dstaddr** | original packet destination IP |
| region | AWS Region |
| az-id | Availability Zone ID |
| sublocation-type / sublocation-id | Wavelength/Outpost/Local Zone |
| pkt-src-aws-service / pkt-dst-aws-service | AWS service name for the IP (S3, EC2…) |
| flow-direction | ingress / egress |
| traffic-path | egress path (IGW, NAT, TGW, peering, VPN…) |
| ecs-cluster-arn / -name | ECS cluster (if ECS task) |
| ecs-container-instance-arn / -id | ECS container instance |
| ecs-container-id / ecs-second-container-id | container runtime IDs |
| ecs-service-name | ECS service |
| ecs-task-definition-arn / ecs-task-arn / ecs-task-id | ECS task |
| reject-reason | BPA / EC |
| resource-id | regional NAT gateway ID |
| encryption-status | VPC encryption-in-transit status |

**Not available in Flow Logs:** SNI, domain, URL, HTTP, user-agent, certificates, JA3, file hashes, any payload.

---

## B. AWS Network Firewall — ALL fields (Suricata EVE: alert / netflow / tls events)

### Envelope + L3/L4 (every event)
| Field | Notes |
|---|---|
| firewall_name, availability_zone, event_timestamp | AWS-added |
| event.timestamp, event_type | `alert` \| `netflow` \| `tls` |
| flow_id, tx_id, direction | flow correlation, to_server/to_client |
| pkt_src | e.g. `geneve encapsulation` |
| **src_ip, src_port, dest_ip, dest_port, proto** | the 5-tuple |
| app_proto | `tls`, `http`, `http2`, `dns`, `ssh`, `smtp`, `ftp`… |
| aws_category | URL/Domain category (when category rules enabled) |
| tls_inspected | `true` when decrypting |

### netflow (flow) events — volume/behavior
| Field | Notes |
|---|---|
| netflow.pkts, netflow.bytes | per uni-directional flow |
| netflow.start, netflow.end, netflow.age | duration |
| netflow.min_ttl, netflow.max_ttl | TTLs |
| netflow.state, netflow.reason, netflow.alerted | flow state |
| tcp.tcp_flags + syn/fin/rst/psh/ack | TCP flags |

### alert events — rule match
| Field | Notes |
|---|---|
| alert.action | allowed / blocked |
| alert.signature, signature_id, rev | matched rule (e.g. "MS Teams") |
| alert.category, severity | classification |
| verdict.action | pass / drop / reject |

### TLS metadata (handshake — no decryption needed)
| Field | Notes |
|---|---|
| tls.sni / sni | server name from ClientHello |
| tls.version | TLS 1.0–1.3 |
| tls.subject | server cert subject |
| tls.issuerdn | server cert issuer |
| tls.serial, tls.fingerprint | cert serial + SHA1 |
| tls.notbefore, tls.notafter | cert validity |
| tls.session_resumed | resumption |
| tls_error | SNI mismatch / handshake errors (tls log) |
| revocation_check.leaf_cert_fpr / status / action | OCSP/CRL result (outbound) |
| **JA3 / JA4** | ❌ **NOT emitted by AWS NFW** (3rd-party only) |

### HTTP / HTTP2 (requires TLS decryption for HTTPS)
| Field | Notes |
|---|---|
| http.hostname / `:authority` | host |
| http.url / `:path` | request path |
| http.http_method / `:method` | GET/POST/… |
| http.http_user_agent | client app + version |
| http.http_content_type | content type |
| http.http_refer | referer |
| http.status, http.length, http.protocol | response status/size/version |
| http.request_headers[] / response_headers[] | full headers |
| http.redirect | redirect target |

### DNS (if DNS traverses the firewall)
| Field | Notes |
|---|---|
| dns.rrname, rrtype | query name + type |
| dns.answers[], rcode | responses |

### File transfers (decrypted HTTP/SMTP/FTP)
| Field | Notes |
|---|---|
| fileinfo.filename, size, magic | file metadata |
| fileinfo.md5 / sha1 / sha256 | hashes (DLP/malware) |
| fileinfo.state, stored | extraction status |

---

## C. Side-by-side summary

| Capability | VPC Flow Logs | AWS Network Firewall |
|---|---|---|
| 5-tuple (IPs/ports/proto) | ✅ | ✅ |
| bytes / packets / TCP flags | ✅ | ✅ (netflow) |
| original IPs behind TGW/NAT | ✅ (pkt-srcaddr/dstaddr) | – |
| AWS-service / ECS / traffic-path metadata | ✅ | – |
| **SNI / TLS version / cert subject-issuer** | ❌ | ✅ |
| **HTTP host / URL / method / user-agent / headers** | ❌ | ✅ (decrypted) |
| **DNS queries** | ❌ | ✅ |
| **File names / hashes** | ❌ | ✅ (decrypted) |
| matched rule / category / verdict | ❌ | ✅ |
| **JA3 / JA4 fingerprints** | ❌ | ❌ (3rd-party only) |

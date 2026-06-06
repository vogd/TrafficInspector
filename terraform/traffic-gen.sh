#!/bin/bash
# Emulated end-client traffic. The spoke route table steers ALL egress through the
# inspection firewall, so no proxy is needed. Read results in NFW alert/tls logs
# (SNI + app classification) and VPC flow logs (torrent fan-out / volume anomaly).
# NOTE: to test live TLS *decryption*, install the NFW CA in this host's trust store
#       (mirrors Aruba pushing the CA to devices). SNI is visible without it.
set -u
NC="ncat"; command -v ncat >/dev/null || NC="nc"
log(){ echo "$(date -u +%FT%TZ) $*"; }
udp(){ echo -n "$3" | timeout 1 "$NC" -u -w1 "$1" "$2" 2>/dev/null; }

while true; do
  # Zoom: TLS SNI *.zoom.us + media UDP 8801-8810
  curl -sS -o /dev/null --max-time 6 https://zoom.us/ && log "zoom tls"
  udp zoom.us 8801 x; udp zoom.us 8810 x

  # MS Teams: TLS SNI + telemetry + STUN/TURN UDP 3478-3481
  curl -sS -o /dev/null --max-time 6 https://teams.microsoft.com/ && log "teams tls"
  curl -sS -o /dev/null --max-time 6 https://teams.events.data.microsoft.com/ || true
  udp teams.microsoft.com 3478 x; udp teams.microsoft.com 3481 x

  # Chrome-like: real JA3 + QUIC attempt on UDP/443 (NFW should DROP -> proves QUIC block)
  curl -sS -o /dev/null --max-time 6 -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36" https://www.google.com/ && log "chrome tls"
  udp www.google.com 443 quic && log "quic sent (expect blocked)"

  # Torrent-like: DHT bootstrap (UDP 6881) + concurrent peer fan-out shape
  for h in router.bittorrent.com dht.transmissionbt.com router.utorrent.com; do udp "$h" 6881 "d1:ad2:id20:" & done
  wait
  log "cycle done"; sleep 15
done

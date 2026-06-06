#!/bin/bash
# nfw-test.sh — Trigger NFW rules and verify detection/blocking
# Run while connected to the TrafInspector VPN
#
# Usage: ./nfw-test.sh [detect|block|status]
#   detect  — Generate traffic to trigger app detection rules (alert only)
#   block   — Add drop rules for specified app categories
#   status  — Check recent NFW alerts for detections

set -euo pipefail
REGION="us-east-2"
PROFILE="${AWS_PROFILE:-default}"
LOG_GROUP="/trafinspector/nfw/alert"
RULE_GROUP="trafinspector-stateful"

# --- DETECT: trigger rules by generating traffic ---
detect() {
  echo "═══════════════════════════════════════════════════════════"
  echo " TRIGGERING NFW RULES — generating traffic from this device"
  echo " (must be connected to TrafInspector VPN)"
  echo "═══════════════════════════════════════════════════════════"
  echo

  TARGETS="AI:OpenAI|https://api.openai.com/v1/models
AI:Anthropic|https://api.anthropic.com/v1/messages
AI:HuggingFace|https://huggingface.co
AI:DeepSeek|https://deepseek.com
Slack|https://slack.com
Discord|https://discord.com
Dropbox|https://www.dropbox.com
GitHub|https://github.com
YouTube|https://www.youtube.com
Netflix|https://www.netflix.com
Evasion:Tor|https://www.torproject.org
VPN:NordVPN|https://nordvpn.com
Reddit|https://www.reddit.com
LinkedIn|https://www.linkedin.com"

  echo "$TARGETS" | while IFS='|' read -r app url; do
    printf "  %-20s → %s ... " "$app" "$url"
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$code" = "000" ]; then
      echo "BLOCKED/timeout"
    else
      echo "$code"
    fi
  done

  echo
  echo "  === P2P / TORRENT EMULATION (should be BLOCKED) ==="
  printf "  %-20s → %s ... " "P2P:BitTorrent-UA" "curl -A BitTorrent"
  code=$(curl -sk --max-time 5 -A "BitTorrent/7.11" -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || echo "000")
  [ "$code" = "000" ] && echo "BLOCKED" || echo "$code"

  printf "  %-20s → %s ... " "P2P:qBittorrent-UA" "curl -A qBittorrent"
  code=$(curl -sk --max-time 5 -A "qBittorrent/4.6.1" -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || echo "000")
  [ "$code" = "000" ] && echo "BLOCKED" || echo "$code"

  printf "  %-20s → %s ... " "P2P:Tracker-SNI" "tracker.opentrackr.org"
  code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" https://tracker.opentrackr.org 2>/dev/null || echo "000")
  [ "$code" = "000" ] && echo "BLOCKED/timeout" || echo "$code"

  printf "  %-20s → %s ... " "P2P:Tracker-DNS" "nslookup tracker"
  nslookup tracker.opentrackr.org >/dev/null 2>&1 && echo "resolved" || echo "failed"

  echo
  echo "  === AI CLASSIFICATION TRIGGERS (no NFW rule, AI identifies) ==="
  for pair in \
    "Airtable|https://airtable.com" \
    "Miro|https://miro.com" \
    "Vercel|https://vercel.app" \
    "Supabase|https://supabase.co" \
    "Fireworks.ai|https://fireworks.ai" \
    "RunPod|https://runpod.io" \
    "Portainer|https://portainer.io" \
    "Grafana|https://grafana.com" \
    "HashiCorp|https://vault.hashicorp.com" \
    "Httpbin|https://httpbin.org/get"; do
    app="${pair%%|*}"
    url="${pair##*|}"
    printf "  %-20s → %s ... " "$app" "$url"
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    [ "$code" = "000" ] && echo "timeout" || echo "$code"
  done
  echo "  → These have NO NFW rule. AI classifier will identify them within 5 min."

  echo
  echo "✓ Traffic sent. Wait 30-60s then run: $0 status"
}

# --- STATUS: check recent NFW alert logs ---
status() {
  echo "═══════════════════════════════════════════════════════════"
  echo " RECENT NFW DETECTIONS (last 5 minutes)"
  echo "═══════════════════════════════════════════════════════════"
  echo

  AWS_PROFILE=$PROFILE aws logs start-query \
    --log-group-name "$LOG_GROUP" \
    --start-time $(($(date +%s) - 300)) \
    --end-time $(date +%s) \
    --query-string 'fields @timestamp, event.alert.signature, event.alert.action, event.src_ip, event.dest_ip, event.dest_port, event.tls.sni
      | filter event.alert.signature not like /^$/
      | sort @timestamp desc
      | limit 30' \
    --region "$REGION" --output json > /tmp/nfw_qid.json 2>&1

  QID=$(python3 -c "import json; print(json.load(open('/tmp/nfw_qid.json'))['queryId'])")
  sleep 3

  AWS_PROFILE=$PROFILE aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
if data['status'] != 'Complete':
    print('  Query still running... try again in a few seconds')
    sys.exit(0)
results = data.get('results', [])
if not results:
    print('  No alerts in last 5 minutes. Generate traffic first: $0 detect')
    sys.exit(0)
print(f'  Found {len(results)} detections:')
print()
print(f'  {\"TIME\":<20} {\"ACTION\":<10} {\"APP/SIGNATURE\":<30} {\"SRC_IP\":<16} {\"DST\":<30}')
print(f'  {\"─\"*20} {\"─\"*10} {\"─\"*30} {\"─\"*16} {\"─\"*30}')
for r in results:
    d = {f['field']: f['value'] for f in r}
    ts = d.get('@timestamp','')[:19]
    sig = d.get('event.alert.signature','?')
    act = d.get('event.alert.action','?')
    src = d.get('event.src_ip','?')
    dst = d.get('event.dest_ip','') + ':' + d.get('event.dest_port','')
    sni = d.get('event.tls.sni','')
    icon = '🔴' if act == 'blocked' else '🟡'
    print(f'  {ts} {icon} {act:<8} {sig:<30} {src:<16} {sni or dst}')
"
}

# --- BLOCK: switch app categories from alert to drop ---
block() {
  cat << 'EOF'
═══════════════════════════════════════════════════════════
 BLOCKING APPS — converting alert rules to drop rules
═══════════════════════════════════════════════════════════

To block an app category, change "alert" to "drop" in the Suricata rules.

Examples — add these to terraform/firewall.tf rule_group:

  # Block all P2P/torrent traffic:
  drop http any any -> any any (http.user_agent; content:"BitTorrent"; nocase; msg:"BLOCK:P2P:BitTorrent"; sid:500; rev:1;)
  drop http any any -> any any (http.user_agent; content:"uTorrent"; nocase; msg:"BLOCK:P2P:uTorrent"; sid:501; rev:1;)
  drop http any any -> any any (http.user_agent; content:"qBittorrent"; nocase; msg:"BLOCK:P2P:qBittorrent"; sid:502; rev:1;)
  drop tls any any -> any any (tls.sni; content:"tracker"; nocase; msg:"BLOCK:P2P:Tracker"; sid:503; rev:1;)

  # Block VPN evasion:
  drop tls any any -> any any (tls.sni; content:"torproject.org"; nocase; msg:"BLOCK:Tor"; sid:510; rev:1;)
  drop tls any any -> any any (tls.sni; content:"nordvpn.com"; nocase; msg:"BLOCK:NordVPN"; sid:511; rev:1;)
  drop tls any any -> any any (tls.sni; content:"psiphon"; nocase; msg:"BLOCK:Psiphon"; sid:512; rev:1;)

  # Block specific AI services:
  drop tls any any -> any any (tls.sni; content:"deepseek.com"; nocase; msg:"BLOCK:AI:DeepSeek"; sid:520; rev:1;)

After editing, deploy:
  cd /Users/golovo/TrafInspector/terraform
  export TF_HTTP_USERNAME=session TF_HTTP_PASSWORD="<key>"
  AWS_PROFILE=learning4 terraform apply -target=aws_networkfirewall_rule_group.stateful

Blocked traffic shows as action="blocked" in alerts + triggers SNS notification.
EOF

  echo
  read -p "Auto-add P2P + VPN evasion block rules now? [y/N] " yn
  if [[ "$yn" == "y" || "$yn" == "Y" ]]; then
    add_block_rules
  fi
}

add_block_rules() {
  RULES_FILE="/Users/golovo/TrafInspector/terraform/firewall.tf"

  # Check if block rules already exist
  if grep -q "sid:500" "$RULES_FILE"; then
    echo "  Block rules already present in firewall.tf"
    return
  fi

  # Insert block rules before the closing RULES heredoc
  sed -i '' '/^      RULES$/i\
\        # === ACTIVE BLOCKS (drop = connection killed) ===\
\        drop http any any -> any any (http.user_agent; content:"BitTorrent"; nocase; msg:"BLOCK:P2P:BitTorrent"; sid:500; rev:1;)\
\        drop http any any -> any any (http.user_agent; content:"uTorrent"; nocase; msg:"BLOCK:P2P:uTorrent"; sid:501; rev:1;)\
\        drop http any any -> any any (http.user_agent; content:"qBittorrent"; nocase; msg:"BLOCK:P2P:qBittorrent"; sid:502; rev:1;)\
\        drop http any any -> any any (http.user_agent; content:"Transmission"; nocase; msg:"BLOCK:P2P:Transmission"; sid:503; rev:1;)\
\        drop tls any any -> any any (tls.sni; content:"tracker"; nocase; msg:"BLOCK:P2P:Tracker"; sid:504; rev:1;)\
\        drop tls any any -> any any (tls.sni; content:"torproject.org"; nocase; msg:"BLOCK:Tor"; sid:510; rev:1;)\
\        drop tls any any -> any any (tls.sni; content:"psiphon"; nocase; msg:"BLOCK:Psiphon"; sid:511; rev:1;)\
\        drop tls any any -> any any (tls.sni; content:"lantern"; nocase; msg:"BLOCK:Lantern"; sid:512; rev:1;)
' "$RULES_FILE"

  echo "  ✓ Block rules added to firewall.tf"
  echo "  Deploy with:"
  echo "    cd /Users/golovo/TrafInspector/terraform"
  echo "    AWS_PROFILE=learning4 terraform apply -target=aws_networkfirewall_rule_group.stateful -auto-approve"
}

# --- Main ---
case "${1:-detect}" in
  detect) detect ;;
  status) status ;;
  block)  block ;;
  *)      echo "Usage: $0 [detect|block|status]"; exit 1 ;;
esac

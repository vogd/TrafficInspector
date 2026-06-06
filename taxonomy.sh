#!/bin/bash
# taxonomy.sh — CLI for managing app taxonomy (approve/reject/list pending classifications)
# Usage: ./taxonomy.sh [list|approve|reject|rename]
set -euo pipefail

API="${TAXONOMY_API:-${TAXONOMY_API:-http://localhost}}"

list() {
  echo "═══ PENDING CLASSIFICATIONS ═══"
  curl -s "${API}?action=pending" | python3 -c "
import sys,json
d=json.load(sys.stdin)
pending=d.get('pending',[])
tax=d.get('taxonomy',{})
print(f'  Pending: {len(pending)} | Taxonomy: {len(tax)} apps\n')
if not pending:
    print('  No pending items 🎉')
else:
    print(f'  {\"APP\":<25} {\"CATEGORY\":<18} {\"DEST\":<35} {\"SEEN\":<5} {\"CONFIDENCE\"}')
    print(f'  {\"─\"*25} {\"─\"*18} {\"─\"*35} {\"─\"*5} {\"─\"*10}')
    for p in sorted(pending, key=lambda x: -int(x.get('seen_count',1))):
        print(f'  {p[\"app\"]:<25} {p[\"category\"]:<18} {p[\"dest_key\"]:<35} {p.get(\"seen_count\",1):<5} {p[\"confidence\"]}')
"
}

approve() {
  local app="${1:?Usage: $0 approve <app_name> [category]}"
  local category="${2:-unknown}"
  # Find the dest_key for this app name
  local dest_key=$(curl -s "${API}?action=pending" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for p in d.get('pending',[]):
    if p['app']=='$app':
        print(p['dest_key']); break
")
  if [ -z "$dest_key" ]; then
    echo "  ✗ App '$app' not found in pending"
    exit 1
  fi
  curl -s -X POST "${API}?action=approve" \
    -H "Content-Type: application/json" \
    -d "{\"dest_key\":\"$dest_key\",\"app\":\"$app\",\"category\":\"$category\"}" | python3 -c "import sys,json; print('  ✓', json.load(sys.stdin).get('message','done'))"
}

reject() {
  local app="${1:?Usage: $0 reject <app_name>}"
  # Search pending first, then try by app name across all items
  local dest_key=$(curl -s "${API}?action=pending" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for p in d.get('pending',[]):
    if p['app']=='$app':
        print(p['dest_key']); break
else:
    # Not in pending — search taxonomy for pattern match
    tax=d.get('taxonomy',{})
    if '$app' in tax:
        # App exists in taxonomy — reject all its patterns
        for pat in tax['$app'].get('patterns',[]):
            print(pat+':443'); break
")
  if [ -z "$dest_key" ]; then
    # Try direct reject by treating app name as dest_key search term
    dest_key=$(curl -s "${API}?action=pending" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for p in d.get('pending',[]):
    if '$app' in p.get('app','').lower() or '$app' in p.get('dest_key','').lower():
        print(p['dest_key']); break
")
  fi
  if [ -z "$dest_key" ]; then
    echo "  ✗ App '$app' not found. Trying direct API reject by name..."
    # Last resort: call reject with the app name as dest_key (admin Lambda handles lookup)
    curl -s -X POST "${API}?action=reject" \
      -H "Content-Type: application/json" \
      -d "{\"dest_key\":\"$app\",\"search_by_app\":true}" | python3 -c "import sys,json; print('  ✓', json.load(sys.stdin).get('message','done'))"
    return
  fi
  curl -s -X POST "${API}?action=reject" \
    -H "Content-Type: application/json" \
    -d "{\"dest_key\":\"$dest_key\"}" | python3 -c "import sys,json; print('  ✓', json.load(sys.stdin).get('message','done'))"
}

rename() {
  local old="${1:?Usage: $0 rename <old_name> <new_name> [category]}"
  local new="${2:?Usage: $0 rename <old_name> <new_name> [category]}"
  local category="${3:-unknown}"
  local dest_key=$(curl -s "${API}?action=pending" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for p in d.get('pending',[]):
    if p['app']=='$old':
        print(p['dest_key']); break
")
  if [ -z "$dest_key" ]; then
    echo "  ✗ App '$old' not found in pending"
    exit 1
  fi
  curl -s -X POST "${API}?action=approve" \
    -H "Content-Type: application/json" \
    -d "{\"dest_key\":\"$dest_key\",\"app\":\"$new\",\"category\":\"$category\"}" | python3 -c "import sys,json; print('  ✓', json.load(sys.stdin).get('message','done'))"
}

case "${1:-list}" in
  list) list ;;
  approve) approve "${2:-}" "${3:-}" ;;
  reject) reject "${2:-}" ;;
  rename) rename "${2:-}" "${3:-}" "${4:-}" ;;
  *) echo "Usage: $0 [list|approve <app> [category]|reject <app>|rename <old> <new> [category]]" ;;
esac

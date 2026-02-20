#!/bin/bash
# V1B3 Cron Scanner
# Reads targets.txt, picks the next unscanned target, scans it,
# updates findings.json, pushes to GitHub, and optionally tweets.
#
# Run via crontab:
#   0 */6 * * * /bin/bash /path/to/v1b3/cron_scan.sh >> /path/to/v1b3/cron.log 2>&1

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

TARGETS_FILE="$DIR/targets.txt"
STATE_FILE="$DIR/.scan_state.json"
LOG="$DIR/cron.log"
PYTHON=$(which python3)

echo ""
echo "========================================"
echo "[V1B3 CRON] $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

# Read active targets (skip comments and blanks)
mapfile -t TARGETS < <(grep -v '^#' "$TARGETS_FILE" | grep -v '^[[:space:]]*$' | tr -d '[:space:]')

if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "[V1B3] No targets in targets.txt. Add some to start scanning."
  exit 0
fi

# Load or init state
if [ ! -f "$STATE_FILE" ]; then
  echo '{"last_index": -1, "scan_count": 0}' > "$STATE_FILE"
fi

LAST_INDEX=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d['last_index'])")
SCAN_COUNT=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d['scan_count'])")

# Pick next target (round robin)
NEXT_INDEX=$(( (LAST_INDEX + 1) % ${#TARGETS[@]} ))
TARGET="${TARGETS[$NEXT_INDEX]}"

echo "[V1B3] Scanning target $((NEXT_INDEX + 1))/${#TARGETS[@]}: $TARGET"

# Run scan
$PYTHON "$DIR/agent.py" --scan "$TARGET"

# Update state
NEW_COUNT=$((SCAN_COUNT + 1))
python3 -c "
import json
d = json.load(open('$STATE_FILE'))
d['last_index'] = $NEXT_INDEX
d['scan_count'] = $NEW_COUNT
d['last_scan'] = '$TARGET'
d['last_scan_time'] = '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
json.dump(d, open('$STATE_FILE', 'w'), indent=2)
"

# Push updated findings to GitHub (updates live site)
echo "[V1B3] Pushing findings to GitHub..."
$PYTHON "$DIR/agent.py" --update-site

# If tweeter is set up, post a status update
if [ -f "$DIR/tweet.py" ] && [ -f "$DIR/.twitter_config.json" ]; then
  echo "[V1B3] Tweeting scan update..."
  $PYTHON "$DIR/tweet.py" --scan-complete --target "$TARGET"
fi

echo "[V1B3] Cron run complete. Total scans: $NEW_COUNT"
echo "========================================"

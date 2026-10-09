#!/bin/bash
# SecureProbe Real-World Benchmark
# Tests both well-secured and intentionally vulnerable websites

SERVER_URL="http://localhost:3000"
RESULTS_DIR="/tmp/secureprobe-benchmark"
mkdir -p "$RESULTS_DIR"

SECURE_SITES=(
    "https://google.com"
    "https://github.com"
    "https://stackoverflow.com"
)

VULNERABLE_SITES=(
    "http://testphp.vulnweb.com"
    "https://juice-shop.herokuapp.com"
)

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  SecureProbe v2.1 — Real-World Benchmark"
echo "══════════════════════════════════════════════════════════════════"
echo ""
echo "  Testing on:"
for site in "${SECURE_SITES[@]}"; do
    echo "    ✓ SECURE:   $site"
done
for site in "${VULNERABLE_SITES[@]}"; do
    echo "    ⚠ VULNERABLE: $site"
done
echo ""

# Start fresh — clean old scans
echo "  [setup] Cleaning old scan data..."
curl -s "$SERVER_URL/api/scans?limit=100" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d.get('scans',[]):
    print(s['id'])
" 2>/dev/null | while read id; do
    curl -s -X DELETE "$SERVER_URL/api/scans/$id" > /dev/null
done

scan_site() {
    local target="$1"
    local label="$2"

    echo ""
    echo "  ────────────────────────────────────────────────────────────────"
    echo "  Scanning: $target"
    echo "  ────────────────────────────────────────────────────────────────"

    # Start scan
    local resp=$(curl -s -X POST "$SERVER_URL/api/scans" \
        -H "Content-Type: application/json" \
        -d "{\"url\":\"$target\",\"options\":{}}")
    local scan_id=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

    if [ -z "$scan_id" ]; then
        echo "  ✗ Failed to start scan"
        return
    fi

    echo "  Scan ID: ${scan_id:0:8}..."

    # Poll for completion
    while true; do
        sleep 3
        local status=$(curl -s "$SERVER_URL/api/scans/$scan_id/status")
        local state=$(echo "$status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        local progress=$(echo "$status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('progress',0))" 2>/dev/null)
        local stage=$(echo "$status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('current_stage',''))" 2>/dev/null)

        if [ "$state" = "completed" ] || [ "$state" = "failed" ]; then
            break
        fi
        printf "\r  Progress: %s%% — %s" "$progress" "$stage"
    done
    echo ""

    # Get results
    local detail=$(curl -s "$SERVER_URL/api/scans/$scan_id")
    local scan=$(echo "$detail" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('scan',{})))" 2>/dev/null)
    local vulns=$(echo "$detail" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('vulnerabilities',[])))" 2>/dev/null)

    local score=$(echo "$scan" | python3 -c "import json,sys; print(json.load(sys.stdin).get('risk_score',0))" 2>/dev/null)
    local level=$(echo "$scan" | python3 -c "import json,sys; print(json.load(sys.stdin).get('risk_level','info'))" 2>/dev/null)
    local count=$(echo "$scan" | python3 -c "import json,sys; print(json.load(sys.stdin).get('vulnerability_count',0))" 2>/dev/null)

    echo "  ════════════════════════════════════════════════════"
    echo "   RISK:  $score/100 ($(echo $level | tr '[:lower:]' '[:upper:]'))"
    echo "   Findings: $count total"
    echo "  ════════════════════════════════════════════════════"

    if [ "$count" -gt 0 ]; then
        echo "$vulns" | python3 -c "
import json,sys
vulns = json.load(sys.stdin)
sev_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
vulns.sort(key=lambda v: sev_order.get(v.get('severity','info'),5))
for v in vulns:
    sev = v.get('severity','info').upper().ljust(8)
    typ = v.get('type','?').ljust(25)
    title = v.get('title','?')[:55]
    print(f'    [{sev}] {typ} {title}')
" 2>/dev/null
    else
        echo "    ✓ No vulnerabilities found"
    fi

    # Also get the markdown report
    curl -s "$SERVER_URL/api/scans/$scan_id/report" > "$RESULTS_DIR/report-${label}.md"
    echo "    Report saved to: $RESULTS_DIR/report-${label}.md"
    echo ""
}

# Scan each site
for site in "${SECURE_SITES[@]}"; do
    label=$(echo "$site" | sed 's|https\?://||' | sed 's|/||g')
    scan_site "$site" "$label"
done

for site in "${VULNERABLE_SITES[@]}"; do
    label=$(echo "$site" | sed 's|https\?://||' | sed 's|/||g')
    scan_site "$site" "$label"
done

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  Benchmark Complete!"
echo "  Reports saved to: $RESULTS_DIR/"
echo "══════════════════════════════════════════════════════════════════"
echo ""
echo "  Summary Table:"
echo ""
echo "  ┌─────────────────────────────┬───────┬──────────┬──────────┐"
echo "  │ Site                        │ Score │ Level    │ Findings │"
echo "  ├─────────────────────────────┼───────┼──────────┼──────────┤"

for site in "${SECURE_SITES[@]}"; do
    label=$(echo "$site" | sed 's|https\?://||' | sed 's|/||g')
    if [ -f "$RESULTS_DIR/report-${label}.md" ]; then
        sc=$(grep "Risk Score" "$RESULTS_DIR/report-${label}.md" | grep -oP '\d+')
        lv=$(grep "Risk Level" "$RESULTS_DIR/report-${label}.md" | grep -oP '\b\w+\b' | tail -1)
        ct=$(grep "Total Vulnerabilities" "$RESULTS_DIR/report-${label}.md" | grep -oP '\d+')
    else
        sc="?"; lv="?"; ct="?"
    fi
    printf "  │ %-27s │ %5s │ %-8s │ %8s │\n" "$site" "$sc" "$lv" "$ct"
done

for site in "${VULNERABLE_SITES[@]}"; do
    label=$(echo "$site" | sed 's|https\?://||' | sed 's|/||g')
    if [ -f "$RESULTS_DIR/report-${label}.md" ]; then
        sc=$(grep "Risk Score" "$RESULTS_DIR/report-${label}.md" | grep -oP '\d+')
        lv=$(grep "Risk Level" "$RESULTS_DIR/report-${label}.md" | grep -oP '\b\w+\b' | tail -1)
        ct=$(grep "Total Vulnerabilities" "$RESULTS_DIR/report-${label}.md" | grep -oP '\d+')
    else
        sc="?"; lv="?"; ct="?"
    fi
    printf "  │ %-27s │ %5s │ %-8s │ %8s │\n" "$site" "$lv" "$ct"
done

echo "  └─────────────────────────────┴───────┴──────────┴──────────┘"
echo ""

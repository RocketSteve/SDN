#!/bin/bash
# Run Suricata with ONLY custom rules (not the full 46k ruleset)
# This avoids Hyperscan crashes and focuses on our specific attack detection

LOG_DIR="/home/mininet/suricata_logs"

if [ -z "$1" ]; then
    echo "Usage: sudo $0 <interface>"
    echo "Example: sudo $0 s1-eth1"
    exit 1
fi

INTERFACE=$1

echo "=== Starting Suricata IDS (Custom Rules Only) ==="
echo "Interface: $INTERFACE"
echo "Log directory: $LOG_DIR"
echo ""

# Create log directory
mkdir -p $LOG_DIR

# Clear old logs
rm -f $LOG_DIR/*.log $LOG_DIR/*.json

# Stop any existing Suricata instance
sudo killall suricata 2>/dev/null
sleep 1

echo "Starting Suricata with custom rules only..."
echo ""

# Run Suricata with:
# -S: Specify rules file (only our custom rules)
# -i: Interface to monitor
# -l: Log directory
# -v: Verbose
# --disable-detection: Disable default rules, use only -S rules

sudo suricata \
    -S /media/sf_shared/custom.rules \
    -i $INTERFACE \
    -l $LOG_DIR \
    --set default-log-dir=$LOG_DIR \
    -v

echo ""
echo "=== Suricata stopped ==="
echo "Logs saved to: $LOG_DIR"
echo ""
echo "To view alerts:"
echo "  cat $LOG_DIR/fast.log"
echo ""

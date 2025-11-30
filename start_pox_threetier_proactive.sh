#!/bin/bash
# Start POX controller for three-tier proactive SDN network

echo "========================================"
echo "Starting POX - Three-Tier Proactive SDN"
echo "========================================"
echo ""
echo "Configuration:"
echo "  Topology: 3-tier (Web, App, Database)"
echo "  Switches: 3 (s1, s2, s3)"
echo "  Mode: Proactive (flows pre-installed)"
echo "  Idle Timeout: 300s (5 minutes)"
echo "  Hard Timeout: 3600s (1 hour)"
echo "  Expected overhead: Minimal"
echo ""
echo "Controller will listen on port 6633"
echo "Waiting for 3 switches to connect..."
echo "Press Ctrl+C to stop"
echo ""
echo "========================================"
echo ""

# Use explicit path (works with sudo)
POX_DIR="/home/mininet/pox"

if [ ! -d "$POX_DIR" ]; then
    echo "ERROR: POX not found at $POX_DIR"
    exit 1
fi

cd "$POX_DIR"

# Copy controller to POX forwarding directory
cp /media/sf_shared/proactive_l2_multitier.py "$POX_DIR/pox/forwarding/"

# Start POX with proactive multi-tier controller
./pox.py log.level --DEBUG forwarding.proactive_l2_multitier

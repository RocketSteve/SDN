#!/bin/bash
################################################################################
# Automated Test Runner for IDS Comparison Study
#
# Compares Traditional 3-Tier vs Proactive SDN 3-Tier networks
# Collects: Time-to-detection, alert counts, detection rates
# Uses: Controlled attack generator (ground truth) + Suricata (custom rules only)
#
# Usage: sudo ./auto_test_runner.sh
################################################################################

set -e  # Exit on error

# Handle Ctrl+C gracefully
trap 'echo ""; echo "Interrupted! Cleaning up..."; cleanup_all; exit 130' INT

# ============================================
# CONFIGURATION
# ============================================
ITERATIONS_TRADITIONAL=0
ITERATIONS_PROACTIVE_SDN=10
RESULTS_BASE="/home/mininet/test_results"
SHARED_DIR="/media/sf_shared"
SURICATA_LOGS="/home/mininet/suricata_logs"
LOG_FILE="/tmp/auto_test_runner.log"
LOG_DIR="/tmp/auto_test_logs"

# Component-specific log files
MININET_LOG="$LOG_DIR/mininet.log"
CONTROLLER_LOG="$LOG_DIR/controller.log"
SURICATA_LOG="$LOG_DIR/suricata.log"
ATTACK_LOG="$LOG_DIR/attack.log"

# Test configuration mapping
declare -A TEST_CONFIGS
TEST_CONFIGS[traditional_topology]="three_tier_traditional_simple.py"
TEST_CONFIGS[traditional_interface]="s3-eth3"
TEST_CONFIGS[traditional_controller]="none"

TEST_CONFIGS[proactive_sdn_topology]="three_tier_sdn.py"
TEST_CONFIGS[proactive_sdn_interface]="s3-eth3"
TEST_CONFIGS[proactive_sdn_controller]="start_pox_threetier_proactive.sh"

# Initialize log files with proper permissions
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"

rm -f "$LOG_FILE"
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

# Create component log files
touch "$MININET_LOG" "$CONTROLLER_LOG" "$SURICATA_LOG" "$ATTACK_LOG"
chmod 666 "$MININET_LOG" "$CONTROLLER_LOG" "$SURICATA_LOG" "$ATTACK_LOG"

# ============================================
# HELPER FUNCTIONS
# ============================================

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_section() {
    local msg="$1"
    log ""
    log "========================================"
    log "$msg"
    log "========================================"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: This script must be run as root (use sudo)"
        exit 1
    fi

    # Get the real user who ran sudo
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_UID="${SUDO_UID:-$UID}"
    REAL_GID="${SUDO_GID:-$GID}"

    log "Running as: root (via sudo from user: $REAL_USER)"
}

cleanup_all() {
    log "Cleaning up all processes..."

    # Kill Mininet
    mn -c >/dev/null 2>&1 || true

    # Kill tmux sessions (as regular user if REAL_USER is set)
    if [ -n "$REAL_USER" ]; then
        sudo -u "$REAL_USER" tmux kill-session -t mininet_test 2>/dev/null || true
        sudo -u "$REAL_USER" tmux kill-session -t controller_test 2>/dev/null || true
        sudo -u "$REAL_USER" tmux kill-session -t suricata_test 2>/dev/null || true
    fi
    # Also try as root (in case some were started as root)
    tmux kill-session -t mininet_test 2>/dev/null || true
    tmux kill-session -t controller_test 2>/dev/null || true
    tmux kill-session -t suricata_test 2>/dev/null || true

    # Kill POX
    pkill -9 -f pox.py 2>/dev/null || true

    # Kill Suricata
    pkill -9 -f suricata 2>/dev/null || true

    # Kill any tail processes following attack output
    pkill -f "tail -f /tmp/attack_output.txt" 2>/dev/null || true

    # Clear Suricata logs
    rm -f "$SURICATA_LOGS"/*.log "$SURICATA_LOGS"/*.json 2>/dev/null || true

    # Clear temp attack stats
    rm -f /tmp/controlled_attack_stats_*.json 2>/dev/null || true
    rm -f /tmp/last_attack_stats.txt 2>/dev/null || true
    rm -f /tmp/attack_output.txt 2>/dev/null || true

    sleep 3
    log "  Cleanup complete"
}

start_controller() {
    local test_type=$1
    local controller_script="${TEST_CONFIGS[${test_type}_controller]}"

    if [ "$controller_script" == "none" ]; then
        log "No controller needed for $test_type"
        return 0
    fi

    log "Starting POX controller: $controller_script"
    echo "=== Controller startup at $(date) ===" >> "$CONTROLLER_LOG"

    # Start controller in tmux session with logging
    tmux new-session -d -s controller_test \
        "cd $SHARED_DIR && ./$controller_script 2>&1 | tee -a $CONTROLLER_LOG"

    sleep 3
    log "  Controller started (log: $CONTROLLER_LOG)"
}

wait_for_controller() {
    log "Waiting for controller to be ready..."
    local timeout=30
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        # Check if controller is listening on port 6633
        if netstat -an 2>/dev/null | grep -q "6633.*LISTEN"; then
            log "  Controller ready! (port 6633 listening)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log "  ERROR: Controller startup timeout!"
    return 1
}

start_network() {
    local test_type=$1
    local topology="${TEST_CONFIGS[${test_type}_topology]}"

    log "Starting Mininet network: $topology"
    echo "=== Mininet startup at $(date) ===" >> "$MININET_LOG"
    echo "Test type: $test_type" >> "$MININET_LOG"
    echo "Topology: $topology" >> "$MININET_LOG"

    # Enable tmux logging (run as regular user)
    sudo -u "$REAL_USER" tmux set-option -g history-limit 50000 2>/dev/null || true

    # Start network in tmux session as regular user
    sudo -u "$REAL_USER" tmux new-session -d -s mininet_test "sudo python3 $SHARED_DIR/$topology"

    sleep 8  # Give network time to start
    log "  Network started"

    # Verify session exists
    if ! sudo -u "$REAL_USER" tmux has-session -t mininet_test 2>/dev/null; then
        log "  ERROR: Tmux session died immediately!"
        log "  This usually means the Python script failed to start"
        return 1
    fi
}

wait_for_network() {
    local test_type=$1
    log "Waiting for network to be ready..."
    local timeout=45
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        # Check if Mininet CLI prompt is ready
        if sudo -u "$REAL_USER" tmux capture-pane -t mininet_test -p 2>/dev/null | grep -q "mininet>"; then
            log "  Mininet CLI ready!"

            # Check if interfaces exist
            if ip link show 2>/dev/null | grep -q "s3-eth3"; then
                log "  Network interfaces created"

                # Wait a bit for network to stabilize
                sleep 2

                # For SDN networks, establish connectivity first with pingall
                if [[ "$test_type" == *"sdn"* ]]; then
                    log "  SDN network: Establishing connectivity with pingall..."
                    sudo -u "$REAL_USER" tmux send-keys -t mininet_test "pingall" C-m
                    sleep 8
                    sudo -u "$REAL_USER" tmux send-keys -t mininet_test "" C-m
                    sleep 2
                    log "  SDN network: Connectivity established"
                fi

                # Start HTTP server on victim host (use port 8080 - no privileges needed)
                log "  Starting HTTP server on victim..."
                sudo -u "$REAL_USER" tmux send-keys -t mininet_test "victim python3 -m http.server 8080 >/dev/null 2>&1 &" C-m
                sleep 3

                # Send Enter to clear the command line
                sudo -u "$REAL_USER" tmux send-keys -t mininet_test "" C-m
                sleep 1

                # Verify HTTP server process is running
                log "  Verifying HTTP server is responding..."

                # Give time for server to start
                sleep 2

                # Check if python http.server process exists
                if ps aux | grep -q "[p]ython3 -m http.server 8080"; then
                    log "  HTTP server verified! (process running on port 8080)"
                    log "  Network ready!"
                    return 0
                else
                    log "  ERROR: HTTP server process not found"
                    log "  Process check:"
                    ps aux | grep "http.server" | grep -v grep >> "$LOG_FILE"
                    return 1
                fi
            fi
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log "  ERROR: Network startup timeout!"
    log "  Last tmux output:"
    sudo -u "$REAL_USER" tmux capture-pane -t mininet_test -p | tail -20 >> "$LOG_FILE"
    return 1
}

start_suricata() {
    local test_type=$1
    local interface="${TEST_CONFIGS[${test_type}_interface]}"

    log "Starting Suricata on interface $interface (CUSTOM RULES ONLY)..."
    echo "=== Suricata startup at $(date) ===" >> "$SURICATA_LOG"
    echo "Interface: $interface" >> "$SURICATA_LOG"

    # Clear old logs
    rm -f "$SURICATA_LOGS"/*.log "$SURICATA_LOGS"/*.json 2>/dev/null || true

    # Ensure log directory exists
    mkdir -p "$SURICATA_LOGS"

    # Start Suricata with custom rules only (with logging)
    tmux new-session -d -s suricata_test \
        "$SHARED_DIR/run_suricata_custom_only.sh $interface 2>&1 | tee -a $SURICATA_LOG"

    sleep 3
    log "  Suricata started (log: $SURICATA_LOG)"
}

wait_for_suricata() {
    log "Waiting for Suricata to be ready..."
    local timeout=30
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        # Check if Suricata is running and logs are created
        if pgrep -f suricata > /dev/null && \
           [ -f "$SURICATA_LOGS/fast.log" ]; then
            log "  Suricata ready and logging!"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log "  ERROR: Suricata startup timeout!"
    return 1
}

run_attacks() {
    log_section "LAUNCHING CONTROLLED ATTACK SUITE"
    echo "=== Attack execution at $(date) ===" >> "$ATTACK_LOG"

    # Clear old stats files
    rm -f /tmp/controlled_attack_stats_*.json
    rm -f /tmp/last_attack_stats.txt
    rm -f /tmp/attack_output.txt

    # Create empty attack output file
    touch /tmp/attack_output.txt
    chmod 666 /tmp/attack_output.txt

    # Get timestamp before attack
    local before_count=$(ls -1 /tmp/controlled_attack_stats_*.json 2>/dev/null | wc -l)

    # Launch attacks from web1 with output redirection
    log "Executing attacks from web1 (target: 10.0.0.100)..."
    log "  Attack output will be logged to: /tmp/attack_output.txt"

    # Send command to Mininet - run attack WITHOUT background/redirection first to see errors
    # This will show output directly in the tmux session
    log "  Sending attack command to Mininet CLI..."
    sudo -u "$REAL_USER" tmux send-keys -t mininet_test "web1 python3 $SHARED_DIR/controlled_attack_generator.py 10.0.0.100" C-m

    # Wait a moment for command to be accepted
    sleep 3

    # Verify command was sent by checking tmux - capture MORE output to see errors
    log "  Command sent, checking Mininet response..."
    local mininet_response=$(sudo -u "$REAL_USER" tmux capture-pane -t mininet_test -p | tail -20)

    # Log the response
    log "  Mininet CLI output (last 20 lines):"
    while IFS= read -r line; do
        log "    $line"
    done <<< "$mininet_response"

    # Check for error messages
    if echo "$mininet_response" | grep -qi "error\|traceback\|exception\|failed"; then
        log "  [ERROR] Detected error in Mininet response!"
    fi

    # Check if the command actually executed
    if echo "$mininet_response" | grep -q "controlled_attack_generator.py"; then
        log "  [OK] Attack command appears in output"
    else
        log "  [WARNING] Attack command NOT visible in output"
    fi

    # Start tailing the output in background
    tail -f /tmp/attack_output.txt >> "$ATTACK_LOG" 2>/dev/null &
    local tail_pid=$!

    # Wait for attack completion by monitoring JSON output
    local timeout=600  # 10 minutes max
    local elapsed=0
    local stats_file=""

    log "Waiting for attack suite to complete..."
    log "  (Checking tmux session for completion message)"

    while [ $elapsed -lt $timeout ]; do
        # Check tmux session for completion message
        local tmux_output=$(sudo -u "$REAL_USER" tmux capture-pane -t mininet_test -p 2>/dev/null)

        if echo "$tmux_output" | grep -q "ATTACK SUITE COMPLETED"; then
            log "  Attack suite completed! (detected in tmux output)"

            # Look for stats file
            stats_file=$(ls -t /tmp/controlled_attack_stats_*.json 2>/dev/null | head -1)

            if [ -n "$stats_file" ] && [ -f "$stats_file" ]; then
                log "  Ground truth saved: $stats_file"
                echo "$stats_file" > /tmp/last_attack_stats.txt

                # Show summary
                local total_packets=$(jq -r '.totals.total_packets_sent // 0' "$stats_file" 2>/dev/null || echo "unknown")
                local duration=$(jq -r '.totals.total_duration // 0' "$stats_file" 2>/dev/null || echo "unknown")
                log "  Total packets sent: $total_packets"
                log "  Total duration: ${duration}s"
            else
                log "  Warning: Stats file not found, but attack completed"
            fi

            # Wait a few more seconds for all alerts to be processed
            log "  Waiting for IDS to process all packets..."
            sleep 10

            # Stop tailing attack output
            kill $tail_pid 2>/dev/null || true

            return 0
        fi

        # Also check if stats file appeared (fallback)
        local after_count=$(ls -1 /tmp/controlled_attack_stats_*.json 2>/dev/null | wc -l)
        if [ $after_count -gt $before_count ]; then
            stats_file=$(ls -t /tmp/controlled_attack_stats_*.json 2>/dev/null | head -1)
            if grep -q "end_time" "$stats_file" 2>/dev/null; then
                log "  Attack suite completed! (stats file detected)"
                log "  Ground truth saved: $stats_file"
                echo "$stats_file" > /tmp/last_attack_stats.txt

                local total_packets=$(jq -r '.totals.total_packets_sent // 0' "$stats_file")
                local duration=$(jq -r '.totals.total_duration // 0' "$stats_file")
                log "  Total packets sent: $total_packets"
                log "  Total duration: ${duration}s"

                log "  Waiting for IDS to process all packets..."
                sleep 10

                kill $tail_pid 2>/dev/null || true
                return 0
            fi
        fi

        sleep 5
        elapsed=$((elapsed + 5))

        # Progress update every 30 seconds with debugging info
        if [ $((elapsed % 30)) -eq 0 ]; then
            log "  Still running... ${elapsed}s elapsed"

            # Check attack output file size
            if [ -f /tmp/attack_output.txt ]; then
                local file_size=$(stat -f%z /tmp/attack_output.txt 2>/dev/null || stat -c%s /tmp/attack_output.txt 2>/dev/null || echo "0")
                log "  Attack output file size: $file_size bytes"

                local last_line=$(tail -1 /tmp/attack_output.txt 2>/dev/null)
                if [ -n "$last_line" ]; then
                    log "  Last output: $last_line"
                else
                    log "  Attack output file is empty - checking if attack started..."
                    # Show what's happening in Mininet
                    sudo -u "$REAL_USER" tmux capture-pane -t mininet_test -p | tail -5 >> "$LOG_FILE"
                fi
            else
                log "  Attack output file doesn't exist yet"
            fi

            # List current stats files
            local stats_count=$(ls -1 /tmp/controlled_attack_stats_*.json 2>/dev/null | wc -l)
            log "  Stats files found: $stats_count (before: $before_count)"

            # Check if attack process is running
            if pgrep -f "controlled_attack_generator.py 10.0.0.100" > /dev/null; then
                log "  Attack process is running (PID: $(pgrep -f 'controlled_attack_generator.py 10.0.0.100'))"
            else
                log "  WARNING: Attack process not found!"
            fi
        fi
    done

    # Stop tailing attack output
    kill $tail_pid 2>/dev/null || true

    log "  ERROR: Attack execution timeout!"
    log "  Check $ATTACK_LOG or /tmp/attack_output.txt for details"
    return 1
}

collect_metrics() {
    local test_type=$1
    local iteration=$2

    log_section "COLLECTING METRICS"

    # Create results directory
    local results_dir="$RESULTS_BASE/${test_type}/iteration_${iteration}"
    mkdir -p "$results_dir"

    log "Results directory: $results_dir"

    # Get ground truth file
    if [ ! -f /tmp/last_attack_stats.txt ]; then
        log "  ERROR: No ground truth file found!"
        return 1
    fi

    local ground_truth=$(cat /tmp/last_attack_stats.txt)

    if [ ! -f "$ground_truth" ]; then
        log "  ERROR: Ground truth file doesn't exist: $ground_truth"
        return 1
    fi

    # Copy raw logs
    log "Copying raw logs..."
    cp "$SURICATA_LOGS/fast.log" "$results_dir/suricata_fast.log" 2>/dev/null || log "  Warning: fast.log not found"
    cp "$SURICATA_LOGS/eve.json" "$results_dir/suricata_eve.json" 2>/dev/null || log "  Warning: eve.json not found"
    cp "$SURICATA_LOGS/stats.log" "$results_dir/suricata_stats.log" 2>/dev/null || log "  Warning: stats.log not found"
    cp "$ground_truth" "$results_dir/attack_ground_truth.json"

    # Count total alerts for quick reference
    local alert_count=$(wc -l < "$results_dir/suricata_fast.log" 2>/dev/null || echo "0")
    echo "$alert_count" > "$results_dir/alert_count.txt"
    log "  Total alerts detected: $alert_count"

    # Run metrics analysis
    log "Analyzing detection metrics..."
    if python3 "$SHARED_DIR/collect_detection_metrics.py" \
        "$ground_truth" \
        "$results_dir/suricata_eve.json" \
        "$results_dir/detection_metrics.json" \
        "$test_type" \
        "$iteration"; then
        log "  Metrics analysis complete!"
    else
        log "  ERROR: Metrics analysis failed!"
        return 1
    fi

    # Create summary file
    cat > "$results_dir/summary.txt" << EOF
========================================
Test Iteration Summary
========================================

Test Type: $test_type
Iteration: $iteration
Date: $(date)

Results:
--------
Total Alerts: $alert_count

See detection_metrics.json for detailed analysis including:
- Time to first detection per attack type
- Alert counts per attack type
- Detection rates vs ground truth

Raw logs:
- suricata_fast.log: Simple alert format
- suricata_eve.json: Detailed JSON events
- attack_ground_truth.json: Exact packets sent

EOF

    log "  Summary saved"
    log "Metrics collection complete!"
}

stop_all() {
    log "Stopping all processes..."

    # Exit Mininet gracefully
    tmux send-keys -t mininet_test "exit" Enter 2>/dev/null || true
    sleep 2

    # Force cleanup
    cleanup_all

    log "  All processes stopped"
}

run_single_test() {
    local test_type=$1
    local iteration=$2

    log_section "TEST: $test_type - ITERATION $iteration"

    # 1. Cleanup
    cleanup_all

    # 2. Start controller if needed
    local controller_script="${TEST_CONFIGS[${test_type}_controller]}"
    if [ "$controller_script" != "none" ]; then
        start_controller "$test_type"
        wait_for_controller || return 1
    fi

    # 3. Start network
    start_network "$test_type"
    wait_for_network "$test_type" || return 1

    # 4. Start Suricata
    start_suricata "$test_type"
    wait_for_suricata || return 1

    # 5. Run attacks
    run_attacks || return 1

    # 6. Collect metrics
    collect_metrics "$test_type" "$iteration" || return 1

    # 7. Stop everything
    stop_all

    # 8. Cooldown
    log "Cooldown period (10s)..."
    sleep 10

    log_section "TEST COMPLETE: $test_type - ITERATION $iteration"
}

generate_comparison_report() {
    log_section "GENERATING FINAL COMPARISON REPORT"

    local report_file="$RESULTS_BASE/FINAL_DETECTION_COMPARISON.txt"

    # Create header
    cat > "$report_file" << EOF
========================================
IDS DETECTION EFFECTIVENESS COMPARISON
========================================
Generated: $(date)

Study: Traditional 3-Tier vs Proactive SDN 3-Tier
IDS: Suricata (custom rules only)
Attack Generator: Controlled (deterministic packet counts)

========================================
TIME-TO-DETECTION COMPARISON
========================================

EOF

    log "Aggregating results from all iterations..."

    # Process each test type
    for test_type in traditional proactive_sdn; do
        echo "" >> "$report_file"
        echo "${test_type^^} NETWORK:" >> "$report_file"
        echo "$(printf '=%.0s' {1..50})" >> "$report_file"
        echo "" >> "$report_file"

        # Process each iteration
        for iter_dir in "$RESULTS_BASE/${test_type}"/iteration_*; do
            if [ ! -d "$iter_dir" ]; then
                continue
            fi

            local iter_num=$(basename "$iter_dir" | sed 's/iteration_//')
            echo "Iteration $iter_num:" >> "$report_file"

            if [ -f "$iter_dir/detection_metrics.json" ]; then
                # Extract metrics using jq
                jq -r '.attacks | to_entries[] |
                    if .value.detected then
                        "  \(.value.attack_type): \(.value.time_to_detect_seconds)s → \(.value.total_alerts) alerts (\(.value.detection_rate_percent | tonumber | floor)% detection rate)"
                    else
                        "  \(.value.attack_type): NOT DETECTED (\(.value.packets_sent) packets sent)"
                    end' \
                    "$iter_dir/detection_metrics.json" >> "$report_file" 2>/dev/null || \
                    echo "  ERROR: Could not parse metrics" >> "$report_file"

                # Add summary
                local total_alerts=$(jq -r '.summary.total_alerts // 0' "$iter_dir/detection_metrics.json" 2>/dev/null)
                echo "  → Total alerts: $total_alerts" >> "$report_file"
            else
                echo "  No metrics file found" >> "$report_file"
            fi

            echo "" >> "$report_file"
        done
    done

    # Add statistical summary if we have data
    cat >> "$report_file" << EOF

========================================
STATISTICAL SUMMARY
========================================

EOF

    for test_type in traditional proactive_sdn; do
        local iterations_dir="$RESULTS_BASE/$test_type"

        if [ ! -d "$iterations_dir" ]; then
            continue
        fi

        echo "${test_type^^}:" >> "$report_file"

        # Collect alert counts
        local counts=()
        for iter_dir in "$iterations_dir"/iteration_*; do
            if [ -f "$iter_dir/alert_count.txt" ]; then
                counts+=($(cat "$iter_dir/alert_count.txt"))
            fi
        done

        if [ ${#counts[@]} -gt 0 ]; then
            # Calculate statistics
            local sum=0
            for count in "${counts[@]}"; do
                sum=$((sum + count))
            done
            local mean=$((sum / ${#counts[@]}))

            local min=${counts[0]}
            local max=${counts[0]}
            for count in "${counts[@]}"; do
                if [ $count -lt $min ]; then min=$count; fi
                if [ $count -gt $max ]; then max=$count; fi
            done

            echo "  Iterations: ${#counts[@]}" >> "$report_file"
            echo "  Mean alerts: $mean" >> "$report_file"
            echo "  Range: $min - $max" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    log "Report generated: $report_file"

    # Display report
    cat "$report_file"
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    log_section "AUTOMATED IDS TESTING SUITE STARTING"

    # Verify we're root
    check_root

    # Initial cleanup
    cleanup_all

    # Create results base directory
    mkdir -p "$RESULTS_BASE"

    log "Configuration:"
    log "  Traditional iterations: $ITERATIONS_TRADITIONAL"
    log "  Proactive SDN iterations: $ITERATIONS_PROACTIVE_SDN"
    log "  Results directory: $RESULTS_BASE"
    log "  Total tests: $((ITERATIONS_TRADITIONAL + ITERATIONS_PROACTIVE_SDN))"
    log ""
    log "Component logs:"
    log "  Main log:       $LOG_FILE"
    log "  Mininet log:    $MININET_LOG"
    log "  Controller log: $CONTROLLER_LOG"
    log "  Suricata log:   $SURICATA_LOG"
    log "  Attack log:     $ATTACK_LOG"

    # Track progress
    local total_tests=$((ITERATIONS_TRADITIONAL + ITERATIONS_PROACTIVE_SDN))
    local completed=0
    local failed=0

    # Run traditional network tests
    for iteration in $(seq 1 $ITERATIONS_TRADITIONAL); do
        if run_single_test "traditional" "$iteration"; then
            completed=$((completed + 1))
            log "[OK] Progress: $completed / $total_tests tests completed"
        else
            failed=$((failed + 1))
            log "[FAIL] Test failed: traditional iteration $iteration"
            log "Continuing with next test..."
        fi
    done

    # Run proactive SDN tests
    for iteration in $(seq 1 $ITERATIONS_PROACTIVE_SDN); do
        if run_single_test "proactive_sdn" "$iteration"; then
            completed=$((completed + 1))
            log "[OK] Progress: $completed / $total_tests tests completed"
        else
            failed=$((failed + 1))
            log "[FAIL] Test failed: proactive_sdn iteration $iteration"
            log "Continuing with next test..."
        fi
    done

    # Final cleanup
    cleanup_all

    # Generate comparison report
    generate_comparison_report

    # Summary
    log_section "TESTING SUITE COMPLETE"
    log "Total tests: $total_tests"
    log "Completed: $completed"
    log "Failed: $failed"
    log "Success rate: $((completed * 100 / total_tests))%"
    log ""
    log "View results in: $RESULTS_BASE"
    log "View comparison: $RESULTS_BASE/FINAL_DETECTION_COMPARISON.txt"
    log "View log: $LOG_FILE"
}

# Run main function
main "$@"

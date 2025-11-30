#!/usr/bin/env python3
"""
Detection Metrics Collector for IDS Comparison Study

Analyzes Suricata logs against attack ground truth to calculate:
- Time to first detection for each attack type
- Total alerts per attack type
- Detection rate (alerts vs packets sent)

Usage:
    python3 collect_detection_metrics.py <ground_truth.json> <eve.json> \
        <output.json> <test_type> <iteration>

Author: Network Security Research Team
"""

import json
import re
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path


class DetectionMetricsCollector:
    """Analyzes IDS detection effectiveness against ground truth"""

    # Mapping of Suricata rule SIDs to attack types
    SID_TO_ATTACK = {
        '1000001': 'HTTP Flood',
        '1000002': 'Port Scan',
        '1000003': 'ICMP Flood',
        '1000004': 'SYN Flood',
        '1000005': 'Suspicious User-Agent',
        '1000006': 'Rapid Connections'
    }

    def __init__(self, ground_truth_file, eve_json_file):
        """Initialize collector with input files"""
        self.ground_truth_file = Path(ground_truth_file)
        self.eve_json_file = Path(eve_json_file)

        # Verify files exist
        if not self.ground_truth_file.exists():
            raise FileNotFoundError(f"Ground truth file not found: {ground_truth_file}")

        if not self.eve_json_file.exists():
            raise FileNotFoundError(f"Suricata eve.json not found: {eve_json_file}")

        # Data storage
        self.ground_truth = None
        self.attack_start_time = None
        self.first_detections = {}
        self.alert_counts = defaultdict(int)

    def parse_ground_truth(self):
        """Parse attack generator output for ground truth data"""
        print("Parsing ground truth data...")

        with open(self.ground_truth_file, 'r') as f:
            data = json.load(f)

        ground_truth = {}

        # Extract attack information
        for attack_name, attack_data in data['attacks'].items():
            # Get packet count (either packets_sent or requests_sent)
            packets_sent = attack_data.get('packets_sent',
                                          attack_data.get('requests_sent', 0))

            ground_truth[attack_name] = {
                'attack_type': attack_data['attack_type'],
                'packets_sent': packets_sent,
                'duration': attack_data.get('duration', 0),
                'target_rate': attack_data.get('target_rate',
                                              attack_data.get('rate', 0)),
                'actual_rate': attack_data.get('actual_rate',
                                              attack_data.get('rate', 0))
            }

            print(f"  {attack_data['attack_type']}: {packets_sent:,} packets")

        # Get overall attack start time
        self.attack_start_time = datetime.fromtimestamp(data['start_time'])
        print(f"  Attack start time: {self.attack_start_time}")

        self.ground_truth = ground_truth
        return ground_truth

    def parse_suricata_detections(self):
        """Parse Suricata eve.json for detection events"""
        print("\nAnalyzing Suricata detections...")

        first_detections = {}
        alert_counts = defaultdict(int)
        total_events = 0
        alert_events = 0

        try:
            with open(self.eve_json_file, 'r') as f:
                for line in f:
                    total_events += 1

                    try:
                        event = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue

                    # Only process alert events
                    if event.get('event_type') != 'alert':
                        continue

                    alert_events += 1

                    # Extract alert information
                    alert = event.get('alert', {})
                    sid = str(alert.get('signature_id', ''))

                    # Check if this is one of our custom rules
                    if sid not in self.SID_TO_ATTACK:
                        continue

                    attack_type = self.SID_TO_ATTACK[sid]

                    # Count this alert
                    alert_counts[attack_type] += 1

                    # Record first detection time if not already recorded
                    if attack_type not in first_detections:
                        try:
                            # Parse timestamp
                            timestamp_str = event['timestamp']
                            # Handle different timestamp formats
                            if timestamp_str.endswith('Z'):
                                timestamp_str = timestamp_str.replace('Z', '+00:00')
                            # Fix timezone format: -0800 to -08:00
                            timestamp_str = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', timestamp_str)

                            detection_time = datetime.fromisoformat(timestamp_str)
                            # Remove timezone info to match ground truth (which is naive)
                            detection_time = detection_time.replace(tzinfo=None)

                            # Calculate time to detection
                            time_to_detect = (detection_time - self.attack_start_time).total_seconds()

                            first_detections[attack_type] = {
                                'timestamp': event['timestamp'],
                                'time_to_detect_seconds': time_to_detect,
                                'signature': alert.get('signature', 'Unknown'),
                                'severity': alert.get('severity', 0)
                            }

                            print(f"  [OK] First detection: {attack_type} at {time_to_detect:.2f}s")

                        except (KeyError, ValueError) as e:
                            print(f"  Warning: Could not parse timestamp for {attack_type}: {e}")
                            continue

        except Exception as e:
            print(f"  Error reading eve.json: {e}")
            raise

        print(f"\n  Total events processed: {total_events:,}")
        print(f"  Alert events: {alert_events:,}")
        print(f"  Custom rule alerts: {sum(alert_counts.values()):,}")

        self.first_detections = first_detections
        self.alert_counts = dict(alert_counts)

        return first_detections, alert_counts

    def calculate_metrics(self):
        """Calculate detection metrics for each attack"""
        print("\nCalculating detection metrics...")

        metrics = {}

        for attack_name, gt_data in self.ground_truth.items():
            attack_type = gt_data['attack_type']
            packets_sent = gt_data['packets_sent']

            # Check if this attack was detected
            detected = attack_type in self.first_detections

            attack_metrics = {
                'attack_type': attack_type,
                'packets_sent': packets_sent,
                'detected': detected,
                'attack_duration': gt_data['duration'],
                'target_rate': gt_data['target_rate'],
                'actual_rate': gt_data['actual_rate']
            }

            if detected:
                # Attack was detected
                detection_info = self.first_detections[attack_type]
                alerts = self.alert_counts.get(attack_type, 0)

                # Calculate detection rate
                detection_rate = (alerts / packets_sent * 100) if packets_sent > 0 else 0

                attack_metrics.update({
                    'time_to_detect_seconds': detection_info['time_to_detect_seconds'],
                    'detection_timestamp': detection_info['timestamp'],
                    'total_alerts': alerts,
                    'detection_rate_percent': detection_rate,
                    'signature': detection_info['signature'],
                    'severity': detection_info['severity']
                })

                print(f"\n  {attack_type}:")
                print(f"    Packets sent:     {packets_sent:,}")
                print(f"    Time to detect:   {detection_info['time_to_detect_seconds']:.3f}s")
                print(f"    Total alerts:     {alerts:,}")
                print(f"    Detection rate:   {detection_rate:.2f}%")

            else:
                # Attack was NOT detected
                attack_metrics.update({
                    'time_to_detect_seconds': None,
                    'detection_timestamp': None,
                    'total_alerts': 0,
                    'detection_rate_percent': 0.0,
                    'signature': None,
                    'severity': None
                })

                print(f"\n  {attack_type}:")
                print(f"    Packets sent:     {packets_sent:,}")
                print(f"    [WARNING] NOT DETECTED")

            metrics[attack_name] = attack_metrics

        return metrics

    def generate_report(self, metrics, test_type, iteration):
        """Generate comprehensive detection report"""
        print("\n" + "="*70)
        print("DETECTION EFFECTIVENESS REPORT")
        print("="*70)

        # Calculate summary statistics
        total_attacks = len(metrics)
        detected_attacks = sum(1 for m in metrics.values() if m['detected'])
        total_packets_sent = sum(m['packets_sent'] for m in metrics.values())
        total_alerts = sum(m['total_alerts'] for m in metrics.values())

        detection_success_rate = (detected_attacks / total_attacks * 100) if total_attacks > 0 else 0
        overall_detection_rate = (total_alerts / total_packets_sent * 100) if total_packets_sent > 0 else 0

        # Build report
        report = {
            'metadata': {
                'test_type': test_type,
                'iteration': iteration,
                'analysis_timestamp': datetime.now().isoformat(),
                'ground_truth_file': str(self.ground_truth_file),
                'eve_json_file': str(self.eve_json_file)
            },
            'attacks': metrics,
            'summary': {
                'total_attacks': total_attacks,
                'detected_attacks': detected_attacks,
                'undetected_attacks': total_attacks - detected_attacks,
                'detection_success_rate_percent': detection_success_rate,
                'total_packets_sent': total_packets_sent,
                'total_alerts': total_alerts,
                'overall_detection_rate_percent': overall_detection_rate
            }
        }

        # Print summary
        print(f"\nTest Configuration: {test_type} - Iteration {iteration}")
        print(f"Attack start time: {self.attack_start_time}")
        print()
        print("Summary Statistics:")
        print(f"  Total attack types:        {total_attacks}")
        print(f"  Detected:                  {detected_attacks}")
        print(f"  Not detected:              {total_attacks - detected_attacks}")
        print(f"  Detection success rate:    {detection_success_rate:.1f}%")
        print()
        print(f"  Total packets sent:        {total_packets_sent:,}")
        print(f"  Total alerts generated:    {total_alerts:,}")
        print(f"  Overall detection rate:    {overall_detection_rate:.2f}%")
        print("="*70)

        return report

    def save_report(self, report, output_file):
        """Save report to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[OK] Report saved: {output_file}")


def main():
    """Main execution function"""
    # Check arguments
    if len(sys.argv) != 6:
        print("Usage: collect_detection_metrics.py <ground_truth.json> <eve.json> "
              "<output.json> <test_type> <iteration>")
        print()
        print("Arguments:")
        print("  ground_truth.json   - Attack generator output (JSON)")
        print("  eve.json           - Suricata event log (JSON)")
        print("  output.json        - Output file for metrics (JSON)")
        print("  test_type          - Test configuration name")
        print("  iteration          - Iteration number")
        sys.exit(1)

    ground_truth_file = sys.argv[1]
    eve_json_file = sys.argv[2]
    output_file = sys.argv[3]
    test_type = sys.argv[4]
    iteration = sys.argv[5]

    print("="*70)
    print("IDS DETECTION METRICS COLLECTOR")
    print("="*70)
    print(f"Ground truth: {ground_truth_file}")
    print(f"Suricata logs: {eve_json_file}")
    print(f"Output: {output_file}")
    print(f"Test: {test_type} - Iteration {iteration}")
    print("="*70)

    try:
        # Initialize collector
        collector = DetectionMetricsCollector(ground_truth_file, eve_json_file)

        # Parse ground truth
        collector.parse_ground_truth()

        # Parse Suricata detections
        collector.parse_suricata_detections()

        # Calculate metrics
        metrics = collector.calculate_metrics()

        # Generate report
        report = collector.generate_report(metrics, test_type, iteration)

        # Save report
        collector.save_report(report, output_file)

        print("\n[OK] Analysis complete!\n")
        return 0

    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}\n")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

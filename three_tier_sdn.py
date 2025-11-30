#!/usr/bin/env python3
"""
Three-Tier SDN Network Topology
Uses OpenFlow switches with POX controller
Simulates: Web tier → App tier → Database tier
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_three_tier_sdn():
    """Create three-tier SDN network topology"""

    info('*** Creating Three-Tier SDN Network\n')

    # Create network with OpenFlow 1.0 switches
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        build=False
    )

    info('*** Adding controller\n')
    # POX controller on localhost
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    info('*** Adding OpenFlow switches\n')
    # Three switches - one per tier
    web_sw = net.addSwitch('s1', protocols='OpenFlow10', failMode='secure')
    app_sw = net.addSwitch('s2', protocols='OpenFlow10', failMode='secure')
    data_sw = net.addSwitch('s3', protocols='OpenFlow10', failMode='secure')

    info('*** Adding hosts\n')

    # All hosts on same subnet for L2 connectivity
    # Web Tier (10.0.0.10-19)
    web1 = net.addHost('web1', ip='10.0.0.11/24', mac='00:00:00:01:01:0a')
    web2 = net.addHost('web2', ip='10.0.0.12/24', mac='00:00:00:01:01:14')
    lb = net.addHost('lb', ip='10.0.0.13/24', mac='00:00:00:01:01:63')

    # Application Tier (10.0.0.20-29)
    app1 = net.addHost('app1', ip='10.0.0.21/24', mac='00:00:00:02:02:0a')
    app2 = net.addHost('app2', ip='10.0.0.22/24', mac='00:00:00:02:02:14')
    app3 = net.addHost('app3', ip='10.0.0.23/24', mac='00:00:00:02:02:1e')

    # Database Tier (10.0.0.30-39)
    db1 = net.addHost('db1', ip='10.0.0.31/24', mac='00:00:00:03:03:0a')
    db2 = net.addHost('db2', ip='10.0.0.32/24', mac='00:00:00:03:03:14')
    victim = net.addHost('victim', ip='10.0.0.100/24', mac='00:00:00:03:03:64')

    info('*** Creating links\n')

    # Web tier hosts to web switch (s1)
    net.addLink(web1, web_sw)    # s1-eth1
    net.addLink(web2, web_sw)    # s1-eth2
    net.addLink(lb, web_sw)      # s1-eth3

    # App tier hosts to app switch (s2)
    net.addLink(app1, app_sw)    # s2-eth1
    net.addLink(app2, app_sw)    # s2-eth2
    net.addLink(app3, app_sw)    # s2-eth3

    # Database tier hosts to data switch (s3)
    net.addLink(db1, data_sw)    # s3-eth1
    net.addLink(db2, data_sw)    # s3-eth2
    net.addLink(victim, data_sw) # s3-eth3

    # Inter-switch links
    net.addLink(web_sw, app_sw)  # s1-eth4 <-> s2-eth4
    net.addLink(app_sw, data_sw) # s2-eth5 <-> s3-eth4

    info('*** Building network\n')
    net.build()

    info('*** Starting controller\n')
    c0.start()

    info('*** Starting switches\n')
    web_sw.start([c0])
    app_sw.start([c0])
    data_sw.start([c0])

    # Wait for switches to connect
    info('*** Waiting for switches to connect to controller\n')
    import time
    time.sleep(3)

    info('\n')
    info('=' * 60 + '\n')
    info('THREE-TIER SDN NETWORK STARTED\n')
    info('=' * 60 + '\n\n')

    info('Network Topology (all hosts on 10.0.0.0/24):\n')
    info('  Web Tier - Switch s1:\n')
    info('    - web1:   10.0.0.11  (s1-eth1) MAC: 00:00:00:01:01:0a\n')
    info('    - web2:   10.0.0.12  (s1-eth2) MAC: 00:00:00:01:01:14\n')
    info('    - lb:     10.0.0.13  (s1-eth3) MAC: 00:00:00:01:01:63\n\n')

    info('  App Tier - Switch s2:\n')
    info('    - app1:   10.0.0.21  (s2-eth1) MAC: 00:00:00:02:02:0a\n')
    info('    - app2:   10.0.0.22  (s2-eth2) MAC: 00:00:00:02:02:14\n')
    info('    - app3:   10.0.0.23  (s2-eth3) MAC: 00:00:00:02:02:1e\n\n')

    info('  Database Tier - Switch s3:\n')
    info('    - db1:    10.0.0.31  (s3-eth1) MAC: 00:00:00:03:03:0a\n')
    info('    - db2:    10.0.0.32  (s3-eth2) MAC: 00:00:00:03:03:14\n')
    info('    - victim: 10.0.0.100 (s3-eth3) MAC: 00:00:00:03:03:64\n\n')

    info('Inter-Switch Links:\n')
    info('  - s1-eth4 <-> s2-eth4  (Web <-> App)\n')
    info('  - s2-eth5 <-> s3-eth4  (App <-> Database)\n\n')

    info('=' * 60 + '\n')
    info('Controller Status:\n')
    info('  Check POX controller terminal for switch connections\n')
    info('  You should see 3 switches connected\n\n')

    info('Verify flows are installed:\n')
    info('  mininet> sh ovs-ofctl dump-flows s1\n')
    info('  mininet> sh ovs-ofctl dump-flows s2\n')
    info('  mininet> sh ovs-ofctl dump-flows s3\n\n')

    info('Test Connectivity:\n')
    info('  mininet> pingall\n\n')

    info('Start HTTP server on victim:\n')
    info('  mininet> victim python3 -m http.server 80 &\n\n')

    info('Run attacks:\n')
    info('  Cross-tier:  web1 python3 three_tier_attacks.py --all\n')
    info('  Single host: lb python3 generate_attack_traffic.py 10.0.0.100 all\n\n')

    info('IDS Monitoring Options:\n')
    info('  Option 1 (Inter-switch): sudo /media/sf_shared/run_suricata_custom_only.sh s1-eth4\n')
    info('  Option 2 (Web tier):     sudo /media/sf_shared/run_suricata_custom_only.sh s1-eth1\n')
    info('  Option 3 (Victim):       sudo /media/sf_shared/run_suricata_custom_only.sh s3-eth3\n\n')

    info('=' * 60 + '\n')

    # Start CLI
    CLI(net)

    # Cleanup
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_three_tier_sdn()

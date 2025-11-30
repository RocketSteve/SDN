#!/usr/bin/env python3
"""
Three-Tier Traditional Network Topology (Simplified)
Uses standard Mininet switches in standalone mode (non-SDN)
Better compatibility with IDS monitoring
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_three_tier_network():
    """Create three-tier network topology with standard switches"""

    info('*** Creating Three-Tier Traditional Network\n')

    # Create network with OVS switches in standalone mode (acts like traditional bridge)
    net = Mininet(
        switch=OVSSwitch,
        link=TCLink,
        build=False,
        autoSetMacs=True
    )

    info('*** Adding switches (standalone mode - no controller)\n')
    # Three switches in standalone mode = traditional bridge behavior
    web_sw = net.addSwitch('s1', failMode='standalone')
    app_sw = net.addSwitch('s2', failMode='standalone')
    data_sw = net.addSwitch('s3', failMode='standalone')

    info('*** Adding hosts\n')

    # All hosts on same subnet for L2 connectivity
    # Web Tier (10.0.0.10-19)
    web1 = net.addHost('web1', ip='10.0.0.11/24')
    web2 = net.addHost('web2', ip='10.0.0.12/24')
    lb = net.addHost('lb', ip='10.0.0.13/24')

    # Application Tier (10.0.0.20-29)
    app1 = net.addHost('app1', ip='10.0.0.21/24')
    app2 = net.addHost('app2', ip='10.0.0.22/24')
    app3 = net.addHost('app3', ip='10.0.0.23/24')

    # Database Tier (10.0.0.30-39)
    db1 = net.addHost('db1', ip='10.0.0.31/24')
    db2 = net.addHost('db2', ip='10.0.0.32/24')
    victim = net.addHost('victim', ip='10.0.0.100/24')

    info('*** Creating links\n')

    # Web tier hosts to web switch
    net.addLink(web1, web_sw)
    net.addLink(web2, web_sw)
    net.addLink(lb, web_sw)

    # App tier hosts to app switch
    net.addLink(app1, app_sw)
    net.addLink(app2, app_sw)
    net.addLink(app3, app_sw)

    # Database tier hosts to data switch
    net.addLink(db1, data_sw)
    net.addLink(db2, data_sw)
    net.addLink(victim, data_sw)

    # Inter-switch links (creates multi-hop paths)
    net.addLink(web_sw, app_sw)  # Web <-> App
    net.addLink(app_sw, data_sw)  # App <-> Database

    info('*** Building network\n')
    net.build()

    info('*** Starting switches\n')
    web_sw.start([])  # No controller - standalone mode
    app_sw.start([])
    data_sw.start([])

    info('\n')
    info('=' * 60 + '\n')
    info('THREE-TIER TRADITIONAL NETWORK STARTED\n')
    info('=' * 60 + '\n\n')

    info('Network Topology (all hosts on 10.0.0.0/24):\n')
    info('  Web Tier:\n')
    info('    - web1:   10.0.0.11  (Web server)\n')
    info('    - web2:   10.0.0.12  (Web server)\n')
    info('    - lb:     10.0.0.13  (Load balancer)\n\n')

    info('  App Tier:\n')
    info('    - app1:   10.0.0.21  (Application server)\n')
    info('    - app2:   10.0.0.22  (Application server)\n')
    info('    - app3:   10.0.0.23  (API server)\n\n')

    info('  Database Tier:\n')
    info('    - db1:    10.0.0.31  (Primary database)\n')
    info('    - db2:    10.0.0.32  (Replica database)\n')
    info('    - victim: 10.0.0.100 (Attack target)\n\n')

    info('Switches (standalone mode = traditional behavior):\n')
    info('  - s1  (Web tier switch)\n')
    info('  - s2  (Application tier switch)\n')
    info('  - s3  (Database tier switch)\n\n')

    # Show network topology
    info('Network connections:\n')
    net.pingAll()
    info('\n')

    # Find victim's interface
    info('=' * 60 + '\n')
    info('IDS MONITORING SETUP:\n')
    info('=' * 60 + '\n')

    # Get victim's interface on data-sw
    for link in net.links:
        if victim in (link.intf1.node, link.intf2.node):
            if link.intf1.node == victim:
                victim_intf = link.intf1.name
                switch_intf = link.intf2.name
            else:
                victim_intf = link.intf2.name
                switch_intf = link.intf1.name

            if 's3' in switch_intf:
                info(f'\nVictim interface: {victim_intf}\n')
                info(f'Switch interface: {switch_intf}\n\n')
                info('To monitor victim traffic:\n')
                info(f'  Terminal 2: sudo /media/sf_shared/run_suricata_custom_only.sh {switch_intf}\n\n')
                break

    info('=' * 60 + '\n')
    info('Test Connectivity:\n')
    info('  mininet> pingall\n\n')

    info('Start HTTP server on victim:\n')
    info('  mininet> victim python3 -m http.server 80 &\n\n')

    info('Run attacks:\n')
    info('  mininet> web1 python3 /media/sf_shared/three_tier_attacks.py --all\n\n')

    info('=' * 60 + '\n')

    # Start CLI
    CLI(net)

    # Cleanup
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_three_tier_network()

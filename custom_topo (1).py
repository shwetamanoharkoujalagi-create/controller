#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

import random

class TenSwitchTopo(Topo):
    def build(self):
        # Create 10 switches with OpenFlow13 protocol 🔧
        switches = [self.addSwitch(f's{i+1}', protocols='OpenFlow13') for i in range(10)]

        # Interconnect switches in a linear + random pattern
        for i in range(9):
            self.addLink(switches[i], switches[i+1])
        self.addLink(switches[0], switches[5])
        self.addLink(switches[2], switches[7])
        self.addLink(switches[3], switches[9])

        # Connect 4 hosts to random switches
        for h in range(1, 5):
            host = self.addHost(f'h{h}')
            sw = random.choice(switches)
            self.addLink(host, sw)

def run():
    topo = TenSwitchTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),  # 🔧 use correct OF13 port
        switch=OVSSwitch,  # 🔧 ensure OVS is used
        link=TCLink,
        autoSetMacs=True
    )
    net.start()

    print("\nNetwork is ready. You can test connectivity or wait for the controller to discover it.")
    print("Try: pingall, or exit with Ctrl+D\n")

    net.interact()
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from functools import partial

def myNetwork():
    
    switch = partial( OVSKernelSwitch, protocols='OpenFlow10' )
    net = Mininet( topo=None,
                   build=False,
                   switch=switch,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    #"""
    """
    S1 = net.addSwitch('S1', cls=OVSKernelSwitch)
    """
    #S2 = net.addSwitch('S2', cls=OVSKernelSwitch)
    #R1 = net.addSwitch('R1', cls=OVSKernelSwitch)
    #R2 = net.addSwitch('R2', cls=OVSKernelSwitch)
    #R3 = net.addSwitch('R3', cls=OVSKernelSwitch)
    #R4 = net.addSwitch('R4', cls=OVSKernelSwitch)
    #"""
    S1 = net.addSwitch('S1')
    #S2 = net.addSwitch('S2')
    #R1 = net.addSwitch('R1')
    #R2 = net.addSwitch('R2')
    #R3 = net.addSwitch('R3')
    #R4 = net.addSwitch('R4')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', cls=Host, ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
    h3 = net.addHost('h3', cls=Host, ip='10.0.3.2/24', defaultRoute='via 10.0.3.1')
    h4 = net.addHost('h4', cls=Host, ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
    h5 = net.addHost('h5', cls=Host, ip='10.0.4.2/24', defaultRoute='via 10.0.4.1')
    h6 = net.addHost('h6', cls=Host, ip='10.0.4.3/24', defaultRoute='via 10.0.4.1')

    info( '*** Add links\n')
    net.addLink(S1, h1)
    net.addLink(S1, h2)
    net.addLink(s1, h3)
    net.addLink(s1, h4)
    net.addLink(s1, h5)
    net.addLink(s1, h6)
    #net.addLink(R3, h3)
    #net.addLink(R3, R4)
    #net.addLink(R2, h4)
    #net.addLink(R4, S2)
    #net.addLink(S2, h5)
    #net.addLink(S2, h6)
    #"""
    #R1.setIP("10.0.1.1", intf = "R1-eth1")
    #R1.setIP("192.0.4.1", intf = "R1-eth2")
    #R2.setIP("192.0.4.2", intf = "R2-eth1")
    #R2.setIP("192.0.3.1", intf = "R2-eth2")
    #R4.setIP("192.0.3.2", intf = "R4-eth1")
    #R1.setIP("192.0.1.1", intf = "R1-eth3")
    #R3.setIP("192.0.1.2", intf = "R3-eth1")
    #R3.setIP("10.3.0.1", intf = "R3-eth2")
    #R3.setIP("192.0.2.1 ", intf = "R3-eth3")
    #R4.setIP("192.0.2.2", intf = "R4-eth2")
    #R2.setIP("10.0.2.1", intf = "R2-eth3")
    #R4.setIP("10.0.4.1 ", intf = "R4-eth3")
    #"""
    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    #net.get('R1').start([c0])
    #net.get('R4').start([c0])
    #net.get('S2').start([c0])
    #net.get('R3').start([c0])
    net.get('S1').start([c0])
    #net.get('R2').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()


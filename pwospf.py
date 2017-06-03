

from pox.core import core
import pox.openflow.libopenflow_01 as of
import csv

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.openflow.nicira as nx

import pox.lib.packet as pkt

#from packet_base import packet_base

import sys        # For argument list
import xmlrpclib  # For XMLRPC
import os         # For making directories
import threading  # For running the server in the background
import time       # For calling the sleep function
import hashlib    # For hashing node addresses & file names
import Queue
import thread
import datetime

routerList = []
HELLO = 1
LSU = 2
class router:
    def __init__(self, dpid, localIp):

        # IP of the current machine
        self.localIp       = localIp

        # Port number at which the process is running
        self.dpid     = dpid

        self.eventid = None

        self.counter = 0

        self.neighbourList = {}

        self.adjacenyList = {}

        self.sequenceList = {}

        self.adjacenyList = {}

    def sendHello(self):
        global HELLO
        print self.localIp + " sending hello message!"
        MIN_LEN = 20
        IP_TYPE = 0x0800
        ETHER_ANY = EthAddr(b"\x00\x00\x00\x00\x00\x00")
        #####################
        ippacket = pkt.ipv4()
        ippacket.srcip = IPAddr(self.localIp)
        ippacket.dstip = IPAddr('10.0.0.20')

        #packet_base.__init__(self)

        ippacket.prev = None

        ippacket.v     = 4
        ippacket.hl    = MIN_LEN / 4
        ippacket.tos   = HELLO
        #ipv4.ip_id = (ipv4.ip_id + 1) & 0xffff   
        #self.counter = (self.counter + 1) & 0xffff
        ippacket.id    = self.counter
        ippacket.flags = 0
        ippacket.frag  = 0
        ippacket.ttl   = 64
        ippacket.protocol = 0
        ippacket.csum  = 0
        ippacket.next  = b'HELLO ANOOP'    
        ippacket.iplen = ipv4.MIN_LEN + len('HELLO ANOOP')

        epacket = ethernet()
        epacket.type = IP_TYPE
        epacket.dst  = ETHER_ANY
        epacket.src  = ETHER_ANY
        epacket.set_payload(ippacket)
        self.eventid.connection.send(of.ofp_packet_out(data=epacket.pack(), action=of.ofp_action_output(port=of.OFPP_ALL)))


    def sendLSUpdate(self):
        global LSU
        print self.localIp + " sending LS_Update!"
        MIN_LEN = 20
        IP_TYPE = 0x0800
        ETHER_ANY = EthAddr(b"\x00\x00\x00\x00\x00\x00")
        ipList = self.neighbourList.keys()
        delim = ','
        data = ""
        t = []
        for ip in ipList:
            t.append(str(ip))
        data = delim.join(t)
        payld = bytes(data)

        #####################
        ippacket = pkt.ipv4()
        ippacket.srcip = IPAddr(self.localIp)
        ippacket.dstip = IPAddr('10.0.0.255')

        #packet_base.__init__(self)

        ippacket.prev = None

        ippacket.v     = 4
        ippacket.hl    = MIN_LEN / 4
        ippacket.tos   = LSU    
        ipv4.ip_id = (ipv4.ip_id + 1) & 0xffff   
        self.counter = (self.counter + 1) & 0xffff
        ippacket.id    = self.counter
        ippacket.flags = 0
        ippacket.frag  = 0
        ippacket.ttl   = 64
        ippacket.protocol = 0
        ippacket.csum  = 0
        ippacket.next  = payld    
        ippacket.iplen = ipv4.MIN_LEN + len(payld)

        epacket = ethernet()
        epacket.type = IP_TYPE
        epacket.dst  = ETHER_ANY
        epacket.src  = ETHER_ANY
        epacket.set_payload(ippacket)
        self.eventid.connection.send(of.ofp_packet_out(data=epacket.pack(), action=of.ofp_action_output(port=of.OFPP_ALL)))


    def processHello(self, event):
        packet = event.parsed
        incomingAddress = packet.next.srcip
	print("\nhandlePacketin(): Connection :%s  DPID: %s" % (event.connection, incomingAddress ) )



    def checkTimeOut(self):
        currentTime = int(time.time())
        for routerObject in self.neighbourList.keys():
            difference = currentTime - self.neighbourList[routerObject]
            if difference > 30:
                print "timeout occured\n\n\n\n\n\n\n\n\n"
                del self.neighbourList[routerObject]

def scheduler():
    global routerList

    counter = 0
    while(1):
        for routerObject in routerList:
            routerObject.sendHello()
            routerObject.checkTimeOut()
            if counter%3 == 0 and counter > 0:
                routerObject.sendLSUpdate()

        counter = counter + 1
        time.sleep(5)

def handleConnectionUp(event):
    #modification for creating routing table at connection up
    dpid = event.connection.dpid
    print("handleConnectionUp(): Connection :%s  DPID: %d" % (event.connection, dpid) )
    #only for router
    if dpid > 10:
        print "in dpid"
        csv_read = csv.reader(file('/home/mininet/pox/pox/misc/dpidtoip.csv')) # read gateway csv file
        for record in csv_read:
            print "record:",int(record[0])
            if int(record[0]) == dpid:
                print "hi",record[0],record[1]
                ip = record[1]
                router_object = router(dpid, ip)
                router_object.eventid = event
                routerList.append(router_object)

def handlePacketIn (event):    
    dpid = event.connection.dpid
    print("\nhandlePacketin(): Connection :%s  DPID: %d" % (event.connection, dpid ) )
    #print "IP to MAC table: ", ip_to_mac
    packet = event.parsed
    inport = event.port
    if dpid > 10:

        if not packet.parsed:
            print("%i %i ignoring unparsed packet" %(dpid, inport))
            return

        if packet.type == ethernet.LLDP_TYPE:
            print "anooperror : LLDP"
            return  

        if isinstance(packet.next, ipv4):
            print("switchPacketin():DPID: %i Port :%i IP %s => %s" % (dpid , inport,  packet.next.srcip , packet.next.dstip))
            tos = packet.next.tos
            for routerObject in routerList:
            	if routerObject.dpid == dpid:
                     routerObject.processHello(event)
            else:
                pass


def launch():
    global routerList

    core.openflow.addListenerByName("PacketIn", handlePacketIn )
    print "launch():Welcome dudessssssssssss"
    core.openflow.addListenerByName("ConnectionUp", handleConnectionUp)    

    server_thread = threading.Thread(target = scheduler)


    server_thread.daemon = True

    # Starting the server thread
    server_thread.start()
    print "THread is started man.."

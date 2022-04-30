#!/usr/bin/env python3

'''{frame.len, eth.type, ip.proto, ip.flags, ipv6.nxt
, ipv6.opt, tcp.srcport, tcp.dstport, tcp.flags, udp.srcport, udp.dstport, eth.src, class}'''

import sys
import socket
import random
import time
import pandas as pd

from scapy.all import *
#
def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def send_packet(iface, listView):
# def send_packet(listView):
    #convert to match types
    typeEth = int(listView[1], 16)
    print(type(typeEth))

    # typeEthNew = hex(typeEth)
    # print(typeEthNew)
    proto = int(listView[2])
    tcp_sport = int(listView[6])
    tcp_dport = int(listView[7])
    udp_sport = int(listView[9])
    udp_dport = int(listView[10])




    # sIP = '0.0.0.0'
    #dIP = '0.0.0.0'
    #print(type(type))
    #print(type(typeEthNew))
    pkt = []
    print(listView)
    if listView[2] == "17":
        pkt = Ether(src=get_if_hwaddr(iface), dst="00:00:0a:00:01:02")
        pkt = pkt / IP(proto=proto, dst="10.0.1.2")
        pkt = pkt / UDP(sport=udp_sport, dport=udp_dport)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

    if listView[2] == '6':
        pkt = Ether(src=get_if_hwaddr(iface), dst="00:00:0a:00:01:02")
        pkt = pkt / IP(proto=proto, dst="10.0.1.2")
        pkt = pkt / TCP(sport=tcp_sport, dport=tcp_dport)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)


    # print(listView)
    # input("Press the return key to send the packet:")

    # sendp(pkt, iface=iface, verbose=False)


def main():

    iface = get_if()

    packetGen = pd.read_csv('/home/p4/Desktop/test_with_low.csv', dtype=str)


    # print(packetGen)

    try:
        # while True:

        for index,row in packetGen.iterrows():
            listView = row.tolist()
            send_packet(iface,listView)
            # send_packet(listView)
            time.sleep(1)

    except KeyboardInterrupt:
        print("Enter Pressed")


if __name__ == '__main__':
    main()

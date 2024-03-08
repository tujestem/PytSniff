from scapy.all import sniff, TCP, UDP, IP
from termcolor import colored

def packet_callback(packet):
    try:
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # Pobieranie podstawowych informacji o pakiecie
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            src_port = packet.sport
            dst_port = packet.dport
            frame_len = len(packet)

            # Start packets analysis.
            errors = []

            # Check packet size.
            if frame_len > 800:
                errors.append("Size of the packet excess value of 800 (take it easy... normal MTU value is 1500)")

            # Wyświetlanie informacji o pakiecie
            print(f"Pakiet {ip_src}:{src_port} -> {ip_dst}:{dst_port}, Rozmiar ramki: {frame_len}")

            # Jeśli są błędy, podkreśl je kolorem czerwonym
            for error in errors:
                print(colored(error, "red"))

    except Exception as e:
        print(f"Wystąpił błąd podczas analizy pakietu: {e}")

# Ustaw nasłuchiwanie pakietów TCP i UDP
sniff(filter="tcp or udp", prn=packet_callback, store=0)

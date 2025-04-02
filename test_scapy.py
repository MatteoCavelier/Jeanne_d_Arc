from scapy.all import sniff

# Fonction de traitement des paquets
def packet_callback(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        dst_port = packet["TCP"].dport

        # Messages spécifiques aux ports
        if dst_port == 80:
            print(f"[HTTP] Coucou HTTP - {src_ip} → {dst_ip}:{dst_port}")
        elif dst_port == 443:
            print(f"[HTTPS] Coucou HTTPS - {src_ip} → {dst_ip}:{dst_port}")
        elif dst_port == 445:
            print(f"[SMB] Coucou SMB - {src_ip} → {dst_ip}:{dst_port}")

# Capture en continu des paquets
print("Capture en cours... (Ctrl+C pour arrêter)")
sniff(prn=packet_callback, store=False)
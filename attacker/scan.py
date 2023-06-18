from scapy.all import ARP, Ether, srp

def scan_network(interface):
    # Crea una solicitud ARP para obtener información de los dispositivos conectados
    arp_request = ARP(pdst='10.12.10.5/24')
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp_request

    # Envia el paquete y recibe la respuesta
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

    # Procesa la respuesta
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

# Especifica la interfaz de red que deseas escanear
interface = 'en0'  # Cambia 'en0' por la interfaz correcta en tu sistema

# Escanea la red y muestra los dispositivos encontrados
devices = scan_network(interface)
print("Dispositivos conectados:")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
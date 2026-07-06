"""
Practica 2 - Reconocimiento activo: descubrimiento de hosts con scapy.

Construye paquetes de sondeo (ICMP timestamp, TCP ACK, UDP) para detectar
hosts activos en un rango de IPs, sin completar ningun handshake ni
establecer conexiones reales.
"""

from __future__ import annotations

from scapy.all import IP, ICMP, TCP, UDP, Net, RandShort

VALID_PROTOCOLS = {"ICMP", "TCP", "UDP"}


def _expand_ip_range(ip_range: str) -> list[str]:
    """Expande un rango de IPs.

    Soporta tres formatos:
      - CIDR: "172.20.0.0/24"           -> delegado en Net()
      - Rango con guion (IP a IP):
        "172.20.0.10-172.20.0.60"        -> expandido manualmente
      - IP unica: "172.20.0.10"          -> se devuelve tal cual

    Nota: a partir de scapy 2.7, Net() ya no admite rangos con guion
    directamente (solo CIDR), asi que el caso de guion se resuelve a mano.
    """
    if "/" in ip_range:
        return [str(ip) for ip in Net(ip_range)]

    if "-" in ip_range:
        start_ip, end_ip = ip_range.split("-")
        start_ip = start_ip.strip()
        end_ip = end_ip.strip()

        start_parts = start_ip.split(".")
        prefix = ".".join(start_parts[:3])
        start_octet = int(start_parts[3])

        # El extremo final puede venir como IP completa ("172.20.0.60")
        # o como octeto suelto ("60"); soportamos ambos.
        if "." in end_ip:
            end_octet = int(end_ip.split(".")[3])
        else:
            end_octet = int(end_ip)

        return [f"{prefix}.{i}" for i in range(start_octet, end_octet + 1)]

    return [ip_range]


def craft_discovery_pkts(
    protocols: str | list[str],
    ip_range: str,
    packet_counts: dict[str, int] | None = None,
    port: int = 80,
) -> list:
    """
    Construye una lista de paquetes scapy para host discovery.

    Args:
        protocols: uno o varios de "ICMP", "TCP", "UDP" (hasta 3), string o lista.
        ip_range: IP unica, rango con guion o notacion CIDR.
        packet_counts: dict {protocolo: numero_de_paquetes}. Por defecto, 1 de cada.
        port: puerto usado en TCP/UDP. Por defecto 80.

    Returns:
        Lista de paquetes IP/<protocolo> listos para enviar con sr()/sr1()/send().
    """
    if isinstance(protocols, str):
        protocols = [protocols]
    protocols = [p.upper() for p in protocols]

    if len(protocols) > 3:
        raise ValueError("Se admiten como maximo 3 protocolos.")
    invalid = set(protocols) - VALID_PROTOCOLS
    if invalid:
        raise ValueError(f"Protocolo(s) no soportado(s): {invalid}. Validos: {VALID_PROTOCOLS}")

    if packet_counts is None:
        packet_counts = {proto: 1 for proto in protocols}

    ips = _expand_ip_range(ip_range)

    packets = []
    for proto in protocols:
        n = packet_counts.get(proto, 1)
        for ip in ips:
            for _ in range(n):
                if proto == "ICMP":
                    pkt = IP(dst=ip) / ICMP(type=13)  # Timestamp Request
                elif proto == "TCP":
                    pkt = IP(dst=ip) / TCP(dport=port, flags="A", sport=RandShort())
                else:  # UDP
                    pkt = IP(dst=ip) / UDP(dport=port, sport=RandShort())
                packets.append(pkt)

    return packets

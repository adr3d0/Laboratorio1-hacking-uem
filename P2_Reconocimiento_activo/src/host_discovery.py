"""
Practica 2 - Reconocimiento activo: script de descubrimiento de hosts.

Envia paquetes ICMP (timestamp), TCP (ACK) y UDP contra un rango de IPs
del laboratorio Docker (red 'labnet', 172.20.0.0/24) y reporta que IPs
respondieron, es decir, que hosts estan activos.

Requiere privilegios de root (sockets raw): ejecutar con sudo.
"""

from scapy.all import sr

from craft_discovery_pkts import craft_discovery_pkts


def discover_hosts(
    protocols,
    ip_range: str,
    packet_counts: dict | None = None,
    port: int = 80,
    timeout: int = 2,
) -> list[str]:
    """Envia los paquetes craftedos y devuelve la lista de IPs que respondieron."""
    packets = craft_discovery_pkts(protocols, ip_range, packet_counts, port)
    answered, unanswered = sr(packets, timeout=timeout, verbose=0)

    active_ips = set()
    for _sent, received in answered:
        active_ips.add(received.src)

    print(f"[*] Paquetes enviados: {len(packets)}")
    print(f"[*] Respuestas recibidas: {len(answered)}")
    print(f"[*] Sin respuesta: {len(unanswered)}\n")

    return sorted(active_ips)


if __name__ == "__main__":
    # Rango que cubre los hosts activos del laboratorio (172.20.0.10 y .11)
    # y varias IPs sin contenedor (p. ej. 172.20.0.50), para cumplir el
    # requisito de probar contra host activo Y host inactivo.
    rango = "172.20.0.10-172.20.0.60"

    activos = discover_hosts(
        protocols=["ICMP", "TCP", "UDP"],
        ip_range=rango,
        packet_counts={"ICMP": 1, "TCP": 2, "UDP": 1},
        port=80,
    )

    print("IPs activas detectadas:")
    for ip in activos:
        print(f"  - {ip}")

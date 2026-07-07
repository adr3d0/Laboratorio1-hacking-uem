"""
Practica 3 - Deteccion de DNS Snooping / ataque tipo Kaminsky con scapy.

Monitoriza respuestas DNS y alerta cuando una misma IP recibe un volumen
de respuestas NXDOMAIN (subdominio inexistente) por encima de un umbral
en una ventana de tiempo corta -- firma tipica de ataques de Kaminsky
(intentos masivos de adivinar una respuesta antes de que llegue la
legitima) o de DNS snooping/reconocimiento de infraestructura interna
mediante fuerza bruta de subdominios.
"""

from __future__ import annotations

import argparse
import time
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, sniff

# Registro: IP -> lista de timestamps de respuestas NXDOMAIN recientes
_nxdomain_log: dict[str, list[float]] = defaultdict(list)

# Umbral y ventana por defecto (ajustables via argumentos de linea de comandos)
DEFAULT_THRESHOLD = 10
DEFAULT_WINDOW_SECONDS = 10


def alert_dnssnooping(
    packet,
    threshold: int = DEFAULT_THRESHOLD,
    window: int = DEFAULT_WINDOW_SECONDS,
    verbose: bool = True,
) -> None:
    """
    Callback de deteccion: analiza un paquete DNS y alerta si detecta una
    rafaga de respuestas NXDOMAIN hacia una misma IP por encima del umbral
    configurado dentro de la ventana de tiempo.

    Se invoca por cada paquete capturado por sniff() con filtro udp port 53.
    """
    if not packet.haslayer(DNS):
        return

    dns = packet[DNS]

    # Solo analizamos respuestas (qr=1) con codigo de respuesta NXDOMAIN (rcode=3)
    if dns.qr != 1 or dns.rcode != 3:
        return

    if not packet.haslayer(IP):
        return

    client_ip = packet[IP].dst  # quien hizo la consulta (destino de la respuesta)
    queried_name = dns.qd.qname.decode(errors="ignore") if dns.qd else "?"
    now = time.time()

    # Limpiamos timestamps fuera de la ventana
    _nxdomain_log[client_ip] = [ts for ts in _nxdomain_log[client_ip] if now - ts < window]
    _nxdomain_log[client_ip].append(now)

    count = len(_nxdomain_log[client_ip])

    if verbose:
        print(f"[info] NXDOMAIN hacia {client_ip} para '{queried_name}' ({count}/{threshold} en {window}s)")

    if count >= threshold:
        print(
            f"[ALERTA DNS SNOOPING] {client_ip} ha recibido {count} respuestas "
            f"NXDOMAIN en los ultimos {window}s (umbral: {threshold}). "
            f"Posible ataque de Kaminsky / mapeo de subdominios en curso."
        )
        # Reiniciamos el contador tras alertar, para evitar alertas repetidas
        # en cada paquete adicional dentro de la misma rafaga.
        _nxdomain_log[client_ip] = []


def main() -> None:
    parser = argparse.ArgumentParser(description="Detector de DNS Snooping / Kaminsky (Practica 3 - laboratorio Docker)")
    parser.add_argument("--iface", required=True, help="Interfaz de red a monitorizar")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Numero de NXDOMAIN para disparar alerta")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS, help="Ventana de tiempo en segundos")
    parser.add_argument("--quiet", action="store_true", help="No mostrar trafico NXDOMAIN normal, solo alertas")
    args = parser.parse_args()

    print(
        f"[*] Monitorizando respuestas DNS en {args.iface} "
        f"(umbral={args.threshold} NXDOMAIN / {args.window}s, Ctrl+C para detener)...\n"
    )

    sniff(
        iface=args.iface,
        filter="udp port 53",
        prn=lambda pkt: alert_dnssnooping(
            pkt, threshold=args.threshold, window=args.window, verbose=not args.quiet
        ),
        store=False,
    )


if __name__ == "__main__":
    main()

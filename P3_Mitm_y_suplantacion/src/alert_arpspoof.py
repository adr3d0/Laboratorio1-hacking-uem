"""
Practica 3 - Deteccion de ARP Spoofing con scapy.

Monitoriza el trafico ARP de una interfaz y alerta cuando una misma IP
responde desde mas de una direccion MAC en un periodo corto de tiempo,
indicador clasico e inequivoco de un ataque de ARP spoofing en curso.
"""

from __future__ import annotations

import argparse
import time
from collections import defaultdict

from scapy.all import ARP, sniff

# Registro: IP -> lista de (MAC, timestamp) vistos recientemente
_arp_table: dict[str, list[tuple[str, float]]] = defaultdict(list)

# Ventana de tiempo (segundos) durante la que se considera "reciente" una entrada
WINDOW_SECONDS = 30


def alert_arpspoof(packet, verbose: bool = True) -> None:
    """
    Callback de deteccion: analiza un paquete ARP y alerta si detecta una
    anomalia consistente con ARP spoofing (misma IP, MACs distintas en
    respuestas ARP recientes).

    Se invoca por cada paquete capturado por sniff() con filtro ARP.
    """
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    # Solo analizamos respuestas ARP (op=2, "is-at"), que son las que
    # realmente actualizan la cache ARP de un host y por tanto las que
    # un atacante falsifica para envenenar.
    if arp.op != 2:
        return

    src_ip = arp.psrc
    src_mac = arp.hwsrc
    now = time.time()

    # Limpiamos entradas antiguas fuera de la ventana de tiempo
    _arp_table[src_ip] = [
        (mac, ts) for mac, ts in _arp_table[src_ip] if now - ts < WINDOW_SECONDS
    ]

    known_macs = {mac for mac, _ in _arp_table[src_ip]}

    if known_macs and src_mac not in known_macs:
        print(
            f"[ALERTA ARP SPOOF] La IP {src_ip} ha respondido desde multiples "
            f"MACs en los ultimos {WINDOW_SECONDS}s: "
            f"{sorted(known_macs | {src_mac})}. "
            f"Posible envenenamiento ARP en curso."
        )
    elif verbose:
        print(f"[info] ARP reply: {src_ip} is-at {src_mac}")

    _arp_table[src_ip].append((src_mac, now))


def main() -> None:
    parser = argparse.ArgumentParser(description="Detector de ARP Spoofing (Practica 3 - laboratorio Docker)")
    parser.add_argument("--iface", required=True, help="Interfaz de red a monitorizar")
    parser.add_argument("--quiet", action="store_true", help="No mostrar trafico ARP normal, solo alertas")
    args = parser.parse_args()

    print(f"[*] Monitorizando ARP en {args.iface} (Ctrl+C para detener)...\n")

    sniff(
        iface=args.iface,
        filter="arp",
        prn=lambda pkt: alert_arpspoof(pkt, verbose=not args.quiet),
        store=False,
    )


if __name__ == "__main__":
    main()

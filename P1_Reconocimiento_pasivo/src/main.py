"""
Practica 1 - Reconocimiento pasivo (OSINT) sobre MAPFRE, S.A.
Asignatura: Laboratorio de Hacking - UEM

Este script automatiza dos tecnicas de reconocimiento PASIVO:
  1. Enumeracion de subdominios via Certificate Transparency (crt.sh).
  2. Consulta RDAP (sucesor de WHOIS) del dominio.

No se realizan escaneos de puertos, fuzzing, ni conexiones directas contra
la infraestructura de la empresa objetivo. Todas las fuentes consultadas
son publicas y de solo lectura.
"""

from __future__ import annotations

import argparse
import json
import sys

import requests

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


CRTSH_URL = "https://crt.sh/"
RDAP_URL = "https://rdap.org/domain/{domain}"
USER_AGENT = "P1-Reconocimiento-Pasivo-UEM/1.0 (uso academico)"


def enumerate_subdomains_crtsh(domain: str, timeout: int = 60) -> set[str]:
    """Consulta crt.sh (Certificate Transparency) y devuelve subdominios unicos."""
    params = {"q": domain, "output": "json"}
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(CRTSH_URL, params=params, headers=headers, timeout=timeout)
    resp.raise_for_status()

    subdomains: set[str] = set()
    try:
        entries = resp.json()
    except json.JSONDecodeError:
        print("[!] crt.sh devolvio una respuesta no-JSON (posible rate limit).", file=sys.stderr)
        return subdomains

    for entry in entries:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line.endswith(domain) and "*" not in line and "@" not in line:
                subdomains.add(line)
    return subdomains


def query_rdap(domain: str, timeout: int = 15) -> dict | None:
    """Consulta RDAP (sucesor moderno de WHOIS) para el dominio."""
    url = RDAP_URL.format(domain=domain)
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        print(f"[!] RDAP respondio {resp.status_code} para {domain}", file=sys.stderr)
    except requests.RequestException as exc:
        print(f"[!] Error consultando RDAP: {exc}", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconocimiento pasivo OSINT (Practica 1 - UEM)")
    parser.add_argument("--domain", default="mapfre.com", help="Dominio objetivo")
    parser.add_argument("--output", help="Fichero donde volcar la lista de subdominios")
    args = parser.parse_args()

    print(f"[*] Reconocimiento pasivo sobre: {args.domain}\n")

    print("[*] Consultando Certificate Transparency logs (crt.sh)...")
    subdomains = enumerate_subdomains_crtsh(args.domain)
    print(f"[+] {len(subdomains)} subdominios unicos encontrados.\n")

    print("[*] Consultando RDAP...")
    rdap_data = query_rdap(args.domain)
    if rdap_data:
        print(f"[+] RDAP handle: {rdap_data.get('handle', 'N/D')}\n")

    for sub in sorted(subdomains):
        print(f"    - {sub}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(subdomains)))
        print(f"\n[+] Subdominios volcados en {args.output}")


if __name__ == "__main__":
    main()

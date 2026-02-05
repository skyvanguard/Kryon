#!/usr/bin/env python3
"""
KRYON First Operation Script
Automated reconnaissance and CTF solving

Clearance: Omega-Command
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from kryon.tools.autonomous import full_auto_enumeration


def print_banner():
    print("=" * 80)
    print("KRYON v3.3.0 - Primera Operacion Autonoma")
    print("=" * 80)
    print()


def run_reconnaissance(target_ip: str, deep: bool = False):
    """Execute reconnaissance operation."""
    print(f"📍 Target: {target_ip}")
    print(f"🔍 Modo: Reconocimiento {'Profundo' if deep else 'Rápido'}")
    print()
    print("🚀 Iniciando reconocimiento autónomo...")
    print()

    try:
        results = full_auto_enumeration(target_ip=target_ip, deep_scan=deep, timeout=1800 if deep else 600)

        # Mostrar resultados
        print()
        print("=" * 80)
        print("📊 RESULTADOS DEL RECONOCIMIENTO")
        print("=" * 80)
        print()

        # Puertos abiertos
        open_ports = results.get("open_ports", [])
        print(f"🔓 Puertos abiertos: {len(open_ports)}")
        if open_ports:
            for port in open_ports[:15]:
                print(f"   • Puerto {port}")
            if len(open_ports) > 15:
                print(f"   ... y {len(open_ports) - 15} más")
        print()

        # Servicios detectados
        services = results.get("services", [])
        print(f"🎯 Servicios detectados: {len(services)}")
        if services:
            for service in services[:10]:
                name = service.get("name", "unknown")
                port = service.get("port", "N/A")
                version = service.get("version", "")
                print(f"   • {name} en puerto {port} {version}")
            if len(services) > 10:
                print(f"   ... y {len(services) - 10} más")
        print()

        # Vulnerabilidades
        vulns = results.get("vulnerabilities", [])
        if vulns:
            print(f"⚠️  Vulnerabilidades potenciales: {len(vulns)}")
            for vuln in vulns[:5]:
                print(f"   • {vuln}")
            print()

        # Web endpoints
        web_paths = results.get("web_paths", [])
        if web_paths:
            print(f"🌐 Rutas web encontradas: {len(web_paths)}")
            for path in web_paths[:10]:
                print(f"   • {path}")
            print()

        # Guardar reporte
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"/workspace/results/operations/recon_{target_ip.replace('.', '_')}_{timestamp}.json"

        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        print("=" * 80)
        print(f"📄 Reporte guardado: {output_file}")
        print("=" * 80)
        print()

        # Resumen final
        print("✅ Operación de reconocimiento completada")
        print()

        return results

    except Exception as e:
        print()
        print("=" * 80)
        print(f"❌ Error durante la operación: {e}")
        print("=" * 80)
        print()
        import traceback

        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(
        description="KRYON First Operation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Reconocimiento rápido
  python3 first_operation.py --target 192.168.3.14

  # Reconocimiento profundo
  python3 first_operation.py --target 192.168.3.14 --deep

  # Reconocimiento de máquina remota
  python3 first_operation.py --target 10.10.10.5 --deep
        """,
    )

    parser.add_argument("--target", required=True, help="Target IP address")

    parser.add_argument("--deep", action="store_true", help="Enable deep scan (slower but more thorough)")

    args = parser.parse_args()

    print_banner()
    run_reconnaissance(args.target, args.deep)


if __name__ == "__main__":
    main()

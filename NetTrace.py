# ===============================
# NetTrace - Analizador de IPs
# Herramienta avanzada para análisis y reputación de direcciones IP
# Desarrollado por Tobías R. para uso personal y educativo
# ===============================
#
# Cómo está montado este archivo (por si hay que buscar algo):
#   1. Rutas, columnas del resultado y texto legal
#   2. Consola: limpiar pantalla, pegados raros, pausas
#   3. Animación de arranque
#   4. Claves de API (cargar / guardar)
#   5. ¿La IP vale? ¿Es privada?
#   6. Llamadas a AbuseIPDB, IPinfo y VPNAPI
#   7. Análisis y cómo se pintan los resultados
#   8. Excel (abrir y guardar)
#   9. Menús (configuración, analizar, ayuda)
#  10. Arranque del programa


import sys
import os
import re
import time
import json
import argparse
from datetime import datetime

import requests
import pandas as pd
import pycountry


# ===============================
# 1. CONFIGURACIÓN DE RUTAS Y ARCHIVOS EN EL PC
#    Todo vive en la carpeta NetTrace del usuario
# ===============================
USER_HOME = os.path.expanduser('~')
NETTRACE_DIR = os.path.join(USER_HOME, 'NetTrace')
APIS_CONFIG_FILE = os.path.join(NETTRACE_DIR, 'apis_config.json')
FIRST_RUN_FILE = os.path.join(NETTRACE_DIR, 'first_run.flag')
TERMINOS_FILE = os.path.join(NETTRACE_DIR, 'terminos_y_condiciones.txt')

# Columnas del resultado (pantalla y Excel). El orden es el que se muestra.
COLUMNS = [
    "IP", "Confianza Maliciosa", "Número de reportes (365 días)", "Última vez reportada",
    "Tipo de Uso", "ISP", "ASN", "Hostname", "Nombre del dominio", "Whitelisted (AbuseIPDB)",
    "Rango de Red (VPNAPI)", "Tor Detectado (AbuseIPDB)", "Tor Detectado (VPNAPI)",
    "VPN Detectado (VPNAPI)", "Proxy Detectado (VPNAPI)", "Relay Detectado (VPNAPI)",
    "Código país", "Nombre del país", "Ciudad", "Error"
]

TEXTO_TERMINOS = (
    "Copyright (c) 2025 Tobías R.\n"
    "Todos los derechos reservados.\n\n"
    "Este software ha sido desarrollado íntegramente por Tobías R. como proyecto personal, "
    "fuera del horario laboral y sin emplear recursos, infraestructura, asistencia o propiedad "
    "intelectual de empresa, institución u organización alguna. La totalidad del código es "
    "propiedad exclusiva del autor.\n\n"
    "Nota: Esta aplicación está concebida para utilizarse con las versiones gratuitas "
    "('free tier') de las APIs correspondientes. El funcionamiento óptimo del software requiere "
    "que el usuario configure sus propias claves gratuitas para cada servicio.\n\n"
    "1. DEFINICIÓN DE USO PERSONAL:\n"
    "   Se entiende por uso personal la instalación y ejecución de este software en un único "
    "equipo de propiedad del usuario. Bajo ningún concepto podrá emplearse como herramienta de "
    "empresa, entidad corporativa o institución, ni formar parte de procesos o sistemas laborales "
    "ajenos al ámbito privado.\n\n"
    "2. CONDICIONES DE USO:\n"
    "   Sin autorización previa y por escrito del autor, queda prohibido:\n"
    "   • El uso comercial, corporativo o institucional\n"
    "   • La utilización por parte de empresas, organizaciones o entidades gubernamentales\n"
    "   • La incorporación total o parcial del código en productos, servicios, plataformas o "
    "sistemas de terceros\n"
    "   • La redistribución, publicación o puesta a disposición del código en cualquier medio "
    "o repositorio, público o privado\n"
    "   • La modificación del código para crear proyectos derivados, adaptaciones, variantes, "
    "forks o reutilizaciones parciales\n"
    "   • El reempaquetado, renombramiento o presentación bajo o con otra autoría\n"
    "   • El empleo en cursos, capacitaciones, materiales académicos o de divulgación sin "
    "consentimiento expreso\n"
    "   • El uso como base técnica para desarrollos ajenos, incluso con fines no comerciales\n\n"
    "3. PERMISOS LIMITADOS:\n"
    "   Se concede únicamente permiso para:\n"
    "   • Configurar y utilizar claves de API propias (gratuitas) con fines locales y privados\n"
    "   • Ejecutar el software en su forma original, sin modificación ni redistribución\n"
    "   • Instalarlo en un único equipo de propiedad del usuario, sin sublicenciar ni ceder "
    "dichos permisos\n\n"
    "4. DURACIÓN DE LA LICENCIA Y REVOCACIÓN:\n"
    "   Vigencia indefinida, salvo revocación expresa del autor. Cualquier autorización o "
    "revocación deberá realizarse mediante comunicación escrita entregada en mano por el autor "
    "o persona autorizada.\n\n"
    "5. CLÁUSULA DE FUERZA MAYOR:\n"
    "   El autor no será responsable de daños, perjuicios, pérdidas ni costes indirectos o "
    "emergentes derivados de eventos fuera de su control razonable, incluidos, entre otros, "
    "fallos de red, interrupciones de servicios de terceros, desastres naturales, actos de "
    "autoridad o incidencias de infraestructura.\n\n"
    "6. RESPONSABILIDAD SOBRE CLAVES DE API:\n"
    "   El autor no asume responsabilidad por la gestión, seguridad, límites de uso, costes, "
    "cargos o sanciones asociadas a las claves de API configuradas por el usuario para "
    "servicios externos.\n\n"
    "7. JURISDICCIÓN Y LEY APLICABLE:\n"
    "   Esta licencia se rige e interpreta de conformidad con la legislación española vigente "
    "en materia de derechos de autor, sin perjuicio de normas imperativas en otras "
    "jurisdicciones. Cualquier disputa se someterá a los tribunales competentes de España.\n\n"
    "8. EXENCIÓN DE RESPONSABILIDAD:\n"
    "   El software se proporciona «tal cual», sin garantía de ningún tipo, expresa o implícita, "
    "incluyendo, entre otras, garantías de funcionamiento, idoneidad para un propósito "
    "específico o ausencia de errores. No se otorga derecho a reembolso de costes. En ningún "
    "caso el autor será responsable de daños, pérdidas o perjuicios directos o indirectos "
    "derivados del uso o imposibilidad de uso del software.\n"
)

if not os.path.exists(NETTRACE_DIR):
    os.makedirs(NETTRACE_DIR)


# ===============================
# 2. UTILIDADES DE CONSOLA / PRIMERA EJECUCIÓN
#    Limpiar pantalla, leer teclado y no liar el menú
#    cuando alguien pega varias líneas de golpe (Ctrl+V)
# ===============================
def es_primera_ejecucion():
    return not os.path.exists(FIRST_RUN_FILE)


def marcar_ejecucion_realizada():
    with open(FIRST_RUN_FILE, 'w', encoding='utf-8') as f:
        f.write('ok')


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def stdin_tiene_datos_pendientes(timeout=0.2):
    # True si todavía hay texto esperando (típico al pegar varias líneas).
    try:
        if sys.platform == 'win32':
            import msvcrt
            fin = time.time() + timeout
            while time.time() < fin:
                if msvcrt.kbhit():
                    return True
                time.sleep(0.01)
            return False
        import select
        return bool(select.select([sys.stdin], [], [], timeout)[0])
    except Exception:
        return False


def drenar_stdin_residual():
    # Tira lo que haya quedado de un pegado, para que no "pulse" el menú solo.
    while stdin_tiene_datos_pendientes(0.05):
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            break


def pause(msg="\nPresiona Enter para continuar..."):
    try:
        # Si quedó texto de un Ctrl+V anterior, no lo uses como "Enter"
        if stdin_tiene_datos_pendientes(0.05):
            drenar_stdin_residual()
        input(msg)
    except (EOFError, KeyboardInterrupt):
        print()


def leer_opcion(prompt, opciones_validas):
    while True:
        try:
            if stdin_tiene_datos_pendientes(0.05):
                drenar_stdin_residual()
            valor = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if valor in opciones_validas:
            return valor
        print(f"Opción no válida. Elige entre: {', '.join(opciones_validas)}")


def enmascarar_clave(clave):
    # En pantalla no enseñamos la clave entera, solo un recorte.
    if not clave:
        return "(vacía)"
    if len(clave) <= 8:
        return "*" * len(clave)
    return f"{clave[:4]}...{clave[-4:]}"


def ensure_console_on_windows():
    # Si se abre sin ventana (pythonw, doble clic raro), intentamos sacar una CMD.
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        if not kernel32.GetConsoleWindow():
            if kernel32.AttachConsole(-1) == 0:
                kernel32.AllocConsole()
            # Reabrir stdout/stderr/stdin hacia la consola
            sys.stdout = open('CONOUT$', 'w', encoding='utf-8', errors='replace')
            sys.stderr = open('CONOUT$', 'w', encoding='utf-8', errors='replace')
            sys.stdin = open('CONIN$', 'r', encoding='utf-8', errors='replace')
        # Colores / movimiento del cursor (la animación los necesita)
        try:
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except Exception:
            pass
    except Exception:
        pass


# ===============================
# 3. ANIMACIÓN ASCII DE INICIO (logo)
# ===============================
def _ir_inicio_cursor():
    # Sube el cursor arriba del todo, sin borrar (se ve más pro).
    sys.stdout.write('\033[H')
    sys.stdout.flush()


def animar_nettrace_fullscreen():
    # aparicion del logo, hace barrido  
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()

    try:
        ascii_art = [
            "   ███╗   ██╗███████╗████████╗████████╗██████╗  █████╗  ██████╗███████╗",
            "   ████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝",
            "   ██╔██╗ ██║█████╗     ██║      ██║   ██████╔╝███████║██║     █████╗  ",
            "   ██║╚██╗██║██╔══╝     ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ",
            "   ██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗",
            "   ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝╚══════╝",
        ]

        alt_terminal = 24
        num_lineas = len(ascii_art)
        ancho = max(len(line) for line in ascii_art)

        tiempo_aparicion = 1.0
        tiempo_hold = 1.0
        tiempo_desaparicion = 1.0
        fps = 60
        frames_aparicion = max(1, int(tiempo_aparicion * fps))
        frames_desaparicion = max(1, int(tiempo_desaparicion * fps))

        def pintar(lineas_visibles: float):
            _ir_inicio_cursor()
            enteras = int(lineas_visibles)
            fraccion = lineas_visibles - enteras
            espacio_arriba = max(0, (alt_terminal - num_lineas) // 2)
            buffer = []

            for _ in range(espacio_arriba):
                buffer.append(' ' * ancho)

            for j in range(num_lineas):
                if j < enteras:
                    buffer.append(ascii_art[j].ljust(ancho))
                elif j == enteras and fraccion > 0:
                    chars = max(1, int(len(ascii_art[j]) * fraccion))
                    buffer.append(ascii_art[j][:chars].ljust(ancho))
                else:
                    buffer.append(' ' * ancho)

            while len(buffer) < alt_terminal:
                buffer.append(' ' * ancho)

            sys.stdout.write('\n'.join(buffer[:alt_terminal]))
            sys.stdout.flush()

        clear_screen()

        t0 = time.perf_counter()
        for f in range(frames_aparicion + 1):
            progreso = f / frames_aparicion
            pintar(progreso * num_lineas)
            objetivo = t0 + (f / frames_aparicion) * tiempo_aparicion
            restante = objetivo - time.perf_counter()
            if restante > 0:
                time.sleep(restante)

        pintar(float(num_lineas))
        time.sleep(tiempo_hold)

        t1 = time.perf_counter()
        for f in range(frames_desaparicion + 1):
            progreso = 1.0 - (f / frames_desaparicion)
            pintar(progreso * num_lineas)
            objetivo = t1 + (f / frames_desaparicion) * tiempo_desaparicion
            restante = objetivo - time.perf_counter()
            if restante > 0:
                time.sleep(restante)

        clear_screen()

    finally:
        sys.stdout.write('\033[?25h')
        sys.stdout.flush()


# ===============================
# 4. CARGA / GUARDADO DE APIs
#    Se guardan en apis_config.json (no van en el código)
# ===============================
def cargar_apis_config():
    try:
        with open(APIS_CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def guardar_apis_config(data):
    try:
        with open(APIS_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error guardando configuración de APIs: {e}")


def recargar_claves_globales():
    # Por si se cambiaron las claves en otro menú y hay que refrescarlas.
    global ABUSEIPDB_API_KEY, IPINFO_API_KEY, VPNAPI_KEY
    cfg = cargar_apis_config()
    ABUSEIPDB_API_KEY = cfg.get('ABUSEIPDB_API_KEY', '')
    IPINFO_API_KEY = cfg.get('IPINFO_API_KEY', '')
    VPNAPI_KEY = cfg.get('VPNAPI_KEY', '')


apis_config = cargar_apis_config()
ABUSEIPDB_API_KEY = apis_config.get('ABUSEIPDB_API_KEY', '')
IPINFO_API_KEY = apis_config.get('IPINFO_API_KEY', '')
VPNAPI_KEY = apis_config.get('VPNAPI_KEY', '')


# ===============================
# 5. VALIDACIÓN Y UTILIDADES DE IP
#    Solo preguntará a las APIs por IPs públicas
# ===============================
def is_valid_ip(ip):
    # Cuatro números de 0 a 255, separados por puntos (IPv4).
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    try:
        return all(0 <= int(parte) <= 255 for parte in partes)
    except ValueError:
        return False


def is_private_or_reserved_ip(ip):
    # Estas no salen a internet de verdad (casa, pruebas, multicast, etc.).
    octetos = list(map(int, ip.split('.')))
    if octetos[0] == 0:
        return True
    if octetos[0] == 10:
        return True
    if octetos[0] == 100 and 64 <= octetos[1] <= 127:
        return True
    if octetos[0] == 127:
        return True
    if octetos[0] == 169 and octetos[1] == 254:
        return True
    if octetos[0] == 172 and 16 <= octetos[1] <= 31:
        return True
    if octetos[0] == 192 and octetos[1] == 0 and octetos[2] == 0:
        return True
    if octetos[0] == 192 and octetos[1] == 0 and octetos[2] == 2:
        return True
    if octetos[0] == 192 and octetos[1] == 31 and octetos[2] == 196:
        return True
    if octetos[0] == 192 and octetos[1] == 52 and octetos[2] == 193:
        return True
    if octetos[0] == 192 and octetos[1] == 88 and octetos[2] == 99:
        return True
    if octetos[0] == 192 and octetos[1] == 168:
        return True
    if octetos[0] == 192 and octetos[1] == 175 and octetos[2] == 48:
        return True
    if octetos[0] == 198 and 18 <= octetos[1] <= 19:
        return True
    if octetos[0] == 198 and octetos[1] == 51 and octetos[2] == 100:
        return True
    if octetos[0] == 203 and octetos[1] == 0 and octetos[2] == 113:
        return True
    if 224 <= octetos[0] <= 239:
        return True
    if 240 <= octetos[0] <= 254:
        return True
    if octetos[0] == 255 and octetos[1] == 255 and octetos[2] == 255 and octetos[3] == 255:
        return True
    return False


def get_country_name(alpha2):
    try:
        country = pycountry.countries.get(alpha_2=alpha2)
        return country.name if country else 'No disponible'
    except Exception:
        return 'No disponible'


def formatear_fecha_estandar(fecha_iso):
    if not fecha_iso or fecha_iso == 'Sin reportes':
        return 'Sin reportes'
    try:
        dt = datetime.fromisoformat(fecha_iso.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except Exception:
        return fecha_iso


# ===============================
# 6. CONSULTAS A APIs
#    AbuseIPDB = reputación / reportes
#    IPinfo    = país, ciudad, ISP
#    VPNAPI    = VPN, proxy, Tor, relay
# ===============================
def check_abuseipdb(ip):
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 365},
            timeout=10
        )
        r.raise_for_status()
        return r.json().get('data', {})
    except Exception as e:
        print(f"Error en check_abuseipdb para {ip}: {e}")
        return {}


def check_ipinfo(ip):
    try:
        r = requests.get(
            f'https://ipinfo.io/{ip}/json',
            params={'token': IPINFO_API_KEY},
            timeout=10
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Error en check_ipinfo para {ip}: {e}")
        return {}


def check_vpnapi(ip):
    try:
        r = requests.get(f'https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}', timeout=10)
        r.raise_for_status()
        response_data = r.json()
        network_data = response_data.get('network', {})
        network_range = network_data.get('network', 'No disponible') if isinstance(network_data, dict) else 'No disponible'
        security_data = response_data.get('security', {})
        security_data['network'] = network_range
        return security_data
    except Exception as e:
        print(f"Error en check_vpnapi para {ip}: {e}")
        return {}


def verificar_apis(abuse_key, ipinfo_key, vpnapi_key):
    # Prueba las tres claves con 8.8.8.8 (Google DNS) para ver si responden.
    resultados = []

    # --- AbuseIPDB ---
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': abuse_key, 'Accept': 'application/json'},
            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 30},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if 'errors' in data:
                mensaje = data['errors'][0].get('detail', 'Clave inválida o sin permisos')
                resultados.append(("AbuseIPDB", False, mensaje))
            elif 'data' in data:
                resultados.append(("AbuseIPDB", True, "Clave válida"))
            else:
                resultados.append(("AbuseIPDB", False, "Respuesta inesperada"))
        else:
            try:
                data = r.json()
                if 'errors' in data:
                    mensaje = data['errors'][0].get('detail', f"Error {r.status_code}")
                    resultados.append(("AbuseIPDB", False, mensaje))
                else:
                    resultados.append(("AbuseIPDB", False, f"Error {r.status_code}"))
            except Exception:
                resultados.append(("AbuseIPDB", False, f"Error {r.status_code}"))
    except Exception as e:
        resultados.append(("AbuseIPDB", False, f"Error: {e}"))

    # --- IPinfo ---
    if not ipinfo_key:
        resultados.append(("IPinfo", False, "No se ingresó clave"))
    else:
        try:
            r = requests.get(
                'https://ipinfo.io/8.8.8.8/json',
                params={'token': ipinfo_key},
                timeout=5
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('error'):
                    mensaje = data.get('error', {}).get('message', 'Clave inválida o sin permisos')
                    resultados.append(("IPinfo", False, mensaje))
                elif 'ip' in data:
                    resultados.append(("IPinfo", True, "Clave válida"))
                else:
                    resultados.append(("IPinfo", False, "Respuesta inesperada"))
            else:
                try:
                    data = r.json()
                    if data.get('error'):
                        mensaje = data.get('error', {}).get('message', f"Error {r.status_code}")
                        resultados.append(("IPinfo", False, mensaje))
                    else:
                        resultados.append(("IPinfo", False, f"Error {r.status_code}"))
                except Exception:
                    resultados.append(("IPinfo", False, f"Error {r.status_code}"))
        except Exception as e:
            resultados.append(("IPinfo", False, f"Error: {e}"))

    # --- VPNAPI.IO ---
    try:
        r = requests.get(f'https://vpnapi.io/api/8.8.8.8?key={vpnapi_key}', timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get('security') is not None:
                resultados.append(("VPNAPI.IO", True, "Clave válida"))
            elif data.get('message'):
                resultados.append(("VPNAPI.IO", False, data.get('message', 'Clave inválida o sin permisos')))
            else:
                resultados.append(("VPNAPI.IO", False, "Respuesta inesperada"))
        else:
            try:
                data = r.json()
                if data.get('message'):
                    resultados.append(("VPNAPI.IO", False, data.get('message', f"Error {r.status_code}")))
                else:
                    resultados.append(("VPNAPI.IO", False, f"Error {r.status_code}"))
            except Exception:
                resultados.append(("VPNAPI.IO", False, f"Error {r.status_code}"))
    except Exception as e:
        resultados.append(("VPNAPI.IO", False, f"Error: {e}"))

    return resultados


# ===============================
# 7. ANÁLISIS DE IPs
#    Se analizan las IPs una por una, se consulta a las APIs y se guardan los resultados en cache.
# ===============================
def analizar_ips(ips, delay=0.3):
    results = []
    cache = {}
    total = len(ips)

    for idx, ip in enumerate(ips, start=1):
        pct = int(idx / total * 100) if total else 100
        print(f"\rAnalizando... [{idx}/{total}] {pct}%", end='', flush=True)

        if ip in cache:
            # Misma IP otra vez: no gastamos otra consulta.
            results.append(cache[ip].copy())
        elif not is_valid_ip(ip):
            resultado = {'IP': ip, 'Error': 'IP no válida'}
            cache[ip] = resultado
            results.append(resultado)
        elif is_private_or_reserved_ip(ip):
            resultado = {'IP': ip, 'Error': 'IP privada o reservada'}
            cache[ip] = resultado
            results.append(resultado)
        else:
            ipinfo = check_ipinfo(ip)
            abuse = check_abuseipdb(ip)
            vpnsec = check_vpnapi(ip)

            country_code = ipinfo.get('country', 'No disponible')
            asn = ipinfo.get('asn', 'No disponible')
            if asn == 'No disponible' and 'org' in ipinfo and 'AS' in ipinfo['org']:
                asn = ipinfo['org'].split()[0]

            resultado = {
                'IP': ip,
                'Confianza Maliciosa': f"{abuse.get('abuseConfidenceScore', 'No disponible')}%",
                'Número de reportes (365 días)': (
                    abuse.get('totalReports') if abuse.get('totalReports') is not None else 'Sin reportes'
                ),
                'Última vez reportada': formatear_fecha_estandar(abuse.get('lastReportedAt') or 'Sin reportes'),
                'Tipo de Uso': abuse.get('usageType') or 'No disponible',
                'ISP': ipinfo.get('org') or abuse.get('isp') or 'No disponible',
                'ASN': asn or 'No disponible',
                'Hostname': (
                    abuse.get('hostnames', ['No disponible'])[0]
                    if abuse.get('hostnames') else 'No disponible'
                ),
                'Nombre del dominio': abuse.get('domain') or 'No disponible',
                'Whitelisted (AbuseIPDB)': "Sí" if abuse.get('isWhitelisted', False) else "No",
                'Rango de Red (VPNAPI)': vpnsec.get('network') or 'No disponible',
                'Tor Detectado (AbuseIPDB)': "Sí" if abuse.get('isTor', False) else "No",
                'Tor Detectado (VPNAPI)': "Sí" if vpnsec.get('tor', False) else "No",
                'VPN Detectado (VPNAPI)': "Sí" if vpnsec.get('vpn', False) else "No",
                'Proxy Detectado (VPNAPI)': "Sí" if vpnsec.get('proxy', False) else "No",
                'Relay Detectado (VPNAPI)': "Sí" if vpnsec.get('relay', False) else "No",
                'Código país': country_code or 'No disponible',
                'Nombre del país': get_country_name(country_code) or 'No disponible',
                'Ciudad': ipinfo.get('city') or 'No disponible',
                'Error': ''
            }
            cache[ip] = resultado
            results.append(resultado)
            time.sleep(delay)

    print()
    return results


def columnas_resultado(results):
    # La columna "Error" solo sale si alguna IP falló.
    mostrar_error = any(r.get('Error') for r in results)
    cols = [c for c in COLUMNS if c != 'Error']
    if mostrar_error:
        cols.append('Error')
    return cols


def _señales_anonimato(row):
    # Resumen corto para la tabla: Tor, VPN, Proxy, Relay.
    partes = []
    if row.get('Tor Detectado (AbuseIPDB)') == 'Sí' or row.get('Tor Detectado (VPNAPI)') == 'Sí':
        partes.append('Tor')
    if row.get('VPN Detectado (VPNAPI)') == 'Sí':
        partes.append('VPN')
    if row.get('Proxy Detectado (VPNAPI)') == 'Sí':
        partes.append('Proxy')
    if row.get('Relay Detectado (VPNAPI)') == 'Sí':
        partes.append('Relay')
    return ', '.join(partes) if partes else '-'


def _imprimir_bloque(titulo, pares):
    print()
    print(f"  --- {titulo} ---")
    print()
    for etiqueta, valor in pares:
        print(f"    {etiqueta}: {valor}")


def _texto_celda(valor, por_defecto='-'):
    texto = str(valor if valor not in (None, '') else por_defecto).strip()
    if texto == 'No disponible':
        return por_defecto
    return texto


def mostrar_resultados_texto(results):
    if not results:
        print("No hay resultados para mostrar.")
        return

    cols = columnas_resultado(results)
    total = len(results)

    # ----- RESUMEN (una línea por IP, anchos según contenido) -----
    print(f"\n=== RESUMEN ({total} IP{'s' if total != 1 else ''}) ===\n")

    filas_resumen = []
    for i, row in enumerate(results, start=1):
        error = (row.get('Error') or '').strip()
        if error:
            filas_resumen.append({
                'error': True,
                '#': str(i),
                'IP': _texto_celda(row.get('IP')),
                'msg': f"ERROR: {error}",
            })
            continue

        reportes = _texto_celda(row.get('Número de reportes (365 días)'))
        if reportes == 'Sin reportes':
            reportes = '0'

        filas_resumen.append({
            'error': False,
            '#': str(i),
            'IP': _texto_celda(row.get('IP')),
            'Confianza': _texto_celda(row.get('Confianza Maliciosa')),
            'Reportes': reportes,
            'País': _texto_celda(row.get('Nombre del país')),
            'Dominio': _texto_celda(row.get('Nombre del dominio')),
            'Uso': _texto_celda(row.get('Tipo de Uso')),
            'WL': _texto_celda(row.get('Whitelisted (AbuseIPDB)')),
            'Señales': _señales_anonimato(row),
        })

    claves = ['#', 'IP', 'Confianza', 'Reportes', 'País', 'Dominio', 'Uso', 'WL', 'Señales']
    anchos = {k: len(k) for k in claves}
    for fila in filas_resumen:
        if fila.get('error'):
            anchos['#'] = max(anchos['#'], len(fila['#']))
            anchos['IP'] = max(anchos['IP'], len(fila['IP']))
            continue
        for k in claves:
            anchos[k] = max(anchos[k], len(str(fila.get(k, ''))))

    cabecera = '  '.join(f"{k:<{anchos[k]}}" for k in claves)
    print(cabecera)
    print('-' * len(cabecera))

    for fila in filas_resumen:
        if fila.get('error'):
            print(f"{fila['#']:<{anchos['#']}}  {fila['IP']:<{anchos['IP']}}  {fila['msg']}")
            continue
        print('  '.join(f"{str(fila[k]):<{anchos[k]}}" for k in claves))

    # ----- DETALLE (todos los campos, agrupados) -----
    print("\n=== DETALLE ===\n")
    for i, row in enumerate(results, start=1):
        ip = row.get('IP', '')
        print('=' * 52)
        print(f"  #{i}  {ip}")
        print('=' * 52)

        error = (row.get('Error') or '').strip()
        if error:
            _imprimir_bloque('Error', [('Detalle', error)])
            # Si hay error, aún mostramos el resto de columnas presentes
            extras = [(c, row.get(c, '')) for c in cols if c not in ('IP', 'Error') and row.get(c, '') not in ('', None)]
            if extras:
                _imprimir_bloque('Otros datos', extras)
            print()
            continue

        _imprimir_bloque('Reputación', [
            ('Confianza Maliciosa', row.get('Confianza Maliciosa', '')),
            ('Número de reportes (365 días)', row.get('Número de reportes (365 días)', '')),
            ('Última vez reportada', row.get('Última vez reportada', '')),
            ('Whitelisted (AbuseIPDB)', row.get('Whitelisted (AbuseIPDB)', '')),
        ])
        _imprimir_bloque('Red / ISP', [
            ('Tipo de Uso', row.get('Tipo de Uso', '')),
            ('ISP', row.get('ISP', '')),
            ('ASN', row.get('ASN', '')),
            ('Hostname', row.get('Hostname', '')),
            ('Nombre del dominio', row.get('Nombre del dominio', '')),
            ('Rango de Red (VPNAPI)', row.get('Rango de Red (VPNAPI)', '')),
        ])
        _imprimir_bloque('Anonimato', [
            ('Tor Detectado (AbuseIPDB)', row.get('Tor Detectado (AbuseIPDB)', '')),
            ('Tor Detectado (VPNAPI)', row.get('Tor Detectado (VPNAPI)', '')),
            ('VPN Detectado (VPNAPI)', row.get('VPN Detectado (VPNAPI)', '')),
            ('Proxy Detectado (VPNAPI)', row.get('Proxy Detectado (VPNAPI)', '')),
            ('Relay Detectado (VPNAPI)', row.get('Relay Detectado (VPNAPI)', '')),
        ])
        _imprimir_bloque('Ubicación', [
            ('Código país', row.get('Código país', '')),
            ('Nombre del país', row.get('Nombre del país', '')),
            ('Ciudad', row.get('Ciudad', '')),
        ])

        # Cualquier columna futura / residual no listada arriba (no se pierde nada)
        ya_mostradas = {
            'IP', 'Confianza Maliciosa', 'Número de reportes (365 días)', 'Última vez reportada',
            'Tipo de Uso', 'ISP', 'ASN', 'Hostname', 'Nombre del dominio', 'Whitelisted (AbuseIPDB)',
            'Rango de Red (VPNAPI)', 'Tor Detectado (AbuseIPDB)', 'Tor Detectado (VPNAPI)',
            'VPN Detectado (VPNAPI)', 'Proxy Detectado (VPNAPI)', 'Relay Detectado (VPNAPI)',
            'Código país', 'Nombre del país', 'Ciudad', 'Error'
        }
        residuales = [(c, row.get(c, '')) for c in cols if c not in ya_mostradas]
        if residuales:
            _imprimir_bloque('Otros', residuales)

        if 'Error' in cols and row.get('Error'):
            _imprimir_bloque('Error', [('Detalle', row.get('Error', ''))])

        print()
        print()


# ===============================
# 8. EXCEL: GUARDAR Y ABRIR
# ===============================
def guardar_resultados_excel(results, path):
    cols = columnas_resultado(results)
    df = pd.DataFrame(results)
    # Asegura todas las columnas aunque alguna IP venga incompleta
    for col in cols:
        if col not in df.columns:
            df[col] = ''
    df = df[cols]

    path = os.path.abspath(path.strip().strip('"'))
    if not path.lower().endswith(('.xlsx', '.xls')):
        path += '.xlsx'

    # .xls antiguo requiere otros motores; forzamos .xlsx + openpyxl
    if path.lower().endswith('.xls') and not path.lower().endswith('.xlsx'):
        path = path[:-4] + '.xlsx'

    try:
        import openpyxl  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "Falta el paquete 'openpyxl' para guardar Excel. "
            "Instálalo con: python -m pip install openpyxl"
        ) from e

    carpeta = os.path.dirname(path)
    if carpeta and not os.path.isdir(carpeta):
        os.makedirs(carpeta, exist_ok=True)

    df.to_excel(path, index=False, engine='openpyxl')

    if not os.path.isfile(path):
        raise RuntimeError(f"No se creó el archivo en: {path}")

    return path


def elegir_ruta_guardar_excel(nombre_sugerido='resultados_nettrace.xlsx'):
    # Ventana del sistema para elegir dónde guardar el Excel. 
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        print("No se pudo abrir la ventana de guardado (tkinter no disponible).")
        try:
            return input("\nRuta para guardar resultados Excel: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print()
            return ''

    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes('-topmost', True)
    except Exception:
        pass
    try:
        path = filedialog.asksaveasfilename(
            title='Guardar resultados Excel',
            defaultextension='.xlsx',
            initialfile=nombre_sugerido,
            filetypes=[
                ('Excel (.xlsx)', '*.xlsx'),
                ('Todos los archivos', '*.*'),
            ]
        )
    finally:
        try:
            root.destroy()
        except Exception:
            pass
    return (path or '').strip()


def elegir_ruta_abrir_excel():
    # Ventana del sistema para elegir el Excel de entrada.
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        print("No se pudo abrir la ventana de selección (tkinter no disponible).")
        try:
            return input("\nRuta del archivo Excel (.xlsx / .xls): ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print()
            return ''

    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes('-topmost', True)
    except Exception:
        pass
    try:
        path = filedialog.askopenfilename(
            title='Seleccionar Excel con IPs',
            filetypes=[
                ('Excel (.xlsx)', '*.xlsx'),
                ('Excel (.xls)', '*.xls'),
                ('Todos los archivos', '*.*'),
            ]
        )
    finally:
        try:
            root.destroy()
        except Exception:
            pass
    return (path or '').strip()


def ofrecer_guardar_excel(results):
    # Después de resultados en texto plano, pregunta si queremos guardar el Excel.
    print("\n¿Quieres guardar estos resultados en Excel?")
    print("  1. Sí")
    print("  2. No")
    op = leer_opcion("\nElige: ", ['1', '2'])
    if op != '1':
        return

    print("\nElige dónde guardar el Excel...")
    path = elegir_ruta_guardar_excel()
    if not path:
        print("Guardado cancelado.")
        return

    try:
        guardado = guardar_resultados_excel(results, path)
        print(f"Resultados guardados en: {guardado}")
    except Exception as e:
        print(f"Error al guardar Excel: {e}")


# ===============================
# 9. CONFIGURACIÓN API
# ===============================
def menu_configuracion_api(forzar_primera=False):
    global ABUSEIPDB_API_KEY, IPINFO_API_KEY, VPNAPI_KEY

    clear_screen()
    print("=" * 50)
    print("  CONFIGURACIÓN DE APIs")
    print("=" * 50)

    if forzar_primera:
        print("\n¡Bienvenido a NetTrace!")
        print("Para comenzar, introduce tus claves de API.\n")

    recargar_claves_globales()
    print(f"AbuseIPDB actual : {enmascarar_clave(ABUSEIPDB_API_KEY)}")
    print(f"IPinfo actual    : {enmascarar_clave(IPINFO_API_KEY)}")
    print(f"VPNAPI.IO actual : {enmascarar_clave(VPNAPI_KEY)}")
    print()
    print("  1. Editar / Guardar claves")
    print("  2. Verificar APIs")
    print("  0. Volver")
    print()

    op = leer_opcion("Elige una opción: ", ['0', '1', '2'])
    if op is None or op == '0':
        return

    if op == '1':
        print("\nDeja vacío un campo para mantener el valor actual.\n")
        print("AbuseIPDB API Key")
        print("  Permite consultar la reputación y reportes de una IP sospechosa")
        abuse = input(f"  Nueva clave [{enmascarar_clave(ABUSEIPDB_API_KEY)}]: ").strip()

        print("\nIPinfo API Key")
        print("  Permite obtener información de geolocalización y ASN de una IP")
        ipinfo = input(f"  Nueva clave [{enmascarar_clave(IPINFO_API_KEY)}]: ").strip()

        print("\nVPNAPI.IO API Key")
        print("  Permite detectar si una IP usa VPN, proxy, Tor o relay")
        vpnapi = input(f"  Nueva clave [{enmascarar_clave(VPNAPI_KEY)}]: ").strip()

        if abuse:
            ABUSEIPDB_API_KEY = abuse
        if ipinfo:
            IPINFO_API_KEY = ipinfo
        if vpnapi:
            VPNAPI_KEY = vpnapi

        guardar_apis_config({
            'ABUSEIPDB_API_KEY': ABUSEIPDB_API_KEY,
            'IPINFO_API_KEY': IPINFO_API_KEY,
            'VPNAPI_KEY': VPNAPI_KEY
        })
        try:
            marcar_ejecucion_realizada()
        except Exception as e:
            print(f"Error al marcar la primera ejecución: {e}")

        print("\n¡Las claves han sido guardadas!")
        pause()
        return

    if op == '2':
        print("\nVerificando APIs (puede tardar unos segundos)...")
        resultados = verificar_apis(ABUSEIPDB_API_KEY, IPINFO_API_KEY, VPNAPI_KEY)
        print()
        for nombre, ok, mensaje in resultados:
            estado = "OK" if ok else "ERROR"
            print(f"  [{estado}] {nombre}: {mensaje}")
        pause()


# ===============================
# 10. MENÚ: ANALIZAR IPs
# ===============================
# Saca IPv4 de un pegado sucio, p. ej. "Taiwan\n198.235.24.56"
# Extrae la IPv4 de un pegado sucio (con más elementos que no son una IP) p. ej. "*Taiwan\n198.235.24.56"
IP_V4_RE = re.compile(
    r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)'
)


def leer_texto_entrada_ips():
    # Lee lo que escribe el usuario. Si pega varias líneas, las recoge todas.
    print("\nIntroduce una o varias IPs (espacios, tabs, comas o varias líneas)")
    try:
        lineas = [input("IPs: ")]
    except (EOFError, KeyboardInterrupt):
        print()
        return ''

    # Pegado multilínea: la 1ª línea cierra input(); el resto queda en el buffer
    while stdin_tiene_datos_pendientes(0.2):
        try:
            extra = input()
        except (EOFError, KeyboardInterrupt):
            break
        if extra.strip() == '':
            break
        lineas.append(extra)

    return '\n'.join(lineas)


def obtener_ips_manual():
    texto = leer_texto_entrada_ips().strip()
    if not texto:
        return []

    # 1) Extraer IPv4 del texto completo (soporta pegados con país/texto extra)
    encontradas = IP_V4_RE.findall(texto)
    if encontradas:
        return encontradas

    # 2) Fallback como la GUI: separar por espacios/comas
    ips = re.split(r'[\s,]+', texto)
    return [ip for ip in ips if ip]


def obtener_ips_excel():
    print("\nElige el Excel con las IPs...")
    path = elegir_ruta_abrir_excel()
    if not path:
        print("Selección cancelada.")
        return []

    if not os.path.isfile(path):
        print("Archivo no encontrado.")
        return []

    try:
        df = pd.read_excel(path)
    except Exception as e:
        print(f"Error leyendo Excel: {e}")
        return []

    columnas = list(df.columns)
    if not columnas:
        print("El Excel no tiene columnas.")
        return []

    print("\nColumnas disponibles:")
    for i, col in enumerate(columnas, start=1):
        print(f"  {i}. {col}")

    while True:
        try:
            sel = input("Elige el número de la columna con las IPs: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []
        if sel.isdigit() and 1 <= int(sel) <= len(columnas):
            col = columnas[int(sel) - 1]
            break
        print("Selección no válida.")

    return [str(x).strip() for x in df[col].dropna() if str(x).strip()]


def menu_analizar_ips():
    clear_screen()
    print("=" * 50)
    print("  ANALIZAR IPs")
    print("=" * 50)

    recargar_claves_globales()
    if not any([ABUSEIPDB_API_KEY, IPINFO_API_KEY, VPNAPI_KEY]):
        print("\nNo hay claves de API configuradas.")
        print("Ve primero a 'Configuración API'.")
        pause()
        return

    print("\nFormato de entrada:")
    print("  1. Introducir IPs en texto plano")
    print("  2. Excel")
    print("  0. Volver")
    entrada = leer_opcion("\nElige: ", ['0', '1', '2'])
    if entrada is None or entrada == '0':
        return

    print("\nFormato de salida:")
    print("  1. Mostrar resultados de IPs en texto plano")
    print("  2. Excel")
    print("  0. Volver")
    salida = leer_opcion("\nElige: ", ['0', '1', '2'])
    if salida is None or salida == '0':
        return

    if entrada == '1':
        ips = obtener_ips_manual()
    else:
        ips = obtener_ips_excel()

    if not ips:
        print("No se encontraron IPs válidas.")
        pause()
        return

    hay_publica = any(is_valid_ip(ip) and not is_private_or_reserved_ip(ip) for ip in ips)
    if not hay_publica:
        print("La lista solo contiene IPs privadas o no válidas. No se realizará el análisis.")
        pause()
        return

    print(f"\nSe analizarán {len(ips)} IP(s)...")
    try:
        results = analizar_ips(ips)
    except KeyboardInterrupt:
        print("\nAnálisis cancelado.")
        pause()
        return

    if salida == '1':
        mostrar_resultados_texto(results)
        ofrecer_guardar_excel(results)
    else:
        print("\nElige dónde guardar el Excel...")
        path = elegir_ruta_guardar_excel()
        if not path:
            print("Guardado cancelado. Mostrando en texto plano.")
            mostrar_resultados_texto(results)
            ofrecer_guardar_excel(results)
        else:
            try:
                guardado = guardar_resultados_excel(results, path)
                print(f"Resultados guardados en: {guardado}")
            except Exception as e:
                print(f"Error al guardar Excel: {e}")
                print("Mostrando resultados en texto plano:")
                mostrar_resultados_texto(results)
                ofrecer_guardar_excel(results)

    pause()


# ===============================
# 11. MENÚ: AYUDA
# ===============================
def mostrar_info_ayuda():
    print("\n--- Información ---")
    print("NetTrace")
    print()
    print("Herramienta orientada al análisis de IPs, para uso exclusivo personal")
    print("y sin propósitos comerciales.")


def mostrar_atajos_ayuda():
    print("\n--- Comandos / Atajos ---")
    print("  (sin argumentos)     Menú interactivo (inicio automático)")
    print("  configurar           Abrir configuración de APIs")
    print("  analizar             Analizar IPs")
    print("  ayuda                Menú de ayuda")
    print("  1 / 2 / 3 / 0        Opciones del menú interactivo")
    print()
    print("Ejemplos:")
    print("  python NetTrace.py")
    print("  python NetTrace.py configurar")
    print("  python NetTrace.py analizar")


def mostrar_terminos_condiciones():
    if not os.path.exists(TERMINOS_FILE):
        try:
            with open(TERMINOS_FILE, 'w', encoding='utf-8') as f:
                f.write(TEXTO_TERMINOS)
        except Exception as e:
            print(f"No se pudo crear el archivo de términos y condiciones: {e}")
            return

    print(f"\nArchivo de términos: {TERMINOS_FILE}")
    print("\n¿Cómo quieres verlos?")
    print("  1. Abrir con el editor del sistema")
    print("  2. Mostrar aquí en consola")
    print("  0. Volver")
    op = leer_opcion("\nElige: ", ['0', '1', '2'])
    if op is None or op == '0':
        return

    if op == '1':
        try:
            if sys.platform.startswith('win'):
                os.startfile(TERMINOS_FILE)
            elif sys.platform.startswith('darwin'):
                import subprocess
                subprocess.Popen(['open', TERMINOS_FILE])
            else:
                import subprocess
                subprocess.Popen(['xdg-open', TERMINOS_FILE])
            print("Archivo abierto.")
        except Exception as e:
            print(f"No se pudo abrir el archivo: {e}")
            print("\n" + TEXTO_TERMINOS)
    else:
        print("\n" + TEXTO_TERMINOS)


def menu_ayuda():
    while True:
        clear_screen()
        print("=" * 50)
        print("  AYUDA")
        print("=" * 50)
        print("  1. Información")
        print("  2. Atajos / Comandos")
        print("  3. Términos y condiciones")
        print("  0. Volver")
        print()
        op = leer_opcion("Elige una opción: ", ['0', '1', '2', '3'])
        if op is None or op == '0':
            return
        if op == '1':
            mostrar_info_ayuda()
            pause()
        elif op == '2':
            mostrar_atajos_ayuda()
            pause()
        elif op == '3':
            mostrar_terminos_condiciones()
            pause()


# ===============================
# 12. MENÚ PRINCIPAL + INICIO AUTOMÁTICO
# ===============================
def menu_principal():
    while True:
        clear_screen()
        print("=" * 50)
        print("  NetTrace - Analizador de IPs")
        print("=" * 50)
        print("  1. Analizar IPs")
        print("  2. Configuración API")
        print("  3. Ayuda")
        print("  0. Salir")
        print()
        op = leer_opcion("Elige una opción: ", ['0', '1', '2', '3'])
        if op is None or op == '0':
            print("Hasta luego.")
            break
        if op == '1':
            menu_analizar_ips()
        elif op == '2':
            menu_configuracion_api()
        elif op == '3':
            menu_ayuda()


def inicio_automatico():
    # Arranque al hacer doble clic o ejecutar sin argumentos
    try:
        animar_nettrace_fullscreen()
    except Exception:
        # Si la animación falla (consola limitada), seguimos al menú
        clear_screen()

    if es_primera_ejecucion():
        clear_screen()
        print("=" * 50)
        print("  ¡Bienvenido a NetTrace!")
        print("=" * 50)
        print("\nGracias por instalar NetTrace")
        print("Para comenzar, introduce tus claves de API.\n")
        pause("Presiona Enter para continuar a Configuración API...")
        menu_configuracion_api(forzar_primera=True)
        if es_primera_ejecucion():
            # Si salió sin guardar, aún así permitir usar el menú
            print("\nPuedes configurar las APIs más tarde desde el menú.")
            pause()
    menu_principal()


def parse_args():
    parser = argparse.ArgumentParser(
        prog='NetTrace',
        description='NetTrace - Analizador de IPs por línea de comandos',
        add_help=True
    )
    parser.add_argument(
        'comando',
        nargs='?',
        default=None,
        choices=['configurar', 'analizar', 'ayuda', 'menu'],
        help='Comando directo: configurar | analizar | ayuda | menu'
    )
    return parser.parse_args()


def main():
    ensure_console_on_windows()
    args = parse_args()

    try:
        if args.comando is None or args.comando == 'menu':
            inicio_automatico()
        elif args.comando == 'configurar':
            menu_configuracion_api()
        elif args.comando == 'analizar':
            menu_analizar_ips()
        elif args.comando == 'ayuda':
            menu_ayuda()
    except KeyboardInterrupt:
        print("\n\nCancelado por el usuario.")
    finally:
        # Evita que la ventana CMD se cierre al instante al hacer doble clic
        if sys.platform == 'win32' and not sys.stdin.closed:
            try:
                # Solo pausar al salir si parece sesión "doble clic" (sin TTY padre claro)
                # En la práctica, al terminar siempre damos una pausa suave si no hay args de pipe
                if sys.stdin.isatty():
                    input("\nPresiona Enter para cerrar...")
            except Exception:
                pass


if __name__ == "__main__":
    main()

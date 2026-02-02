# ===============================
# NetTrace - Analizador de IPs
# Herramienta avanzada para análisis y reputación de direcciones IP
# Desarrollado por Tobías R. para uso personal y educativo
# ===============================

# ===============================
# IMPORTACIONES DE LIBRERÍAS
# - Módulos estándar de Python (sys, os, re, time, json, base64, datetime, ctypes)
# - Librerías externas para análisis y GUI: requests, pandas, pycountry, PySide6
# ===============================
import sys
import re
import time
import requests
import pandas as pd
import pycountry
from datetime import datetime
import ctypes
import json
import base64
from PySide6.QtGui import QIcon, QPixmap, QCursor, QPalette, QColor
from PySide6.QtWidgets import QToolTip

from PySide6.QtCore import QObject, Signal, QThread, QPropertyAnimation, QEasingCurve, QPoint, Qt, QTimer, QEvent, Property, QVariantAnimation
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QComboBox, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QProgressBar, QDialog, QInputDialog, QHeaderView, QGraphicsOpacityEffect, QStackedWidget,
    QSizePolicy, QStyledItemDelegate, QToolButton, QFrame, QGraphicsDropShadowEffect, QProxyStyle, QStyle, QStyleOptionViewItem, QFormLayout, QProxyStyle, QStyleOptionFrame, QTextEdit
)
from PySide6.QtGui import QBrush, QPainter, QColor, QPen, QFont, QLinearGradient, QKeySequence, QShortcut
from PySide6.QtWidgets import QMenu
from PySide6.QtGui import QAction
import os

# ===============================
# CONFIGURACIÓN DE RUTAS Y ARCHIVOS DE LA APLICACIÓN
# - Se define la ruta del directorio de usuario y la carpeta de configuración 'NetTrace'.
# - El archivo 'apis_config.json' almacena las claves de las APIs necesarias para el análisis de IPs.
# ===============================
USER_HOME = os.path.expanduser('~')
NETTRACE_DIR = os.path.join(USER_HOME, 'NetTrace')
APIS_CONFIG_FILE = os.path.join(NETTRACE_DIR, 'apis_config.json')

# --- Archivo de primera ejecución ---
FIRST_RUN_FILE = os.path.join(NETTRACE_DIR, 'first_run.flag')

def es_primera_ejecucion():
    return not os.path.exists(FIRST_RUN_FILE)

def marcar_ejecucion_realizada():
    with open(FIRST_RUN_FILE, 'w') as f:
        f.write('ok')

# ===============================
# CREACIÓN AUTOMÁTICA DE LA CARPETA DE CONFIGURACIÓN
# - Si la carpeta 'NetTrace' no existe en el directorio del usuario, se crea automáticamente.
# - Esto asegura que siempre haya un lugar para guardar la configuración de las APIs.
# ===============================
if not os.path.exists(NETTRACE_DIR):
    os.makedirs(NETTRACE_DIR)

# ===============================
# FUNCIONES PARA CARGAR Y GUARDAR LA CONFIGURACIÓN DE LAS APIS
# - cargar_apis_config(): Lee el archivo de configuración y devuelve un diccionario con las claves de las APIs.
#   Si el archivo no existe o hay un error, devuelve un diccionario vacío.
# - guardar_apis_config(data): Guarda el diccionario de claves de APIs en el archivo de configuración en formato JSON.
# ===============================
def cargar_apis_config():
    try:
        with open(APIS_CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except Exception:
        return {}

def guardar_apis_config(data):
    try:
        with open(APIS_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error guardando configuración de APIs: {e}")

# ===============================
# CARGA DE CLAVES DE API DESDE ARCHIVO DE CONFIGURACIÓN
# - Si existen claves guardadas, se usan; si no, se asignan valores por defecto (pueden ser de prueba o placeholders).
# - Estas claves se utilizan para autenticar las peticiones a las APIs externas.
# ===============================
apis_config = cargar_apis_config()
ABUSEIPDB_API_KEY = apis_config.get('ABUSEIPDB_API_KEY', '')
IPINFO_API_KEY   = apis_config.get('IPINFO_API_KEY', '')
VPNAPI_KEY       = apis_config.get('VPNAPI_KEY', '')

# ===============================
# DEFINICIÓN DE ESTILOS PARA LA INTERFAZ GRÁFICA (QT)
# - common_style: Estilo oscuro por defecto para widgets principales (combobox, lineedit, botones, etc.)
# - light_style:  Estilo claro (modo día) alternativo para los mismos widgets.
# ===============================
common_style = """
QComboBox, QLineEdit, QPushButton, QGroupBox {
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    color: rgb(242,242,247);
    padding: 0px 15px;
    border: 1px solid #0e0e0e;
    border-radius: 6px;
    background: rgb(22,20,20);
    min-height: 28px;
    max-height: 28px;
    selection-background-color: transparent;
    selection-color: rgb(242,242,247);
}
QGroupBox {
    border: none;
    margin-top: 10px;
    background: transparent;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top center;
    background: transparent;
    color: rgb(242,242,247);
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
    font-weight: bold;
    padding: 0 3px;
}
QComboBox::drop-down {
    width: 0;
    border: none;
    background: none;
}
QComboBox QAbstractItemView {
    background: #161414;
    color: #f2f2f7;
    border-radius: 6px;
    border: 1px solid(32, 32, 32);
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    selection-background-color: transparent;
    selection-color: #fff;
    outline: none;
}
QComboBox QAbstractItemView::item {
    padding: 6px 0px;
    border: none;
    text-align: center;
}
QComboBox QAbstractItemView::item:hover {
    background: #232323;
    color: #fff;
}
QComboBox:focus, QLineEdit:focus {
    border: 1px solid rgb(32, 32, 32);
}
QComboBox:hover, QLineEdit:hover {
    border: 1px solid rgb(32, 32, 32);
}
"""

# --- NUEVO: Estilo claro (modo día) ---
light_style = """
QComboBox, QLineEdit, QPushButton, QGroupBox {
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    color: #222;
    padding: 0px 15px;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    background: rgb(224, 224, 224);
    min-height: 28px;
    max-height: 28px;
    selection-background-color:transparent;
    selection-color: #222;
}
QGroupBox {
    border: none;
    margin-top: 10px;
    background: transparent;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top center;
    background: transparent;
    color: #222;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
    font-weight: bold;
    padding: 0 3px;
}
QComboBox::drop-down {
    width: 0;
    border: none;
    background: none;
}
QComboBox QAbstractItemView {
    background: rgb(224, 224, 224);  /* Igual que el combobox cerrado */
    color: #222;
    border-radius: 6px;
    /* border: 1px solid #bdbdbd;  <-- Eliminado el borde */
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    selection-background-color: transparent;
    selection-color: #222;
    outline: none;
}
QComboBox QAbstractItemView::item {
    padding: 6px 0px;
    border: none;
    text-align: center;
}
QComboBox QAbstractItemView::item:hover {
    background: #f0f0f0;
    color: #222;
}
QComboBox:focus, QLineEdit:focus {
    border: 1px solid rgb(170, 170, 170);
}
QComboBox:hover, QLineEdit:hover {
    border: 1px solid rgb(170, 170, 170);
}
"""

# ===============================
# UTILIDADES DE VALIDACIÓN Y CONVERSIÓN DE IPs
# - Funciones para validar el formato de una IP, detectar si es privada/reservada,
#   y obtener el nombre de país a partir de un código.
# ===============================

# Comprueba si una cadena tiene formato IPv4 válido (cuatro octetos entre 0 y 255).
# Devuelve True si la IP es válida, False en caso contrario.
def is_valid_ip(ip):
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    try:
        return all(0 <= int(parte) <= 255 for parte in partes)
    except ValueError:
        return False

# Determina si una IP es privada, reservada o especial según los rangos definidos por IANA.
# Devuelve True si la IP pertenece a alguno de estos rangos, False si es pública.
# Útil para filtrar IPs que no deben analizarse en servicios públicos.
def is_private_or_reserved_ip(ip):
    octetos = list(map(int, ip.split('.')))
    if octetos[0] == 0:
        return True  # 0.0.0.0/8 (red local, no enrutable)
    if octetos[0] == 10:
        return True  # 10.0.0.0/8 (privada)
    if octetos[0] == 100 and 64 <= octetos[1] <= 127:
        return True  # 100.64.0.0/10 (CGNAT)
    if octetos[0] == 127:
        return True  # 127.0.0.0/8 (loopback)
    if octetos[0] == 169 and octetos[1] == 254:
        return True  # 169.254.0.0/16 (APIPA)
    if octetos[0] == 172 and 16 <= octetos[1] <= 31:
        return True  # 172.16.0.0/12 (privada)
    if octetos[0] == 192 and octetos[1] == 0 and octetos[2] == 0:
        return True  # 192.0.0.0/24 (reserva)
    if octetos[0] == 192 and octetos[1] == 0 and octetos[2] == 2:
        return True  # 192.0.2.0/24 (documentación)
    if octetos[0] == 192 and octetos[1] == 31 and octetos[2] == 196:
        return True  # 192.31.196.0/24 (reserva)
    if octetos[0] == 192 and octetos[1] == 52 and octetos[2] == 193:
        return True  # 192.52.193.0/24 (reserva)
    if octetos[0] == 192 and octetos[1] == 88 and octetos[2] == 99:
        return True  # 192.88.99.0/24 (reserva)
    if octetos[0] == 192 and octetos[1] == 168:
        return True  # 192.168.0.0/16 (privada)
    if octetos[0] == 192 and octetos[1] == 175 and octetos[2] == 48:
        return True  # 192.175.48.0/24 (reserva)
    if octetos[0] == 198 and 18 <= octetos[1] <= 19:
        return True  # 198.18.0.0/15 (pruebas de benchmark)
    if octetos[0] == 198 and octetos[1] == 51 and octetos[2] == 100:
        return True  # 198.51.100.0/24 (documentación)
    if octetos[0] == 203 and octetos[1] == 0 and octetos[2] == 113:
        return True  # 203.0.113.0/24 (documentación)
    if 224 <= octetos[0] <= 239:
        return True  # 224.0.0.0/4 (multicast)
    if 240 <= octetos[0] <= 254:
        return True  # 240.0.0.0/4 (reservado para futuro)
    if octetos[0] == 255 and octetos[1] == 255 and octetos[2] == 255 and octetos[3] == 255:
        return True  # 255.255.255.255/32 (broadcast)
    return False

# Convierte un código de país (ISO alpha-2) en el nombre completo del país en inglés.
# Si el código no es válido o no se encuentra, devuelve 'No disponible'.
# Útil para mostrar información geográfica legible en la interfaz.
def get_country_name(alpha2):
    try:
        country = pycountry.countries.get(alpha_2=alpha2)
        return country.name if country else 'No disponible'
    except Exception:
        return 'No disponible'

# ===============================
# FUNCIONES DE CONSULTA A SERVICIOS EXTERNOS (APIs)
# - Encapsulan las llamadas HTTP a las APIs de reputación, geolocalización y detección de VPN/proxy.
# - Devuelven diccionarios con la información relevante para el análisis de IPs.
# ===============================

# Consulta la API de AbuseIPDB para obtener la reputación y reportes de una IP.
# Devuelve un diccionario con los datos principales (confianza, reportes, uso, etc.).
# Si ocurre un error en la petición, devuelve un diccionario vacío y muestra el error por consola.
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

# Consulta la API de IPinfo para obtener información de geolocalización, ASN y organización de una IP.
# Devuelve un diccionario con los datos obtenidos (país, ciudad, ASN, etc.).
# Si ocurre un error, devuelve un diccionario vacío y muestra el error por consola.
def check_ipinfo(ip):
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', params={'token': IPINFO_API_KEY}, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Error en check_ipinfo para {ip}: {e}")
        return {}

# Consulta la API de VPNAPI.IO para detectar si una IP utiliza VPN, proxy, Tor o relay.
# Devuelve un diccionario con los indicadores de seguridad y el rango de red asociado.
# Si ocurre un error, devuelve un diccionario vacío y muestra el error por consola.
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

# ===============================
# WORKER DE ANÁLISIS EN SEGUNDO PLANO (THREAD)
# - Permite procesar grandes listas de IPs sin bloquear la interfaz gráfica (GUI).
# - Utiliza señales para informar del progreso y devolver los resultados al finalizar.
# ===============================

# Clase que ejecuta el análisis de IPs en un hilo separado.
# Recibe una lista de IPs y consulta las APIs para cada una, construyendo un resultado detallado.
# Señales:
#   - progress: emite el progreso actual (índice, total)
#   - finished: emite la lista de resultados al terminar
class AnalyzerWorker(QObject):
    progress = Signal(int, int)
    finished = Signal(list)

    # ips: lista de direcciones IP a analizar
    # batch_size: tamaño de lote para procesar (no usado en la versión actual, reservado para mejoras)
    # delay: retardo (en segundos) entre peticiones para evitar bloqueos o límites de las APIs
    def __init__(self, ips, batch_size=50, delay=0.3):
        super().__init__()
        self.ips = ips
        self.batch_size = batch_size
        self.delay = delay
        self.cache = {}  # Caché para evitar consultas repetidas de la misma IP

    # Método principal que realiza el análisis de cada IP:
    # - Valida el formato y si es pública
    # - Consulta las APIs externas y recopila los datos relevantes
    # - Emite el progreso tras cada IP y, al final, la lista completa de resultados
    def run(self):
        results = []
        total = len(self.ips)
        try:
            for idx, ip in enumerate(self.ips, start=1):
                if ip in self.cache:
                    results.append(self.cache[ip].copy())
                elif not is_valid_ip(ip):
                    resultado = {'IP': ip, 'Error': 'IP no válida'}
                    self.cache[ip] = resultado
                    results.append(resultado)
                elif is_private_or_reserved_ip(ip):
                    resultado = {'IP': ip, 'Error': 'IP privada o reservada'}
                    self.cache[ip] = resultado
                    results.append(resultado)
                else:
                    ipinfo = check_ipinfo(ip)
                    abuse  = check_abuseipdb(ip)
                    vpnsec = check_vpnapi(ip)

                    country_code = ipinfo.get('country', 'No disponible')
                    asn = ipinfo.get('asn', 'No disponible')
                    if asn == 'No disponible' and 'org' in ipinfo and 'AS' in ipinfo['org']:
                        asn = ipinfo['org'].split()[0]

                    resultado = {
                        'IP': ip,
                        'Confianza Maliciosa': f"{abuse.get('abuseConfidenceScore','No disponible')}%",
                        'Número de reportes (365 días)': abuse.get('totalReports') if abuse.get('totalReports') is not None else 'Sin reportes',
                        'Última vez reportada': formatear_fecha_estandar(abuse.get('lastReportedAt') or 'Sin reportes'),
                        'Tipo de Uso': abuse.get('usageType') or 'No disponible',
                        'ISP': ipinfo.get('org') or abuse.get('isp') or 'No disponible',
                        'ASN': asn or 'No disponible',
                        'Hostname': (abuse.get('hostnames', ['No disponible'])[0] if abuse.get('hostnames') else 'No disponible'),
                        'Nombre del dominio': abuse.get('domain') or 'No disponible',
                        'Whitelisted (AbuseIPDB)': "Sí" if abuse.get('isWhitelisted', False) else "No",
                        'Rango de Red (VPNAPI)': vpnsec.get('network') or 'No disponible',
                        'Tor Detectado (AbuseIPDB)': "Sí" if abuse.get('isTor',False) else "No",
                        'Tor Detectado (VPNAPI)': "Sí" if vpnsec.get('tor',False) else "No",
                        'VPN Detectado (VPNAPI)': "Sí" if vpnsec.get('vpn',False) else "No",
                        'Proxy Detectado (VPNAPI)': "Sí" if vpnsec.get('proxy',False) else "No",
                        'Relay Detectado (VPNAPI)': "Sí" if vpnsec.get('relay',False) else "No",
                        'Código país': country_code or 'No disponible',
                        'Nombre del país': get_country_name(country_code) or 'No disponible',
                        'Ciudad': ipinfo.get('city') or 'No disponible',
                        'Error': ''
                    }
                    self.cache[ip] = resultado
                    results.append(resultado)
                    time.sleep(self.delay)
                self.progress.emit(idx, total)
        except Exception as e:
            print(f"Error inesperado en el worker: {e}")
        finally:
            self.finished.emit(results)

# ===============================
# PANTALLA DE CARGA CIRCULAR ANIMADA (CircularProgress)
# - Ventana flotante y transparente que muestra el progreso de análisis largos.
# - Incluye animaciones de entrada/salida y adaptación a modo claro/oscuro.
# - Se utiliza para mejorar la experiencia de usuario durante operaciones en background.
# ===============================

# Clase que implementa una pantalla de carga circular con animación de progreso y opacidad.
# Se muestra centrada sobre la ventana principal mientras se realiza el análisis de IPs.
# Permite personalización visual según el modo (claro/oscuro) y animaciones suaves.
class CircularProgress(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(220, 220)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

        # Estado de progreso y opacidad
        self.progress = 0
        self.target_progress = 0  # Nuevo: progreso objetivo
        self.opacity = 0.0
        self.setWindowOpacity(self.opacity)

        # Temporizadores para animaciones de entrada y salida
        self.fade_in_timer = QTimer(self)
        self.fade_in_timer.timeout.connect(self.fade_in)
        self.fade_in_timer.start(40)
        self.fade_out_timer = None  # Añadido para gestionar el timer de fade-out

        # Temporizador para animar el avance del progreso
        self.progress_timer = QTimer(self)  # Nuevo: timer para animar el progreso
        self.progress_timer.timeout.connect(self._animate_progress)

        # Adaptación a modo claro/oscuro según la ventana principal
        self.modo_dia = False
        if parent is not None and hasattr(parent, 'modo_dia'):
            self.modo_dia = parent.modo_dia

    # Animación de entrada (fade-in) de la ventana
    def fade_in(self):
        self.opacity += 0.04
        if self.opacity >= 1.0:
            self.opacity = 1.0
            self.fade_in_timer.stop()
        self.setWindowOpacity(self.opacity)

    # Animación de salida (fade-out) de la ventana, manteniéndola centrada
    def fade_out(self):
        if self.parent() is not None:
            parent_geom = self.parent().geometry()
            x = parent_geom.x() + (parent_geom.width() - self.width()) // 2
            y = parent_geom.y() + (parent_geom.height() - self.height()) // 2
            self.move(x, y)
        self.opacity -= 0.04
        if self.opacity <= 0.0:
            self.opacity = 0.0
            if self.fade_out_timer:
                self.fade_out_timer.stop()
            super().close()  # Llama al método close real de la ventana
        else:
            self.setWindowOpacity(self.opacity)

    # Cierre controlado: inicia fade-out si no está ya en proceso
    def closeEvent(self, event):
        if self.opacity <= 0.0:
            event.accept()
            return
        if not self.fade_out_timer or not self.fade_out_timer.isActive():
            self.fade_out_timer = QTimer(self)
            self.fade_out_timer.timeout.connect(self.fade_out)
            self.fade_out_timer.start(20)
        event.ignore()

    # Establece el progreso objetivo y lanza la animación de avance
    def set_progress(self, value):
        self.target_progress = int(value)
        if not self.progress_timer.isActive():
            self.progress_timer.start(10)  # cada 10 ms

    # Anima el avance del progreso de forma suave
    def _animate_progress(self):
        if self.progress < self.target_progress:
            self.progress += 1
            self.update()
        elif self.progress > self.target_progress:
            self.progress -= 1
            self.update()
        else:
            self.progress_timer.stop()

    # Dibuja el círculo de progreso, el glow y el texto de porcentaje centrado
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        cx = self.width() // 2
        cy = self.height() // 2
        radius = 40
        # Colores adaptados al modo claro/oscuro
        if self.modo_dia:
            main_color = QColor("#222")  # Oscuro en modo claro
            glow_color = QColor(60, 60, 60, 40)
            arc_color = QColor(34, 34, 34, 120)
            text_color = QColor(34, 34, 34, 220)
        else:
            main_color = QColor("#FFFFFF")  # Blanco en modo oscuro
            glow_color = QColor(60, 60, 60, 40)
            arc_color = QColor(255, 255, 255, 120)
            text_color = QColor(255, 255, 255, 220)

        # Glow externo
        glow_pen = QPen(glow_color, 8)
        glow_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(glow_pen)
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2,
                        90 * 16, -int((self.progress / 100) * 360 * 16))

        # Arco principal
        pen = QPen(arc_color, 3)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2,
                        90 * 16, -int((self.progress / 100) * 360 * 16))

        # Texto de porcentaje centrado
        painter.setPen(text_color)
        font = painter.font()
        font.setPointSize(10)
        font.setBold(True)
        painter.setFont(font)
        text = f"{self.progress}%"
        text_rect = painter.boundingRect(0, 0, self.width(), self.height(), Qt.AlignCenter, text)
        painter.drawText(text_rect, Qt.AlignCenter, text)

    # Centra la ventana respecto a su parent al mostrarse
    def showEvent(self, event):
        super().showEvent(event)
        if self.parent() is not None:
            parent_geom = self.parent().geometry()
            x = parent_geom.x() + (parent_geom.width() - self.width()) // 2
            y = parent_geom.y() + (parent_geom.height() - self.height()) // 2
            self.move(x, y)

    # Permite cambiar el modo visual (claro/oscuro) en caliente
    def set_modo_dia(self, modo_dia):
        self.modo_dia = modo_dia
        self.update()  # Fuerza el repintado con el nuevo color

# ===============================
# COMBOBOX PERSONALIZADO PARA MEJOR UX/UI (CustomComboBox)
# - Mejora la experiencia visual y de interacción respecto al QComboBox estándar de Qt.
# - Incluye flecha personalizada, centrado de texto, solo lectura y estilos adaptados.
# ===============================

# QLineEdit especial para usarse dentro del CustomComboBox.
# Permite mostrar el popup del combo al hacer clic en el campo de texto.
class ComboLineEdit(QLineEdit):
    def __init__(self, parent_combo, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent_combo = parent_combo
    def mousePressEvent(self, event):
        self.parent_combo.showPopup()
        super().mousePressEvent(event)
    def contextMenuEvent(self, event):
        # Desactivar menú contextual
        pass

# QComboBox personalizado con mejoras visuales y de accesibilidad.
# Características:
#   - Flecha personalizada siempre visible y clicable
#   - Delegate para centrar el texto en el desplegable
#   - Editable pero solo lectura (no permite escribir manualmente)
#   - Estilos adaptados a modo claro/oscuro
#   - Permite bloquear la navegación con flechas si hay animaciones activas
class CustomComboBox(QComboBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cooldown_blocker = None  # Referencia a función o lambda que retorna True si está bloqueado
        # Flecha personalizada (label con símbolo)
        self.arrow_label = QLabel("▼", self)
        self.arrow_label.setStyleSheet("color: white; font-size: 16px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")
        self.arrow_label.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.arrow_label.setAlignment(Qt.AlignCenter)
        self.arrow_label.raise_()
        self.update_arrow_position()
        self.arrow_label.mousePressEvent = lambda event: self.showPopup()
        # Delegate para centrar el texto en el desplegable
        self.setItemDelegate(CenteredComboDelegate(self))
        # Hacer editable pero solo lectura, y centrar el texto usando ComboLineEdit
        self.setEditable(True)
        custom_line_edit = ComboLineEdit(self)
        custom_line_edit.setAlignment(Qt.AlignCenter)
        custom_line_edit.setReadOnly(True)
        custom_line_edit.setStyleSheet("""
background: transparent;
border: none;
color: #f2f2f7;
selection-background-color: #232323;
selection-color: #fff;
QLineEdit::selection {
    background: #232323;
    color: #fff;
}
""")
        self.setLineEdit(custom_line_edit)
        self.setStyleSheet(self.styleSheet() + """
QComboBox {
    background: #161414;
    color: #f2f2f7;
    border: 1px solid #161414;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 0px 15px;
    min-height: 28px;
    max-height: 28px;
}
QComboBox QAbstractItemView {
    background: #161414;
    color: #f2f2f7;
    border-radius: 6px;
    border: 1px solid #232323;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    selection-background-color: #232323;
    selection-color: #fff;
    outline: none;
}
QComboBox QAbstractItemView::item {
    padding: 6px 0px;
    border: none;
    text-align: center;
}
QComboBox QAbstractItemView::item:hover {
    background: #232323;
    color: #fff;
}
""")
        # --- Captura clics en el QLineEdit ---
        # Eliminado: self.lineEdit().mousePressEvent = lambda event: self.showPopup()
        # --- Captura clics en el QComboBox (fuera del QLineEdit) ---
        # Eliminado el código anterior de mousePressEvent personalizado

    # Permite establecer una función que bloquea la navegación con flechas si retorna True
    def set_cooldown_blocker(self, func):
        self._cooldown_blocker = func

    # Bloquea las flechas arriba/abajo si hay animación activa (cooldown)
    def keyPressEvent(self, event):
        if self._cooldown_blocker and self._cooldown_blocker():
            if event.key() in (Qt.Key_Up, Qt.Key_Down):
                event.ignore()
                return
        super().keyPressEvent(event)

    # Muestra el popup al hacer clic en cualquier parte del combo
    def mousePressEvent(self, event):
        self.showPopup()
        super().mousePressEvent(event)

    # Reposiciona la flecha personalizada al cambiar el tamaño del combo
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_arrow_position()

    # Calcula y actualiza la posición de la flecha personalizada
    def update_arrow_position(self):
        h = self.height()
        w = self.width()
        arrow_w = 20
        self.arrow_label.setFixedSize(arrow_w, h)
        self.arrow_label.move(w - arrow_w, 0)

    # Permite cambiar el color de la flecha personalizada
    def set_arrow_color(self, color):
        self.arrow_label.setStyleSheet(f"color: {color}; font-size: 16px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")

    def contextMenuEvent(self, event):
        # Desactivar menú contextual
        pass

# Delegate para centrar el texto en los QComboBox
class CenteredComboDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.displayAlignment = Qt.AlignCenter

# ===============================
# BOTÓN PERSONALIZADO CON ANIMACIÓN DE BRILLO (ShinyButton)
# - QPushButton avanzado con animaciones visuales: barrido brillante, cambio de color y escala.
# - Mejora la experiencia de usuario en acciones principales o destacadas.
# ===============================

# Clase de botón con efecto de barrido brillante y animaciones de color/escala.
# Ideal para acciones principales donde se busca llamar la atención del usuario.
# Incluye animaciones suaves al pasar el ratón, hacer clic o recibir el foco.
class ShinyButton(QPushButton):
    def __init__(self, text, *args, **kwargs):
        super().__init__(text, *args, **kwargs)
        # Estado y animación del brillo (barrido)
        self._shine_pos = -1
        self._shine_anim = QPropertyAnimation(self, b'shine_pos')
        self.setMouseTracking(True)
        # Animación de color de fondo (hover)
        self._bg_color = QColor(55, 156, 55)
        self._color_normal = QColor(55, 156, 55)
        self._color_hover = QColor(46, 174, 78)
        self._anim = QPropertyAnimation(self, b"bgColor")
        self._anim.setDuration(350)
        self._anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.setStyleSheet("QPushButton { color: #fff; border: 1px solid rgb(55,156,55); border-radius: 6px; min-height: 28px; max-height: 28px; outline: none; } QPushButton:focus { outline: none; } QPushButton:hover { border: 1px solid rgb(46, 174, 78); }")
        # Animación de escala (al hacer clic)
        self._scale = 1.0
        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(120)
        self._scale_anim.setEasingCurve(QEasingCurve.InOutQuad)

    # Al pasar el ratón: inicia animación de brillo y color de fondo
    def enterEvent(self, event):
        if self._shine_anim.state() != QPropertyAnimation.Running:
            self._shine_anim.stop()
            self._shine_anim.setStartValue(-self.width())
            self._shine_anim.setEndValue(self.width())
            self._shine_anim.setDuration(700)
            self._shine_anim.setEasingCurve(QEasingCurve.OutQuad)
            self._shine_anim.start()
        self._anim.stop()
        self._anim.setStartValue(self._bg_color)
        self._anim.setEndValue(self._color_hover)
        self._anim.start()
        super().enterEvent(event)

    # Al salir el ratón: vuelve a color normal, mantiene el brillo si estaba activo
    def leaveEvent(self, event):
        self._shine_pos = self._shine_pos  # Mantener la posición actual
        self.update()
        self._anim.stop()
        self._anim.setStartValue(self._bg_color)
        self._anim.setEndValue(self._color_normal)
        self._anim.start()
        super().leaveEvent(event)

    # Al presionar: reduce la escala para dar feedback visual
    def mousePressEvent(self, event):
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(0.93)
        self._scale_anim.setDuration(80)
        self._scale_anim.start()
        super().mousePressEvent(event)

    # Al soltar: vuelve la escala a 1.0
    def mouseReleaseEvent(self, event):
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.setDuration(120)
        self._scale_anim.start()
        super().mouseReleaseEvent(event)

    # Dibuja el botón con el efecto de brillo, escala y color de fondo animados
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        painter.translate(w/2, h/2)
        painter.scale(self._scale, self._scale)
        painter.translate(-w/2, -h/2)
        painter.setBrush(QBrush(self._bg_color))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 6, 6)
        # Efecto de brillo animado
        if self._shine_anim.state() == QPropertyAnimation.Running or self._shine_pos != -1:
            grad = QLinearGradient(self._shine_pos, 0, self._shine_pos + 60, 0)
            grad.setColorAt(0.0, QColor(255,255,255,0))
            grad.setColorAt(0.3, QColor(255,255,255,80))
            grad.setColorAt(0.5, QColor(255,255,255,180))
            grad.setColorAt(0.7, QColor(255,255,255,80))
            grad.setColorAt(1.0, QColor(255,255,255,0))
            painter.setBrush(QBrush(grad))
            painter.setPen(Qt.NoPen)
            painter.drawRect(self.rect())
        # Borde de foco verde oscuro si tiene el foco
        if getattr(self, '_focus', False):
            pen = QPen(QColor(22, 80, 22), 1)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(self.rect().adjusted(1,1,-1,-1), 6, 6)
        # Texto blanco centrado
        painter.setPen(QColor("#fff"))
        font = self.font()
        painter.setFont(font)
        text = self.text()
        rect = self.rect()
        painter.drawText(rect, Qt.AlignCenter, text)
        # No llamar a super().paintEvent(event)

    # Propiedad para la posición del brillo animado
    def get_shine_pos(self):
        return self._shine_pos

    def set_shine_pos(self, value):
        self._shine_pos = value
        self.update()

    shine_pos = Property(int, get_shine_pos, set_shine_pos)

    # Propiedad para el color de fondo animado
    def getBgColor(self):
        return self._bg_color

    def setBgColor(self, color):
        if isinstance(color, QColor):
            self._bg_color = color
        else:
            self._bg_color = QColor(color)
        self.update()

    bgColor = Property(QColor, getBgColor, setBgColor)

    # Propiedad de escala animada
    def getScale(self):
        return self._scale
    def setScale(self, value):
        self._scale = value
        self.update()
    scale = Property(float, getScale, setScale)

    # Al cambiar tamaño: reinicia la animación de brillo si está activa
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._shine_anim.state() == QPropertyAnimation.Running:
            self._shine_anim.stop()
            self._shine_anim.setStartValue(-self.width())
            self._shine_anim.setEndValue(self.width())
            self._shine_anim.setDuration(700)
            self._shine_anim.setEasingCurve(QEasingCurve.OutQuad)
            self._shine_anim.start()

    # Al recibir el foco: dibuja el borde especial
    def focusInEvent(self, event):
        self._focus = True
        self.update()
        super().focusInEvent(event)

    # Al perder el foco: quita el borde especial
    def focusOutEvent(self, event):
        self._focus = False
        self.update()
        super().focusOutEvent(event)

    # Permite activar la animación de escala y click con Enter/Return
    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self._scale_anim.stop()
            self._scale_anim.setStartValue(self._scale)
            self._scale_anim.setEndValue(0.93)
            self._scale_anim.setDuration(80)
            self._scale_anim.start()
            super().keyPressEvent(event)
            self.click()
            self._scale_anim.stop()
            self._scale_anim.setStartValue(0.93)
            self._scale_anim.setEndValue(1.0)
            self._scale_anim.setDuration(120)
            self._scale_anim.start()
        else:
            super().keyPressEvent(event)

# ===============================
# DELEGATE PERSONALIZADO PARA COLUMNA 'CONFIANZA MALICIOSA' (ConfianzaMaliciosaDelegate)
# - Añade animaciones de gradiente y opacidad para resaltar visualmente el score de confianza maliciosa.
# - Permite distinguir rápidamente el nivel de riesgo de una IP mediante colores y efectos visuales.
# ===============================

# Delegate que pinta celdas con gradiente de color y animación de opacidad según el score de confianza maliciosa.
# Utiliza colores intensos para cada rango de score y animaciones suaves al mostrar los datos.
class ConfianzaMaliciosaDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._opacidades = {}  # Diccionario: (fila, columna) -> opacidad actual de la celda
        self._animando = set() # Conjunto de (fila, columna) que están en animación
        self._max_alpha = 90   # Opacidad máxima para el gradiente
        self._duracion = 500   # Duración de la animación en ms
        # Diccionario de colores por nivel de score (bajo, medio_bajo, medio_alto, alto)
        self.colores = {
            'bajo': (QColor(55, 156, 55), QColor(55, 156, 55)),
            'medio_bajo': (QColor(255, 255, 100), QColor(255, 255, 100)),
            'medio_alto': (QColor(255, 140, 40), QColor(255, 140, 40)),
            'alto': (QColor(255, 80, 80), QColor(127, 0, 0)),
        }

    # Inicia la animación de fade-in para una celda específica (fila, columna)
    # Llama a _on_anim_value en cada frame para actualizar la opacidad
    def start_fade_in(self, table, fila, columna):
        key = (fila, columna)
        if key in self._animando:
            return
        self._animando.add(key)
        anim = QVariantAnimation()
        anim.setStartValue(0)
        anim.setEndValue(self._max_alpha)
        anim.setDuration(self._duracion)
        anim.valueChanged.connect(lambda value: self._on_anim_value(table, fila, columna, value))
        anim.finished.connect(lambda: self._animando.discard(key))
        anim.start()
        # Guardar referencia para evitar que el GC lo elimine
        if not hasattr(self, '_anims'):
            self._anims = []
        self._anims.append(anim)

    # Actualiza la opacidad de la celda y fuerza el repintado
    def _on_anim_value(self, table, fila, columna, value):
        self._opacidades[(fila, columna)] = int(value)
        table.viewport().update(table.visualRect(table.model().index(fila, columna)))

    # Pinta la celda con gradiente de color y opacidad según el score
    def paint(self, painter, option, index):
        # Quitar el flag de focus para que Qt no pinte el rectángulo punteado estándar
        option.state &= ~QStyle.State_HasFocus
        super().paint(painter, option, index)
        fila = index.row()
        columna = index.column()
        valor_str = index.data()
        try:
            valor = int(str(valor_str).replace('%', ''))
        except Exception:
            valor = None
        painter.save()
        rect = option.rect
        # Selección de colores según el score
        color1 = color2 = None
        if valor is not None:
            if valor <= 20:
                color1, color2 = self.colores['bajo']
            elif valor <= 49:
                color1, color2 = self.colores['medio_bajo']
            elif valor <= 74:
                color1, color2 = self.colores['medio_alto']
            elif valor <= 100:
                color1, color2 = self.colores['alto']
        # Dibujar gradiente en un rectángulo redondeado más pequeño y centrado
        if color1 and color2:
            key = (fila, columna)
            alpha = self._opacidades.get(key, 0)
            color1.setAlpha(alpha)
            color2.setAlpha(alpha)
            grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
            grad.setColorAt(0, color1)
            grad.setColorAt(1, color2)
            margin_x = 6
            margin_y = 4
            rounded_rect = rect.adjusted(margin_x, margin_y, -margin_x, -margin_y)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setBrush(grad)
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(rounded_rect, 6, 6)
        painter.restore()

# ===============================
# QTableWidgetItem NUMÉRICO Y DE FECHA PARA ORDENACIÓN PERSONALIZADA
# - NumericTableWidgetItem: Permite ordenar correctamente columnas con porcentajes o números.
# - DateTableWidgetItem: Permite ordenar correctamente columnas con fechas en formato personalizado.
# ===============================

# QTableWidgetItem especializado para valores numéricos (por ejemplo, porcentajes).
# Extrae el valor numérico del texto para permitir una ordenación precisa en la tabla.
class NumericTableWidgetItem(QTableWidgetItem):
    def __init__(self, text):
        super().__init__(text)
        # Extraer el valor numérico, ignorando símbolos como %
        try:
            self.numeric_value = float(str(text).replace('%','').replace(',','.'))
        except Exception:
            self.numeric_value = 0
    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            return self.numeric_value < other.numeric_value
        return super().__lt__(other)

# QTableWidgetItem especializado para fechas en formato 'dd/mm/YYYY HH:MM:SS'.
# Permite una ordenación cronológica correcta incluso si hay textos no válidos (los pone al final).
class DateTableWidgetItem(QTableWidgetItem):
    def __init__(self, text):
        super().__init__(text)
        self.text_value = str(text)
        try:
            # Intentar parsear la fecha en formato 'dd/mm/YYYY HH:MM:SS'
            self.date_value = datetime.strptime(self.text_value, '%d/%m/%Y %H:%M:%S')
        except Exception:
            # Si no es una fecha válida (por ejemplo, 'Sin reportes'), usar fecha muy antigua
            self.date_value = datetime(1900, 1, 1)
    def __lt__(self, other):
        if isinstance(other, DateTableWidgetItem):
            return self.date_value < other.date_value
        return super().__lt__(other)

# ===============================
# DELEGATE ELEGANTE PARA ELIMINAR EL RECTÁNGULO DE FOCO EN LA TABLA
# - ElegantFocusDelegate: Evita que Qt pinte el borde punteado estándar al seleccionar celdas.
# - Mejora la estética de la tabla y la experiencia visual.
# ===============================

# Delegate que elimina el rectángulo de foco estándar en las celdas de la tabla.
# Solo pinta el contenido, sin bordes adicionales al seleccionar o enfocar.
class ElegantFocusDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        # Quitar el flag de focus para que Qt no pinte el rectángulo punteado estándar
        option.state &= ~QStyle.State_HasFocus
        super().paint(painter, option, index)
        # Ya no se dibuja ningún borde ni efecto de foco

# Ventana principal
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.modo_dia = cargar_modo_config()
        self.setWindowIcon(get_icono_desde_base64())
        self.setStyleSheet("QWidget { background-color: rgb(0,0,0); }")
        self.setWindowTitle("NetTrace")
        self.setFont(QFont("San Francisco"))
        self.BASE_WIDTH = 900
        self.BASE_HEIGHT = 600
        self.resize(self.BASE_WIDTH, self.BASE_HEIGHT)
        self.setMinimumSize(self.BASE_WIDTH, self.BASE_HEIGHT)  # <-- Tamaño mínimo de ventana
        # --- CINTA DE OPCIONES PERSONALIZADA ---
        self.ribbon = QWidget(self)
        self.ribbon.setObjectName("customRibbon")
        self.ribbon.setFixedHeight(26)
        layout_ribbon = QHBoxLayout(self.ribbon)
        layout_ribbon.setContentsMargins(0, 0, 0, 0)
        layout_ribbon.setSpacing(0)
        self.ribbon_btn_config = QPushButton("Configuración", self.ribbon)
        self.ribbon_btn_config.setObjectName("ribbonBtnConfig")
        layout_ribbon.addWidget(self.ribbon_btn_config)

        # --- Botón de Ayuda ---
        self.ribbon_btn_help = QPushButton("Ayuda", self.ribbon)
        self.ribbon_btn_help.setObjectName("ribbonBtnHelp")
        layout_ribbon.addWidget(self.ribbon_btn_help)
        self.ribbon_help_menu = QMenu(self)
        self.action_info = QAction("Información", self)
        self.action_atajos = QAction("Atajos", self)
        self.action_terminos = QAction("Términos y condiciones", self)  # NUEVO
        self.ribbon_help_menu.addAction(self.action_info)
        self.ribbon_help_menu.addAction(self.action_atajos)
        self.ribbon_help_menu.addAction(self.action_terminos)  # NUEVO
        self.ribbon_btn_help.clicked.connect(lambda: self.ribbon_help_menu.exec(self.ribbon_btn_help.mapToGlobal(self.ribbon_btn_help.rect().bottomLeft())))
        self.action_info.triggered.connect(self.mostrar_info_ayuda)
        self.action_atajos.triggered.connect(self.mostrar_atajos_ayuda)
        self.action_terminos.triggered.connect(self.mostrar_terminos_condiciones)  # NUEVO

        layout_ribbon.addStretch(1)
        # Menú personalizado para el botón
        self.ribbon_menu = QMenu(self)
        self.action_modo = QAction("Modo claro/oscuro", self)
        self.action_config_apis = QAction("Configuración de APIs", self)
        self.ribbon_menu.addAction(self.action_modo)
        self.ribbon_menu.addAction(self.action_config_apis)
        self.ribbon_btn_config.clicked.connect(lambda: self.ribbon_menu.exec(self.ribbon_btn_config.mapToGlobal(self.ribbon_btn_config.rect().bottomLeft())))
        self.action_modo.triggered.connect(self.toggle_modo_dia)
        self.action_config_apis.triggered.connect(self.abrir_config_api)
        # --- FIN CINTA DE OPCIONES ---
        self.actualizar_ribbon_modo()
        # --- CONTENEDOR PRINCIPAL PARA RIBBON + CENTRAL ---
        from PySide6.QtWidgets import QVBoxLayout
        self.main_container = QWidget(self)
        self.main_layout = QVBoxLayout(self.main_container)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.main_layout.addWidget(self.ribbon)
        # Central widget
        self.central = QWidget(self.main_container)
        self.main_layout.addWidget(self.central)
        self.setCentralWidget(self.main_container)
        # ... el resto igual, elimina cualquier self.central.move() ...
        # Asegurar que la cinta esté siempre arriba
        self.ribbon.raise_()
        self.columns = [
            "IP", "Confianza Maliciosa", "Número de reportes (365 días)", "Última vez reportada",
            "Tipo de Uso", "ISP", "ASN", "Hostname", "Nombre del dominio", "Whitelisted (AbuseIPDB)", "Rango de Red (VPNAPI)",
            "Tor Detectado (AbuseIPDB)", "Tor Detectado (VPNAPI)", "VPN Detectado (VPNAPI)",
            "Proxy Detectado (VPNAPI)", "Relay Detectado (VPNAPI)", "Código país", "Nombre del país",
            "Ciudad", "Error"
        ]
        # Diccionario de geometría base para cada widget
        self.widget_geometries = {
            "inp_title":      (60,  40, 320, 28),
            "input_combo":    (60,  80, 320, 28),
            "ip_line":        (60, 120, 320, 28),
            "excel_label":    (60, 120, 320, 28),
            "out_title":      (520,  40, 320, 28),
            "output_combo":   (520,  80, 320, 28),
            "btn_analyze":    (520, 120, 320, 28),
            "stacked":        (20, 180, 860, 390),
        }
        # Widgets principales
        self.inp_title = QLabel("Formato de Entrada", self.central)
        self.inp_title.setAlignment(Qt.AlignCenter)
        self.inp_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: rgb(242,242,247);
            background: transparent;
            font-weight: bold;
        """)
        self.input_combo = CustomComboBox(self.central)
        self.input_combo.set_cooldown_blocker(lambda: getattr(self, 'animando_titulo_entrada', False))
        self.input_combo.addItems(["Introducir IPs", "Excel"])
        self.input_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.input_combo.setMinimumHeight(28)
        self.input_combo.set_editable_with_popup = lambda: None
        self.input_combo.setItemDelegate(CenteredComboDelegate(self.input_combo))
        self.input_combo.setStyleSheet(common_style)
        self.input_combo.setEnabled(False)  # <--- Deshabilitar al inicio
        self.input_combo.set_arrow_color("white")  # --- Color inicial flecha ---
        # Entrada manual y excel
        self.ip_line = QLineEdit(self.central)
        self.ip_line.setPlaceholderText("8.8.8.8")
        self.ip_line.setAlignment(Qt.AlignCenter)
        self.ip_line.setMinimumHeight(28)
        self.ip_line.contextMenuEvent = lambda event: None
        self.excel_label = QLabel("", self.central)
        self.excel_label.setAlignment(Qt.AlignCenter)
        self.excel_label.setStyleSheet("color: #aaa; font-style: italic;")
        # Eliminar input_stack y poner ambos widgets directamente
        self.ip_line.setVisible(True)
        self.excel_label.setVisible(False)
        # Actualizar lógica de cambio de modo de entrada
        self.input_combo.currentIndexChanged.connect(self.cambiar_modo_entrada)
        self.input_combo.currentIndexChanged.connect(self.actualizar_titulo_entrada_cooldown)
        self.input_combo.activated.connect(self.actualizar_titulo_entrada_cooldown)
        # Título salida
        self.out_title = QLabel("Formato de Salida", self.central)
        self.out_title.setAlignment(Qt.AlignCenter)
        self.out_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: rgb(242,242,247);
            background: transparent;
            font-weight: bold;
        """)
        self.output_combo = CustomComboBox(self.central)
        self.output_combo.set_cooldown_blocker(lambda: getattr(self, 'animando_titulo_salida', False))
        self.output_combo.addItems(["Texto plano", "Excel"])
        self.output_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.output_combo.setMinimumHeight(28)
        self.output_combo.set_editable_with_popup = lambda: None
        self.output_combo.setItemDelegate(CenteredComboDelegate(self.output_combo))
        self.output_combo.setStyleSheet(common_style)
        self.output_combo.set_arrow_color("white")  # --- Color inicial flecha ---
        self.output_combo.currentIndexChanged.connect(self.actualizar_titulo_salida_cooldown)
        self.output_combo.activated.connect(self.actualizar_titulo_salida_cooldown)
        self.output_combo.setEnabled(False)  # <--- Deshabilitar al inicio
        # Reemplazo QPushButton por ShinyButton para el botón Analizar IPs
        self.btn_analyze = ShinyButton("Analizar IPs", self.central)
        self.btn_analyze.setMinimumHeight(28)
        self.btn_analyze.setStyleSheet("""
QPushButton {
    background: #161414;
    color: #f2f2f7;
    border: 1px solid #161414;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 0px 15px;
    min-height: 28px;
    max-height: 28px;
    outline: none;
    
}
QPushButton:focus { outline: none; }
QPushButton:hover {
    background: #232323;
    border: 1px solid #232323;
}
""")
        self.btn_analyze.clicked.connect(self.on_analyze)
        self.btn_analyze.setEnabled(False)  # <--- Deshabilitar al inicio
        # El stylesheet ya está en la clase, no hace falta ponerlo aquí
        # Tabla y placeholder
        self.table = QTableWidget(self.central)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectItems)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.setSortingEnabled(True)
        fuente_tabla = QFont("San Francisco")
        fuente_tabla.setStyleHint(QFont.SansSerif)
        fuente_tabla.setFamilies(["San Francisco", "Segoe UI", "Arial", "sans-serif"])
        self.table.setFont(fuente_tabla)
        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        # Asignar el delegate personalizado a la columna 'Confianza Maliciosa'
        idx_confianza = self.columns.index('Confianza Maliciosa')
        self.confianza_delegate = ConfianzaMaliciosaDelegate(self.table)
        self.table.setItemDelegateForColumn(idx_confianza, self.confianza_delegate)
        # Asignar el delegate elegante al resto de columnas
        self.elegant_focus_delegate = ElegantFocusDelegate(self.table)
        for col in range(self.table.columnCount()):
            if col != idx_confianza:
                self.table.setItemDelegateForColumn(col, self.elegant_focus_delegate)
        self.table.setStyleSheet("""
QTableWidget {
    background: #000;
    color: #f2f2f7;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    gridline-color: transparent;
    selection-background-color: #181818;
    selection-color: #fff;
}
QHeaderView::section {
    background: transparent;
    color: #bdbdbd;
    border: none;
    font-weight: bold;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 2px 0;
}
QHeaderView::down-arrow, QHeaderView::up-arrow {
    width: 0px;
    height: 0px;
}
QTableWidget QTableCornerButton::section {
    background: transparent;
    border: none;
}
QTableWidget::item {
    border: none;
    padding: 2px 4px;
}
QTableWidget::item:selected {
    background: #181818;
    color: #fff;
}
QTableWidget::item:hover {
    background: #232323;
    color: #fff;
}
QScrollBar:vertical {
    background: #161414;
    width: 12px;
    margin: 2px 0 2px 0;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #393939;
    min-height: 24px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover {
    background: #5c5c5c;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background: none;
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}
QScrollBar:horizontal {
    background: #161414;
    height: 12px;
    margin: 0 2px 0 2px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #393939;
    min-width: 24px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal:hover {
    background: #5c5c5c;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    background: none;
    width: 0px;
}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: none;
}
""")
        self.placeholder = QLabel("", self.central)
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setStyleSheet("background: transparent; border: none;")
        self.stacked = QStackedWidget(self.central)
        self.stacked.addWidget(self.placeholder)
        self.stacked.addWidget(self.table)
        self.stacked.setCurrentWidget(self.placeholder)
        # Estado inicial de visibilidad
        self.input_combo.currentIndexChanged.connect(self.cambiar_modo_entrada)
        self.table.setVisible(False)
        self.placeholder.setVisible(True)
        self.stacked.setVisible(True)
        self._animacion_inicial_aplicada = False
        self.inp_box = self.input_combo
        self.out_box = self.output_combo
        self.circular_loader = None
        # Snackbar: debe ir antes de update_widget_positions
        self.snackbar = QLabel("?", self.central)
        self.snackbar.setAlignment(Qt.AlignCenter)
        self.snackbar.setStyleSheet("""
            color: rgba(255,255,255,180);
            font-size: 18px;
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            padding: 0;
            border: none;
            background: #393939;
            border-radius: 12px;
            min-width: 24px;
            min-height: 24px;
            max-width: 24px;
            max-height: 24px;
        """)
        self.snackbar.setVisible(False)
        self.snackbar_tooltip_text = "Ctrl + T para modificar APIs\nCtrl + L para cambiar a modo claro/oscuro"
        self.snackbar_tooltip = CustomTooltip(self, modo_dia=self.modo_dia)
        # --- Estado del snackbar: solo mostrar tooltip si está abajo ---
        self.snackbar_abajo = False
        # Mostrar el tooltip personalizado al pasar el ratón
        def mostrar_tooltip(event):
            if self.snackbar_abajo:
                if hasattr(event, 'position'):
                    pos = event.position().toPoint()
                    global_pos = self.snackbar.mapToGlobal(pos)
                else:
                    global_pos = event.globalPos()
                x = global_pos.x() - self.snackbar_tooltip.width() // 2 + self.snackbar.width() // 2
                y = global_pos.y() + self.snackbar.height() + 8
                self.snackbar_tooltip.set_modo_dia(self.modo_dia)
                self.snackbar_tooltip.show_tooltip(self.snackbar_tooltip_text, QPoint(x, y))
        def ocultar_tooltip(event):
            self.snackbar_tooltip.hide_tooltip()
        self.snackbar.enterEvent = mostrar_tooltip
        self.snackbar.leaveEvent = ocultar_tooltip
        # Llama a la función de posiciones absolutas
        self.update_widget_positions()
        self._set_maximize_enabled(False)
        QTimer.singleShot(2000, self.deshabilitar_bloqueo_maximizar)
        self.shortcut_api = QShortcut(QKeySequence("Ctrl+T"), self)
        self.shortcut_api.activated.connect(self.abrir_config_api)
        self.shortcut_api.setEnabled(False)  # Deshabilitar al inicio
        QTimer.singleShot(2000, lambda: self.shortcut_api.setEnabled(True))  # Habilitar tras 2 segundos
        # --- NUEVO: Atajo para alternar modo día ---
        self.shortcut_light = QShortcut(QKeySequence("Ctrl+L"), self)
        self.shortcut_light.activated.connect(self.toggle_modo_dia)
        self.shortcut_light.setEnabled(False)  # Deshabilitar al inicio

        set_modo_claro_oscuro_mainwindow(self, self.modo_dia)

        self.animando_titulo_entrada = False  # Cooldown para animación de entrada
        self.animando_titulo_salida = False   # Cooldown para animación de salida

        # --- NUEVO: Instalar event filter en la tabla para controlar el tabulador ---
        self.table.installEventFilter(self)
        # --- NUEVO: Instalar event filter en el input_combo para Shift+Tab ---
        self.input_combo.installEventFilter(self)
        # --- NUEVO: Instalar event filter en el btn_analyze para Tab hacia la tabla ---
        self.btn_analyze.installEventFilter(self)
        # --- NUEVO: Bandera para saber si volvemos a la tabla por Shift+Tab o Tab ---
        self._volver_a_tabla_por_shift_tab = False
        self._volver_a_tabla_por_tab = False

        # --- NUEVO: Sobrescribir focusInEvent de la tabla ---
        original_focus_in = self.table.focusInEvent
        def custom_focus_in(event):
            if self._volver_a_tabla_por_shift_tab:
                # Selecciona la última celda
                if self.table.rowCount() > 0 and self.table.columnCount() > 0:
                    last_row = self.table.rowCount() - 1
                    last_col = self.table.columnCount() - 1
                    self.table.setCurrentCell(last_row, last_col)
                self._volver_a_tabla_por_shift_tab = False
            elif self._volver_a_tabla_por_tab:
                # Selecciona la primera celda
                if self.table.rowCount() > 0 and self.table.columnCount() > 0:
                    self.table.setCurrentCell(0, 0)
                self._volver_a_tabla_por_tab = False
            else:
                # No selecciones ninguna celda
                self.table.clearSelection()
            original_focus_in(event)
        self.table.focusInEvent = custom_focus_in

        # --- NUEVO: Selección de fila completa con doble clic ---
        self.table.cellDoubleClicked.connect(self.seleccionar_fila_entera)

        # ... dentro de la clase MainWindow, en __init__
        self.analizando = False

    # ===============================
    # FILTRO DE EVENTOS PARA NAVEGACIÓN AVANZADA (eventFilter)
    # - Permite una navegación fluida con Tab y Shift+Tab entre la tabla y los widgets principales.
    # - Gestiona el foco y la selección de celdas según la dirección de la navegación.
    # ===============================
    def eventFilter(self, obj, event):
        # Tab en la última celda de la tabla: pasa al siguiente widget (input_combo)
        if obj is self.table and event.type() == QEvent.KeyPress:
            current = self.table.currentIndex()
            # Tab en la última celda
            if event.key() == Qt.Key_Tab and not event.modifiers():
                if (current.row() == self.table.rowCount() - 1 and
                    current.column() == self.table.columnCount() - 1):
                    # Mueve el foco al siguiente widget en el orden de tabulación
                    # y fuerza el foco visual
                    self.input_combo.setFocus(Qt.TabFocusReason)
                    # Si el combobox es editable, también fuerza el foco en el QLineEdit
                    if self.input_combo.isEditable() and self.input_combo.lineEdit() is not None:
                        self.input_combo.lineEdit().setFocus(Qt.TabFocusReason)
                    # Limpiar la selección de la tabla después del cambio de foco
                    QTimer.singleShot(0, self.table.clearSelection)
                    return False
            # Shift+Tab en la primera celda
            if event.key() == Qt.Key_Tab and event.modifiers() == Qt.ShiftModifier:
                if (current.row() == 0 and current.column() == 0):
                    self._volver_a_tabla_por_shift_tab = False
                    self.btn_analyze.setFocus(Qt.BacktabFocusReason)
                    return True
        # Shift+Tab en input_combo: regresa a la última celda de la tabla
        if obj is self.input_combo and event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Tab and event.modifiers() == Qt.ShiftModifier:
                if self.table.rowCount() > 0 and self.table.columnCount() > 0:
                    last_row = self.table.rowCount() - 1
                    last_col = self.table.columnCount() - 1
                    self._volver_a_tabla_por_shift_tab = True
                    self.table.setFocus()
                    self.table.setCurrentCell(last_row, last_col)
                    return True
        # Tab en btn_analyze: ir a la primera celda de la tabla
        if obj is self.btn_analyze and event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Tab and not event.modifiers():
                if self.table.rowCount() > 0 and self.table.columnCount() > 0:
                    self._volver_a_tabla_por_tab = True
                    self.table.setFocus()
                    self.table.setCurrentCell(0, 0)
                    return True
        return super().eventFilter(obj, event)

    # ===============================
    # CAMBIO DE MODO CLARO/OSCURO (toggle_modo_dia)
    # - Alterna entre los estilos visuales claro y oscuro en toda la interfaz.
    # - Reinicia la ventana principal para aplicar los cambios de forma global.
    # ===============================
    def toggle_modo_dia(self):
        # Cerrar pantalla de carga circular si está activa
        if hasattr(self, 'circular_loader') and self.circular_loader and self.circular_loader.isVisible():
            self.circular_loader.close()
            self.circular_loader = None
        # Ocultar tooltip si está visible
        if hasattr(self, 'snackbar_tooltip'):
            self.snackbar_tooltip.hide_tooltip()
        self.modo_dia = not self.modo_dia
        guardar_modo_config(self.modo_dia)
        self.close()
        global VENTANA_MAIN_GLOBAL
        VENTANA_MAIN_GLOBAL = MainWindow()
        VENTANA_MAIN_GLOBAL.show()
        # Actualizar tooltip personalizado
        if hasattr(self, 'snackbar_tooltip'):
            self.snackbar_tooltip.set_modo_dia(self.modo_dia)
        # Actualizar ribbon visualmente
        if hasattr(VENTANA_MAIN_GLOBAL, 'actualizar_ribbon_modo'):
            VENTANA_MAIN_GLOBAL.actualizar_ribbon_modo()

    # ===============================
    # POSICIONAMIENTO Y REDIMENSIONADO DE WIDGETS (update_widget_positions, resizeEvent)
    # - Calcula y ajusta la posición/tamaño de los widgets según el tamaño de la ventana.
    # - Asegura que la interfaz sea responsiva y que los elementos clave estén siempre visibles y bien alineados.
    # ===============================
    def update_widget_positions(self):
        w, h = self.width(), self.height()
        fx = w / self.BASE_WIDTH
        fy = h / self.BASE_HEIGHT
        # --- Lógica adaptativa ---
        if w <= self.BASE_WIDTH:
            # Geometría base (como hasta ahora)
            for name, (x, y, ancho, alto) in self.widget_geometries.items():
                widget = getattr(self, name, None)
                if widget:
                    if name == "stacked":
                        widget.move(int(0), int(y * fy))
                        widget.resize(int(w), int(alto * fy))
                    else:
                        widget.move(int(x * fx), int(y * fy))
                        widget.resize(int(ancho * fx), int(alto * fy))
        else:
            # Repartir el espacio extra horizontal
            # Dos columnas: izquierda (input), derecha (output)
            margen_lateral = 60 * fx
            espacio_central = 40 * fx
            ancho_total_widgets = w - 2 * margen_lateral - espacio_central
            ancho_col = ancho_total_widgets // 2
            alto_base = 28 * fy
            # Izquierda
            x_izq = int(margen_lateral)
            # Derecha
            x_der = int(margen_lateral + ancho_col + espacio_central)
            # input_combo
            self.input_combo.move(x_izq, int(80 * fy))
            self.input_combo.resize(ancho_col, alto_base)
            # output_combo
            self.output_combo.move(x_der, int(80 * fy))
            self.output_combo.resize(ancho_col, alto_base)
            # ip_line
            self.ip_line.move(x_izq, int(120 * fy))
            self.ip_line.resize(ancho_col, alto_base)
            # excel_label
            self.excel_label.move(x_izq, int(120 * fy))
            self.excel_label.resize(ancho_col, alto_base)
            # btn_analyze
            self.btn_analyze.move(x_der, int(120 * fy))
            self.btn_analyze.resize(ancho_col, alto_base)
            # Títulos
            self.inp_title.move(x_izq, int(40 * fy))
            self.inp_title.resize(ancho_col, alto_base)
            self.out_title.move(x_der, int(40 * fy))
            self.out_title.resize(ancho_col, alto_base)
            # stacked
            self.stacked.move(int(20), int(180 * fy))
            self.stacked.resize(w - 40, int(390 * fy))
        # Snackbar (siempre centrado entre los títulos)
        inp_title_geom = self.inp_title.geometry()
        out_title_geom = self.out_title.geometry()
        x_c = (inp_title_geom.x() + out_title_geom.x() + inp_title_geom.width()//2 + out_title_geom.width()//2) // 2
        y_c = inp_title_geom.y()
        snackbar_w = self.snackbar.sizeHint().width()
        snackbar_h = self.snackbar.sizeHint().height()
        self.snackbar.move(x_c - snackbar_w//2, y_c)
        self.snackbar.resize(snackbar_w, snackbar_h)

    def resizeEvent(self, event):
        self.update_widget_positions()
        # Forzar la posición de los labels animados si están en animación
        for label in [self.inp_title, self.out_title]:
            if hasattr(label, '_anim_pos_in') and label._anim_pos_in.state() == QPropertyAnimation.Running:
                label._anim_pos_in.stop()
            if hasattr(label, '_anim_pos_out') and label._anim_pos_out.state() == QPropertyAnimation.Running:
                label._anim_pos_out.stop()
            if label.parentWidget() and label.parentWidget().layout():
                label.parentWidget().layout().activate()
                layout = label.parentWidget().layout()
                for i in range(layout.count()):
                    item = layout.itemAt(i)
                    if item and item.widget() is label:
                        label.move(item.geometry().topLeft())
                        break
        # --- Lógica para el snackbar ---
        if hasattr(self.snackbar, '_anim_pos') and self.snackbar._anim_pos.state() == QPropertyAnimation.Running:
            self.snackbar._anim_pos.stop()
        if hasattr(self.snackbar, '_anim_pos_out') and self.snackbar._anim_pos_out.state() == QPropertyAnimation.Running:
            self.snackbar._anim_pos_out.stop()
        # --- Solución puntual para el botón de barrido ---
        if hasattr(self, 'btn_analyze'):
            shine_anim = getattr(self.btn_analyze, '_shine_anim', None)
            if shine_anim is not None:
                if shine_anim.state() == QPropertyAnimation.Running:
                    shine_anim.stop()
                    shine_anim.setStartValue(-self.btn_analyze.width())
                    shine_anim.setEndValue(self.btn_analyze.width())
                    shine_anim.setDuration(700)
                    shine_anim.setEasingCurve(QEasingCurve.OutQuad)
                    shine_anim.start()
                else:
                    # Si la animación terminó, resetea la posición de la luz
                    self.btn_analyze.set_shine_pos(-1)
            self.btn_analyze.update()
        # Reposicionar el snackbar a su sitio correcto tras el resize
        self.update_widget_positions()
        super().resizeEvent(event)

    def _set_maximize_enabled(self, enabled: bool):
        if sys.platform == "win32":
            hwnd = int(self.winId())
            GWL_STYLE = -16
            WS_MAXIMIZEBOX = 0x00010000
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
            if enabled:
                style |= WS_MAXIMIZEBOX
            else:
                style &= ~WS_MAXIMIZEBOX
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, style)
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                0x0002 | 0x0001 | 0x0020 | 0x0040)  # SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED
        else:
            self.setWindowFlag(Qt.WindowMaximizeButtonHint, enabled)
            self.show()  # Necesario para que el cambio surta efecto

    def deshabilitar_bloqueo_maximizar(self):
        self._set_maximize_enabled(True)

    def actualizar_titulo_entrada_cooldown(self):
        if self.animando_titulo_entrada:
            return
        self.animando_titulo_entrada = True
        # self.input_combo.setEnabled(False)
        texto = self.input_combo.currentText()
        if texto == "Introducir IPs":
            animate_label_text_change(self.inp_title, "Entrada manual de direcciones IP", on_finished=self._fin_animacion_titulo_entrada)
        elif texto == "Excel":
            animate_label_text_change(self.inp_title, "Importar IPs desde archivo Excel", on_finished=self._fin_animacion_titulo_entrada)
        else:
            animate_label_text_change(self.inp_title, "Formato de Entrada", on_finished=self._fin_animacion_titulo_entrada)

    def _fin_animacion_titulo_entrada(self):
        self.animando_titulo_entrada = False
        # self.input_combo.setEnabled(True)

    def actualizar_titulo_salida_cooldown(self):
        if self.animando_titulo_salida:
            return
        self.animando_titulo_salida = True
        # self.output_combo.setEnabled(False)
        texto = self.output_combo.currentText()
        if texto == "Texto plano":
            animate_label_text_change(self.out_title, "Visualización en texto plano", on_finished=self._fin_animacion_titulo_salida)
        elif texto == "Excel":
            animate_label_text_change(self.out_title, "Exportar resultados a Excel", on_finished=self._fin_animacion_titulo_salida)
        else:
            animate_label_text_change(self.out_title, "Formato de Salida", on_finished=self._fin_animacion_titulo_salida)

    def _fin_animacion_titulo_salida(self):
        self.animando_titulo_salida = False
        # self.output_combo.setEnabled(True)

    # ===============================
    # MÉTODO PRINCIPAL DE ANÁLISIS (on_analyze)
    # - Valida la entrada, obtiene las IPs, verifica su validez y lanza el análisis en segundo plano.
    # - Muestra mensajes de error si la entrada no es válida y gestiona la animación de carga.
    # ===============================
    def on_analyze(self):
        if self.analizando:
            return
        self.btn_analyze.setEnabled(False)  # Deshabilitar el botón al iniciar
        self.mostrar_placeholder()
        mode_idx = self.input_combo.currentIndex()
        if mode_idx == 0:  # Introducir IPs
            ips = re.split(r'[\s,]+', self.ip_line.text().strip())
        elif mode_idx == 1:  # Excel
            path, _ = QFileDialog.getOpenFileName(self, "Abrir Excel", filter="Excel Files (*.xlsx *.xls)")
            if not path:
                self.btn_analyze.setEnabled(True)
                return
            df = pd.read_excel(path)
            # USAR DIALOGO PERSONALIZADO PARA SELECCIONAR COLUMNA
            dlg = SeleccionarColumnaDialog(self, list(df.columns), modo_dia=self.modo_dia)
            ok = dlg.exec()
            col = dlg.get_selected() if ok else None
            if not ok or not col or col not in df.columns:
                self.btn_analyze.setEnabled(True)
                return
            ips = [str(x).strip() for x in df[col].dropna()]
        else:
            ips = []
        ips = [ip for ip in ips if ip]
        if not ips:
            shake_widget(self.ip_line)
            mostrar_mensaje(self, "Error", "No se encontraron IPs válidas.", modo_dia=self.modo_dia, icon=QMessageBox.Warning)
            self.btn_analyze.setEnabled(True)
            self.input_combo.setFocus(Qt.OtherFocusReason)
            return
        # Verificar si hay al menos una IP válida y pública
        hay_ip_valida_publica = any(is_valid_ip(ip) and not is_private_or_reserved_ip(ip) for ip in ips)
        if not hay_ip_valida_publica:
            shake_widget(self.ip_line)
            mostrar_mensaje(self, "Error", "La lista solo contiene IPs privadas o no válidas. No se realizará el análisis.", modo_dia=self.modo_dia, icon=QMessageBox.Warning)
            self.btn_analyze.setEnabled(True)
            self.input_combo.setFocus(Qt.OtherFocusReason)
            return
        self.analizando = True  # <-- Solo aquí, después de todas las validaciones
        self.circular_loader = CircularProgress(self)
        self.circular_loader.show()
        self.centralWidget().setFocus(Qt.OtherFocusReason)
        # Lanzar worker en hilo
        self.thread = QThread()
        self.worker = AnalyzerWorker(ips)
        self.worker.moveToThread(self.thread)
        self.worker.progress.connect(self.update_circular_progress)
        self.worker.finished.connect(self.on_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    # ===============================
    # ACTUALIZACIÓN DEL PROGRESO CIRCULAR (update_circular_progress)
    # - Actualiza la animación de progreso circular según el avance del análisis.
    # ===============================
    def update_circular_progress(self, current, total):
        porcentaje = int(current / total * 100)
        if self.circular_loader:
            self.circular_loader.set_progress(porcentaje)

    # ===============================
    # FINALIZACIÓN DEL ANÁLISIS (on_finished)
    # - Recibe los resultados, cierra el loader, muestra los datos en la tabla o exporta a Excel.
    # - Gestiona la visibilidad y el estado de los widgets tras el análisis.
    # ===============================
    def on_finished(self, results):
        if self.circular_loader:
            self.circular_loader.close()
            self.circular_loader = None
        self.analizando = False
        self.btn_analyze.setEnabled(True)  # Re-habilitar el botón al finalizar
        mostrar_columna_error = any(r.get('Error') for r in results)
        columns = [col for col in self.columns if col != 'Error']
        if mostrar_columna_error:
            columns.append('Error')
        if self.output_combo.currentText() == "Excel":
            df = pd.DataFrame(results)
            df = df[columns]
            path, _ = QFileDialog.getSaveFileName(self, "Guardar resultados", filter="Excel Files (*.xlsx *.xls)")
            if path:
                df.to_excel(path, index=False)
                mostrar_mensaje(self, "Éxito", f"Resultados guardados en {path}", modo_dia=self.modo_dia, icon=QMessageBox.Information)
        else:
            if not results:
                self.mostrar_placeholder()
                return
            self.table.setSortingEnabled(False)  # Desactivar mientras se actualiza
            self.table.setColumnCount(len(columns))
            self.table.setHorizontalHeaderLabels(columns)
            self.table.setRowCount(len(results))
            idx_confianza = columns.index('Confianza Maliciosa')
            idx_reportes = columns.index('Número de reportes (365 días)') if 'Número de reportes (365 días)' in columns else -1
            idx_ultima_fecha = columns.index('Última vez reportada') if 'Última vez reportada' in columns else -1
            for r, row in enumerate(results):
                for c, key in enumerate(columns):
                    value = str(row.get(key, ""))
                    if c == idx_confianza or c == idx_reportes:
                        item = NumericTableWidgetItem(value)
                    elif c == idx_ultima_fecha:
                        item = DateTableWidgetItem(value)
                    else:
                        item = QTableWidgetItem(value)
                    item.setTextAlignment(Qt.AlignCenter)
                    self.table.setItem(r, c, item)
                # Lanzar fade-in solo en la celda de Confianza Maliciosa
                self.confianza_delegate.start_fade_in(self.table, r, idx_confianza)
            self.table.resizeColumnsToContents()
            self.table.resizeRowsToContents()
            self.table.verticalScrollBar().setValue(0)
            self.update_widget_positions()
            opacity_effect = QGraphicsOpacityEffect(self.stacked)
            self.stacked.setGraphicsEffect(opacity_effect)
            opacity_effect.setOpacity(0.0)
            self.stacked.setCurrentWidget(self.table)
            QTimer.singleShot(10, lambda: animate_widget(self.stacked, duration=900))
            self.table.setSortingEnabled(True)  # Reactivar ordenación después de actualizar
        from PySide6.QtWidgets import QApplication
        if QApplication.focusWidget():
            QApplication.focusWidget().clearFocus()
        # --- Evitar que el foco vuelva a un widget interactivo ---
        QTimer.singleShot(0, lambda: self.centralWidget().setFocus(Qt.OtherFocusReason))
        # --- Asegurar que el hilo termine antes de cerrar la ventana ---
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()

    # ===============================
    # MOSTRAR PLACEHOLDER (mostrar_placeholder)
    # - Muestra un mensaje o espacio vacío cuando no hay resultados en la tabla.
    # - Gestiona la animación de salida de la tabla y el cambio de visibilidad.
    # ===============================
    def mostrar_placeholder(self):
        def after_out():
            self.placeholder.setText("")
            self.placeholder.setStyleSheet("background: transparent; border: none;")
            self.stacked.setCurrentWidget(self.placeholder)
            self.table.clearContents()
            self.table.setRowCount(0)
        if self.stacked.currentWidget() == self.table:
            animate_widget_out(self.stacked, duration=900, on_finished=after_out)
        else:
            after_out()

    def showEvent(self, event):
        super().showEvent(event)
        if not self._animacion_inicial_aplicada:
            # --- Deshabilitar ribbon y botones antes de la animación ---
            self.ribbon.setEnabled(False)
            self.ribbon_btn_config.setEnabled(False)
            self.ribbon_btn_help.setEnabled(False)
            # Animar el ribbon primero, saliendo desde arriba
            pos_final_ribbon = self.ribbon.pos()
            pos_inicio_ribbon = pos_final_ribbon - QPoint(0, 60)
            self.ribbon.move(pos_inicio_ribbon)
            def habilitar_ribbon():
                self.ribbon.setEnabled(True)
                self.ribbon_btn_config.setEnabled(True)
                self.ribbon_btn_help.setEnabled(True)
            animate_widget(self.ribbon, duration=1800, pos_final=pos_final_ribbon, on_finished=habilitar_ribbon)
            # Animar los demás widgets como antes
            animate_widget(self.inp_title, duration=1800)
            animate_widget(self.out_title, duration=1800)
            animate_widget(self.inp_box, duration=1800)
            animate_widget(self.out_box, duration=1800)
            animate_widget(self.stacked, duration=1800)
            animate_widget(self.ip_line, duration=1800)
            animate_widget(self.btn_analyze, duration=1800, on_finished=self.habilitar_comboboxes)
            # QTimer.singleShot(1800, self._mostrar_snackbar_inicio)  # Eliminado porque ya no existe el snackbar
            self._animacion_inicial_aplicada = True
            QTimer.singleShot(0, lambda: self.centralWidget().setFocus())
            QTimer.singleShot(2000, lambda: self.shortcut_light.setEnabled(True))  # Habilitar Ctrl+L tras 2 segundos
        # self.mostrar_placeholder()  # Línea comentada para evitar limpiar la tabla al restaurar la ventana

    def moveEvent(self, event):
        super().moveEvent(event)
        if self.circular_loader and self.circular_loader.isVisible():
            parent_geom = self.geometry()
            x = parent_geom.x() + (parent_geom.width() - self.circular_loader.width()) // 2
            y = parent_geom.y() + (parent_geom.height() - self.circular_loader.height()) // 2
            self.circular_loader.move(x, y)

    def cambiar_modo_entrada(self, idx):
        if idx == 0:  # "Introducir IPs"
            self.excel_label.setVisible(False)
            self.ip_line.setGraphicsEffect(None)
            effect = QGraphicsOpacityEffect(self.ip_line)
            effect.setOpacity(1.0)
            self.ip_line.setGraphicsEffect(effect)
            self.ip_line.setVisible(True)
            self.ip_line.raise_()
            self.ip_line.repaint()
            self.ip_line.setGraphicsEffect(None)
            # Calcular posición absoluta final
            w, h = self.width(), self.height()
            fx = w / self.BASE_WIDTH
            fy = h / self.BASE_HEIGHT
            pos_final = QPoint(int(60 * fx), int(120 * fy))
            self.ip_line.move(pos_final)
            # --- Aquí el cambio importante ---
            def on_anim_in_finished():
                # Forzar la posición final después de la animación
                w, h = self.width(), self.height()
                fx = w / self.BASE_WIDTH
                fy = h / self.BASE_HEIGHT
                pos_final = QPoint(int(60 * fx), int(120 * fy))
                self.ip_line.move(pos_final)
            animate_widget(self.ip_line, duration=900, pos_final=pos_final, on_finished=on_anim_in_finished)
        else:  # "Excel" (idx == 1)
            if self.ip_line.isVisible():
                def ocultar_y_limpiar():
                    self.ip_line.setVisible(False)
                    self.ip_line.setGraphicsEffect(None)
                animate_widget_out(self.ip_line, duration=450, on_finished=ocultar_y_limpiar)
            else:
                self.ip_line.setVisible(False)
                self.ip_line.setGraphicsEffect(None)
            self.excel_label.setVisible(True)

    def habilitar_comboboxes(self):
        self.input_combo.setEnabled(True)
        self.output_combo.setEnabled(True)
        self.btn_analyze.setEnabled(True)

    def abrir_config_api(self):
        # Ocultar pantalla de carga si está visible
        if hasattr(self, 'circular_loader') and self.circular_loader and self.circular_loader.isVisible():
            self.circular_loader.close()
            self.circular_loader = None
        # Ocultar tooltip si está visible
        if hasattr(self, 'snackbar_tooltip'):
            self.snackbar_tooltip.hide_tooltip()
        self.close()
        self.api_config = ApiConfigWindow()
        self.api_config.show()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.WindowStateChange:
            if not self.isMinimized() and hasattr(self, "btn_analyze"):
                # Si la animación está activa, reiníciala
                if self.btn_analyze._shine_anim.state() == QPropertyAnimation.Running:
                    self.btn_analyze._shine_anim.stop()
                    self.btn_analyze._shine_anim.setStartValue(-self.btn_analyze.width())
                    self.btn_analyze._shine_anim.setEndValue(self.btn_analyze.width())
                    self.btn_analyze._shine_anim.setDuration(700)
                    self.btn_analyze._shine_anim.setEasingCurve(QEasingCurve.OutQuad)
                    self.btn_analyze._shine_anim.start()
                self.btn_analyze.update()

    def seleccionar_fila_entera(self, row, column):
        """
        Selecciona toda la fila cuando se hace doble clic en cualquier celda.
        """
        self.table.selectRow(row)

    def actualizar_ribbon_modo(self):
        """
        Actualiza el fondo y el borde del ribbon según el modo claro/oscuro.
        El fondo del ribbon será igual al color de fondo del botón del ribbon.
        """
        if getattr(self, 'modo_dia', False):
            fondo = "rgb(224, 224, 224)"  # Más claro que antes
            color_texto = "#222"
            borde = "#bdbdbd"
            color_hover = "#d0d0d0"  # Más oscuro para mejor contraste
            menu_bg = "#fafafa"
            menu_text = "#222"
            menu_sel = "#e0e0e0"
            focus_style = f"""
QPushButton#ribbonBtnConfig:focus, QPushButton#ribbonBtnHelp:focus {{
    background: {color_hover};
    color: {color_texto};
    outline: none;
}}
"""
            hover_style = f"""
QPushButton#ribbonBtnConfig:hover, QPushButton#ribbonBtnHelp:hover {{
    background: {color_hover};
    color: {color_texto};
}}
"""
        else:
            fondo = "rgb(22, 20, 20)"  # Más oscuro que antes
            color_texto = "#f2f2f7"
            borde = "#232323"
            color_hover = "#232323"
            menu_bg = "#161414"
            menu_text = "#f2f2f7"
            menu_sel = "#232323"
            focus_style = f"""
QPushButton#ribbonBtnConfig:focus, QPushButton#ribbonBtnHelp:focus {{
    background: {color_hover};
    color: {color_texto};
    outline: none;
}}
"""
            hover_style = f"""
QPushButton#ribbonBtnConfig:hover, QPushButton#ribbonBtnHelp:hover {{
    background: {color_hover};
    color: {color_texto};
}}
"""
        self.ribbon.setStyleSheet(f"""
            QWidget#customRibbon {{
                background: {fondo};
            }}
            QPushButton#ribbonBtnConfig, QPushButton#ribbonBtnHelp {{
                background: {fondo};
                color: {color_texto};
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                border: none;
                padding: 0 8px;
                min-height: 26px;
                min-width: 44px;
                border-radius: 0;
            }}
            {hover_style}
            {focus_style}
        """)
        self.ribbon_menu.setStyleSheet(f"""
            QMenu {{
                background: {menu_bg};
                color: {menu_text};
                border: none;
                border-radius: 0px;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                padding: 2px 0;
            }}
            QMenu::item {{
                padding: 6px 18px 6px 14px;
                min-height: 26px;
                background: transparent;
                border-radius: 0px;
            }}
            QMenu::item:selected {{
                background: {menu_sel};
                color: {menu_text};
            }}
        """)
        self.ribbon_help_menu.setStyleSheet(f"""
            QMenu {{
                background: {menu_bg};
                color: {menu_text};
                border: none;
                border-radius: 0px;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                padding: 2px 0;
            }}
            QMenu::item {{
                padding: 6px 18px 6px 14px;
                min-height: 26px;
                background: transparent;
                border-radius: 0px;
            }}
            QMenu::item:selected {{
                background: {menu_sel};
                color: {menu_text};
            }}
        """)

    def mostrar_info_ayuda(self):
        texto = (
            "<b>NetTrace</b><br>"
            "<br>"
            "Herramienta orientada al análisis de IPs, para uso exclusivo personal y sin propósitos comerciales. \n"
        )
        mostrar_mensaje(self, "Información", texto, modo_dia=self.modo_dia)

    def mostrar_atajos_ayuda(self):
        texto = (
            "<b>Atajos de teclado:</b><br>"
            "<div style='min-width:420px; text-align:left; margin-top:6px;'>"
            "<b>Ctrl + T</b>: Configuración de APIs<br>"
            "<b>Ctrl + L</b>: Modo claro/oscuro<br>"
            "<b>Tab</b> / <b>Shift+Tab</b>: Navegación<br>"
            "<b>Flechas</b>: Navegación<br>"
            "<b>Enter</b>: Acción"
            "</div>"
        )
        mostrar_mensaje(self, "Atajos", texto, modo_dia=self.modo_dia)

    def mostrar_terminos_condiciones(self):
        import sys
        ruta = os.path.join(NETTRACE_DIR, "terminos_y_condiciones.txt")
        texto = (
            "Copyright (c) 2025 Tobías R.\n"
            "Todos los derechos reservados.\n\n"
            "Este software ha sido desarrollado íntegramente por Tobías R. como proyecto personal, fuera del horario laboral y sin emplear recursos, infraestructura, asistencia o propiedad intelectual de empresa, institución u organización alguna. La totalidad del código es propiedad exclusiva del autor.\n\n"
            "Nota: Esta aplicación está concebida para utilizarse con las versiones gratuitas ('free tier') de las APIs correspondientes. El funcionamiento óptimo del software requiere que el usuario configure sus propias claves gratuitas para cada servicio.\n\n"
            "1. DEFINICIÓN DE USO PERSONAL:\n"
            "   Se entiende por uso personal la instalación y ejecución de este software en un único equipo de propiedad del usuario. Bajo ningún concepto podrá emplearse como herramienta de empresa, entidad corporativa o institución, ni formar parte de procesos o sistemas laborales ajenos al ámbito privado.\n\n"
            "2. CONDICIONES DE USO:\n"
            "   Sin autorización previa y por escrito del autor, queda prohibido:\n"
            "   • El uso comercial, corporativo o institucional\n"
            "   • La utilización por parte de empresas, organizaciones o entidades gubernamentales\n"
            "   • La incorporación total o parcial del código en productos, servicios, plataformas o sistemas de terceros\n"
            "   • La redistribución, publicación o puesta a disposición del código en cualquier medio o repositorio, público o privado\n"
            "   • La modificación del código para crear proyectos derivados, adaptaciones, variantes, forks o reutilizaciones parciales\n"
            "   • El reempaquetado, renombramiento o presentación bajo o con otra autoría\n"
            "   • El empleo en cursos, capacitaciones, materiales académicos o de divulgación sin consentimiento expreso\n"
            "   • El uso como base técnica para desarrollos ajenos, incluso con fines no comerciales\n\n"
            "3. PERMISOS LIMITADOS:\n"
            "   Se concede únicamente permiso para:\n"
            "   • Configurar y utilizar claves de API propias (gratuitas) con fines locales y privados\n"
            "   • Ejecutar el software en su forma original, sin modificación ni redistribución\n"
            "   • Instalarlo en un único equipo de propiedad del usuario, sin sublicenciar ni ceder dichos permisos\n\n"
            "4. DURACIÓN DE LA LICENCIA Y REVOCACIÓN:\n"
            "   Vigencia indefinida, salvo revocación expresa del autor. Cualquier autorización o revocación deberá realizarse mediante comunicación escrita entregada en mano por el autor o persona autorizada.\n\n"
            "5. CLÁUSULA DE FUERZA MAYOR:\n"
            "   El autor no será responsable de daños, perjuicios, pérdidas ni costes indirectos o emergentes derivados de eventos fuera de su control razonable, incluidos, entre otros, fallos de red, interrupciones de servicios de terceros, desastres naturales, actos de autoridad o incidencias de infraestructura.\n\n"
            "6. RESPONSABILIDAD SOBRE CLAVES DE API:\n"
            "   El autor no asume responsabilidad por la gestión, seguridad, límites de uso, costes, cargos o sanciones asociadas a las claves de API configuradas por el usuario para servicios externos.\n\n"
            "7. JURISDICCIÓN Y LEY APLICABLE:\n"
            "   Esta licencia se rige e interpreta de conformidad con la legislación española vigente en materia de derechos de autor, sin perjuicio de normas imperativas en otras jurisdicciones. Cualquier disputa se someterá a los tribunales competentes de España.\n\n"
            "8. EXENCIÓN DE RESPONSABILIDAD:\n"
            "   El software se proporciona «tal cual», sin garantía de ningún tipo, expresa o implícita, incluyendo, entre otras, garantías de funcionamiento, idoneidad para un propósito específico o ausencia de errores. No se otorga derecho a reembolso de costes. En ningún caso el autor será responsable de daños, pérdidas o perjuicios directos o indirectos derivados del uso o imposibilidad de uso del software.\n\n"  
        )
        if not os.path.exists(ruta):
            try:
                with open(ruta, 'w', encoding='utf-8') as f:
                    f.write(texto)
            except Exception as e:
                mostrar_mensaje(self, "Error", f"No se pudo crear el archivo de términos y condiciones: {e}", modo_dia=self.modo_dia)
                return
        # Abrir el archivo con el editor predeterminado según el sistema operativo
        try:
            if sys.platform.startswith('win'):
                os.startfile(ruta)
            elif sys.platform.startswith('darwin'):
                import subprocess
                subprocess.Popen(['open', ruta])
            else:
                import subprocess
                subprocess.Popen(['xdg-open', ruta])
        except Exception as e:
            mostrar_mensaje(self, "Error", f"No se pudo abrir el archivo de términos y condiciones: {e}", modo_dia=self.modo_dia)

def animate_widget(widget, duration=900, pos_final=None, on_finished=None):
    # Efecto de opacidad
    opacity_effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(opacity_effect)
    opacity_effect.setOpacity(0.0)
    # Animación de opacidad
    anim_opacity = QPropertyAnimation(opacity_effect, b"opacity")
    anim_opacity.setStartValue(0.0)
    anim_opacity.setEndValue(1.0)
    anim_opacity.setDuration(duration)
    anim_opacity.setEasingCurve(QEasingCurve.InOutQuad)
    # Animación de barrido (posición vertical)
    if pos_final is None:
        pos_final = widget.pos()
        anim_pos = QPropertyAnimation(widget, b"pos")
        anim_pos.setStartValue(pos_final + QPoint(0, 60))
        anim_pos.setEndValue(pos_final)
    else:
        # Si pos_final se pasa, el widget ya debe estar en la posición inicial deseada
        anim_pos = QPropertyAnimation(widget, b"pos")
        anim_pos.setStartValue(widget.pos())
        anim_pos.setEndValue(pos_final)
    anim_pos.setDuration(duration)
    anim_pos.setEasingCurve(QEasingCurve.InOutQuad)
    # Lanzar ambas animaciones
    anim_opacity.start()
    anim_pos.start()
    # Mantener referencia para evitar que el recolector de basura las elimine
    widget._anim_opacity = anim_opacity
    widget._anim_pos = anim_pos
    if on_finished:
        anim_pos.finished.connect(on_finished)

def shake_widget(widget, shake_distance=10, shake_times=6, duration=300):
    # Animación de sacudida horizontal
    orig_pos = widget.pos()
    anim = QPropertyAnimation(widget, b"pos")
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Linear)
    for i in range(shake_times):
        offset = shake_distance if i % 2 == 0 else -shake_distance
        anim.setKeyValueAt(i / shake_times, orig_pos + QPoint(offset, 0))
    anim.setKeyValueAt(1, orig_pos)
    anim.start()
    widget._shake_anim = anim  # Mantener referencia

def animate_widget_out(widget, duration=900, on_finished=None, pos_final=None):
    # Efecto de opacidad
    opacity_effect = widget.graphicsEffect()
    if not isinstance(opacity_effect, QGraphicsOpacityEffect):
        opacity_effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(opacity_effect)
    # Animación de opacidad
    anim_opacity = QPropertyAnimation(opacity_effect, b"opacity")
    current_op = opacity_effect.opacity() if opacity_effect else 1.0
    anim_opacity.setStartValue(current_op)
    anim_opacity.setEndValue(0.0)
    anim_opacity.setDuration(duration)
    anim_opacity.setEasingCurve(QEasingCurve.InOutQuad)
    # Animación de barrido (posición vertical)
    orig_pos = widget.pos()
    anim_pos = QPropertyAnimation(widget, b"pos")
    anim_pos.setStartValue(orig_pos)
    if pos_final is not None:
        anim_pos.setEndValue(pos_final)
    else:
        anim_pos.setEndValue(orig_pos + QPoint(0, 60))  # Por defecto, hacia abajo
    anim_pos.setDuration(duration)
    anim_pos.setEasingCurve(QEasingCurve.InOutQuad)
    # Conectar finalización
    if on_finished:
        anim_opacity.finished.connect(on_finished)
    # Lanzar ambas animaciones
    anim_opacity.start()
    anim_pos.start()
    widget._anim_opacity_out = anim_opacity
    widget._anim_pos_out = anim_pos

def formatear_fecha_estandar(fecha_iso):
    if not fecha_iso or fecha_iso == 'Sin reportes':
        return 'Sin reportes'
    try:
        dt = datetime.fromisoformat(fecha_iso.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except Exception:
        return fecha_iso  # Si hay error, muestra el original

def animate_label_text_change(label, new_text, duration=500, on_finished=None):
    # Efecto de opacidad y barrido vertical al cambiar el texto
    from PySide6.QtWidgets import QGraphicsOpacityEffect
    from PySide6.QtCore import QPropertyAnimation, QEasingCurve, QPoint
    
    # Preparar opacidad
    opacity_effect = label.graphicsEffect()
    if not isinstance(opacity_effect, QGraphicsOpacityEffect):
        opacity_effect = QGraphicsOpacityEffect(label)
        label.setGraphicsEffect(opacity_effect)
    
    # Usar la posición actual del layout como referencia
    if label.parentWidget() and label.parentWidget().layout():
        label.parentWidget().layout().activate()
        layout = label.parentWidget().layout()
        orig_pos = None
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item and item.widget() is label:
                orig_pos = item.geometry().topLeft()
                break
        if orig_pos is None:
            orig_pos = label.pos()
    else:
        orig_pos = label.pos()
    
    # Animación de opacidad (fade out)
    anim_out = QPropertyAnimation(opacity_effect, b"opacity")
    anim_out.setStartValue(1.0)
    anim_out.setEndValue(0.0)
    anim_out.setDuration(duration // 2)
    anim_out.setEasingCurve(QEasingCurve.InOutQuad)
    # Animación de barrido (hacia abajo)
    anim_pos_out = QPropertyAnimation(label, b"pos")
    anim_pos_out.setStartValue(orig_pos)
    anim_pos_out.setEndValue(orig_pos + QPoint(0, 20))
    anim_pos_out.setDuration(duration // 2)
    anim_pos_out.setEasingCurve(QEasingCurve.InOutQuad)
    
    def on_fade_out_finished():
        label.setText(new_text)
        # Animación de opacidad (fade in)
        anim_in = QPropertyAnimation(opacity_effect, b"opacity")
        anim_in.setStartValue(0.0)
        anim_in.setEndValue(1.0)
        anim_in.setDuration(duration // 2)
        anim_in.setEasingCurve(QEasingCurve.InOutQuad)
        # Animación de barrido (hacia arriba, vuelve a la posición original)
        anim_pos_in = QPropertyAnimation(label, b"pos")
        anim_pos_in.setStartValue(label.pos())
        anim_pos_in.setEndValue(orig_pos)
        anim_pos_in.setDuration(duration // 2)
        anim_pos_in.setEasingCurve(QEasingCurve.InOutQuad)
        def on_anim_in_finished():
            # Forzar la posición del label a la que le da el layout
            if label.parentWidget() and label.parentWidget().layout():
                label.parentWidget().layout().activate()
                layout = label.parentWidget().layout()
                for i in range(layout.count()):
                    item = layout.itemAt(i)
                    if item and item.widget() is label:
                        label.move(item.geometry().topLeft())
                        break
            if on_finished:
                on_finished()  # Llama al callback si se pasó
        anim_in.finished.connect(on_anim_in_finished)
        anim_in.start()
        anim_pos_in.start()
        # Mantener referencia
        label._anim_in = anim_in
        label._anim_pos_in = anim_pos_in
    anim_out.finished.connect(on_fade_out_finished)
    anim_out.start()
    anim_pos_out.start()
    # Mantener referencia
    label._anim_out = anim_out
    label._anim_pos_out = anim_pos_out

# --- Ventana de configuración de APIs ---
class ApiConfigWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.modo_dia = cargar_modo_config()
        self.setWindowIcon(get_icono_desde_base64())
        self.setWindowTitle("Configuración de APIs")
        set_modo_claro_oscuro_apiconfig(self, self.modo_dia)
        self.setFont(QFont("San Francisco"))
        self.setFixedSize(620, 500)
        central = QWidget(self)
        self.setCentralWidget(central)
        # Parámetros proporcionales
        total_width = 620
        field_width = 520
        left = (total_width - field_width) // 2  # 50px
        label_width = 220
        luz_offset = label_width + 10
        vertical_gap = 70
        help_gap = 38
        # AbuseIPDB
        abuse_y = 40
        abuse_label = QLabel("AbuseIPDB API Key", central)
        abuse_label.setStyleSheet("font-weight: bold; color: #f2f2f7; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        abuse_label.setAlignment(Qt.AlignCenter)
        abuse_label.adjustSize()
        abuse_label_x = left + (field_width - abuse_label.width())//2
        abuse_label.move(abuse_label_x, abuse_y)
        abuse_label.setObjectName("abuse_title")
        self.abuse_luz = QLabel("●", central)
        self.abuse_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.abuse_luz.adjustSize()
        # Centrar verticalmente la luz respecto al label
        luz_y = abuse_y + (abuse_label.height() - self.abuse_luz.height()) // 2
        self.abuse_luz.move(abuse_label_x + abuse_label.width() + 2, luz_y)
        self.abuse_edit = QLineEdit(central)
        self.abuse_edit.setText(ABUSEIPDB_API_KEY)
        self.abuse_edit.setFixedWidth(field_width)
        self.abuse_edit.setAlignment(Qt.AlignCenter)
        self.abuse_edit.move(left, abuse_y + 28)
        self.abuse_edit.contextMenuEvent = lambda event: None
        self.abuse_help = QLabel("Permite consultar la reputación y reportes de una IP sospechosa", central)
        self.abuse_help.setWordWrap(True)
        self.abuse_help.setFixedWidth(field_width)
        self.abuse_help.setStyleSheet("color: #aaa; font-size: 12px; margin-top: 9px; margin-bottom: 4px; padding-left: 0px; padding-right: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.abuse_help.setAlignment(Qt.AlignHCenter)
        self.abuse_help.move(left, abuse_y + 28 + 36)
        # IPinfo
        ipinfo_y = abuse_y + 28 + 36 + 50
        ipinfo_label = QLabel("IPinfo API Key", central)
        ipinfo_label.setStyleSheet("font-weight: bold; color: #f2f2f7; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        ipinfo_label.setAlignment(Qt.AlignCenter)
        ipinfo_label.adjustSize()
        ipinfo_label_x = left + (field_width - ipinfo_label.width())//2
        ipinfo_label.move(ipinfo_label_x, ipinfo_y)
        ipinfo_label.setObjectName("ipinfo_title")
        self.ipinfo_luz = QLabel("●", central)
        self.ipinfo_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.ipinfo_luz.adjustSize()
        luz_y = ipinfo_y + (ipinfo_label.height() - self.ipinfo_luz.height()) // 2
        self.ipinfo_luz.move(ipinfo_label_x + ipinfo_label.width() + 2, luz_y)
        self.ipinfo_edit = QLineEdit(central)
        self.ipinfo_edit.setText(IPINFO_API_KEY)
        self.ipinfo_edit.setFixedWidth(field_width)
        self.ipinfo_edit.setAlignment(Qt.AlignCenter)
        self.ipinfo_edit.move(left, ipinfo_y + 28)
        self.ipinfo_edit.contextMenuEvent = lambda event: None
        self.ipinfo_help = QLabel("Permite obtener información de geolocalización y ASN de una IP", central)
        self.ipinfo_help.setWordWrap(True)
        self.ipinfo_help.setFixedWidth(field_width)
        self.ipinfo_help.setStyleSheet("color: #aaa; font-size: 12px; margin-top: 9px; margin-bottom: 4px; padding-left: 0px; padding-right: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.ipinfo_help.setAlignment(Qt.AlignHCenter)
        self.ipinfo_help.move(left, ipinfo_y + 28 + 36)
        # VPNAPI.IO
        vpnapi_y = ipinfo_y + 28 + 36 + 50
        vpnapi_label = QLabel("VPNAPI.IO API Key", central)
        vpnapi_label.setStyleSheet("font-weight: bold; color: #f2f2f7; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        vpnapi_label.setAlignment(Qt.AlignCenter)
        vpnapi_label.adjustSize()
        vpnapi_label_x = left + (field_width - vpnapi_label.width())//2
        vpnapi_label.move(vpnapi_label_x, vpnapi_y)
        vpnapi_label.setObjectName("vpnapi_title")
        self.vpnapi_luz = QLabel("●", central)
        self.vpnapi_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.vpnapi_luz.adjustSize()
        luz_y = vpnapi_y + (vpnapi_label.height() - self.vpnapi_luz.height()) // 2
        self.vpnapi_luz.move(vpnapi_label_x + vpnapi_label.width() + 2, luz_y)
        self.vpnapi_edit = QLineEdit(central)
        self.vpnapi_edit.setText(VPNAPI_KEY)
        self.vpnapi_edit.setFixedWidth(field_width)
        self.vpnapi_edit.setAlignment(Qt.AlignCenter)
        self.vpnapi_edit.move(left, vpnapi_y + 28)
        self.vpnapi_edit.contextMenuEvent = lambda event: None
        self.vpnapi_help = QLabel("Permite detectar si una IP usa VPN, proxy, Tor o relay", central)
        self.vpnapi_help.setWordWrap(True)
        self.vpnapi_help.setFixedWidth(field_width)
        self.vpnapi_help.setStyleSheet("color: #aaa; font-size: 12px; margin-top: 9px; margin-bottom: 4px; padding-left: 0px; padding-right: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        self.vpnapi_help.setAlignment(Qt.AlignHCenter)
        self.vpnapi_help.move(left, vpnapi_y + 28 + 36)
        # Botones
        btn_y = self.vpnapi_help.y() + self.vpnapi_help.height() + 50  # 50 es el mismo vertical_gap usado entre bloques
        nueva_altura = btn_y + 32 + 50  # 32 = altura del botón, 50 = margen inferior
        self.setFixedSize(620, nueva_altura)
        self.btn_save = SimpleAnimatedButton("Guardar", central)
        self.btn_save.setMinimumWidth(240)
        self.btn_save.setMaximumWidth(240)
        self.btn_save.setMinimumHeight(32)
        self.btn_save.setMaximumHeight(32)
        self.btn_save.clicked.connect(self.guardar_y_reabrir_principal)
        self.btn_save.setEnabled(False)  # <-- Deshabilitar al inicio
        self.btn_test = SimpleAnimatedButton("Verificar APIs", central)
        self.btn_test.setMinimumWidth(240)
        self.btn_test.setMaximumWidth(240)
        self.btn_test.setMinimumHeight(32)
        self.btn_test.setMaximumHeight(32)
        self.btn_test.clicked.connect(self.verificar_apis)
        self.btn_test.setEnabled(False)  # <-- Deshabilitar al inicio
        self.btn_test.move(330, btn_y)
        self.mostrar_estado_apis(None)
        self.btn_save.move(50, btn_y)
        # Atajo Ctrl+T para volver a la pantalla principal
        self.shortcut_api = QShortcut(QKeySequence("Ctrl+T"), self)
        self.shortcut_api.activated.connect(self.reabrir_principal)
        self.shortcut_api.setEnabled(False)  # Deshabilitar Ctrl+T hasta que termine la animación de entrada
        # --- NUEVO: Atajo para alternar modo día ---
        self.shortcut_light = QShortcut(QKeySequence("Ctrl+L"), self)
        self.shortcut_light.activated.connect(self.toggle_modo_dia)
        self.shortcut_light.setEnabled(False)  # Deshabilitar al inicio

        set_modo_claro_oscuro_apiconfig(self, self.modo_dia)

        # ... al final del constructor de ApiConfigWindow ...
        if self.modo_dia:
            for label_name in ["abuse_title", "ipinfo_title", "vpnapi_title"]:
                label = self.findChild(QLabel, label_name)
                if label:
                    label.setStyleSheet("font-weight: bold; color: #222; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")

    def toggle_modo_dia(self):
        # Cerrar pantalla de carga circular si está activa
        if hasattr(self, 'circular_loader') and self.circular_loader and self.circular_loader.isVisible():
            self.circular_loader.close()
            self.circular_loader = None
        # Ocultar tooltip si está visible
        if hasattr(self, 'snackbar_tooltip'):
            self.snackbar_tooltip.hide_tooltip()
        self.modo_dia = not self.modo_dia
        guardar_modo_config(self.modo_dia)
        self.close()
        global VENTANA_API_GLOBAL
        VENTANA_API_GLOBAL = ApiConfigWindow()
        VENTANA_API_GLOBAL.show()

        # ... al final del método toggle_modo_dia de ApiConfigWindow ...
        if self.modo_dia:
            for label_name in ["abuse_title", "ipinfo_title", "vpnapi_title"]:
                label = self.findChild(QLabel, label_name)
                if label:
                    label.setStyleSheet("font-weight: bold; color: #222; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")

    def mostrar_estado_apis(self, resultados):
        # Actualiza las luces de cada campo según resultados
        if resultados is None:
            # Solo setea el color base, sin animar
            self.abuse_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
            self.ipinfo_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
            self.vpnapi_luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        elif not resultados:
            animar_luz_estado(self.abuse_luz, "#e53935")
            animar_luz_estado(self.ipinfo_luz, "#e53935")
            animar_luz_estado(self.vpnapi_luz, "#e53935")
        else:
            for nombre_api, ok, _ in resultados:
                color = "#4caf50" if ok else "#e53935"
                if nombre_api == "AbuseIPDB":
                    animar_luz_estado(self.abuse_luz, color)
                elif nombre_api == "IPinfo":
                    animar_luz_estado(self.ipinfo_luz, color)
                elif nombre_api == "VPNAPI.IO":
                    animar_luz_estado(self.vpnapi_luz, color)

    def guardar_y_reabrir_principal(self):
        global ABUSEIPDB_API_KEY, IPINFO_API_KEY, VPNAPI_KEY
        ABUSEIPDB_API_KEY = self.abuse_edit.text().strip()
        IPINFO_API_KEY = self.ipinfo_edit.text().strip()
        VPNAPI_KEY = self.vpnapi_edit.text().strip()
        guardar_apis_config({
            'ABUSEIPDB_API_KEY': ABUSEIPDB_API_KEY,
            'IPINFO_API_KEY': IPINFO_API_KEY,
            'VPNAPI_KEY': VPNAPI_KEY
        })
        # --- NUEVO: Marcar la primera ejecución como realizada al guardar ---
        try:
            marcar_ejecucion_realizada()
        except Exception as e:
            print(f"Error al marcar la primera ejecución: {e}")
        self.mostrar_estado_apis([
            ("Guardado", True, "¡Las llaves han sido guardadas! Cerrando...")
        ])
        QTimer.singleShot(900, self.reabrir_principal)

    def reabrir_principal(self):
        self.close()
        self.main = MainWindow()
        self.main.show()

    def verificar_apis(self):
        abuse = self.abuse_edit.text().strip()
        ipinfo = self.ipinfo_edit.text().strip()
        vpnapi = self.vpnapi_edit.text().strip()
        # Quitar el foco de todos los widgets de entrada
        self.setFocus()
        self.btn_test.setEnabled(False)
        self.btn_save.setEnabled(False)
        # Lanzar worker en hilo
        self.api_thread = QThread()
        self.api_worker = ApiVerifierWorker(abuse, ipinfo, vpnapi)
        self.api_worker.moveToThread(self.api_thread)
        self.api_thread.started.connect(self.api_worker.run)
        self.api_worker.finished.connect(self.on_api_verificado)
        self.api_worker.finished.connect(self.api_thread.quit)
        self.api_worker.finished.connect(self.api_worker.deleteLater)
        self.api_thread.finished.connect(self.api_thread.deleteLater)
        self.api_thread.start()

    def on_api_verificado(self, resultados):
        self.mostrar_estado_apis(resultados)
        self.btn_test.setEnabled(True)
        self.btn_save.setEnabled(True)

    def showEvent(self, event):
        super().showEvent(event)
        # Bloques de widgets por API
        abuse_widgets = [
            self.findChild(QLabel, "abuse_title"),
            self.abuse_luz, self.abuse_edit, self.abuse_help
        ]
        ipinfo_widgets = [
            self.findChild(QLabel, "ipinfo_title"),
            self.ipinfo_luz, self.ipinfo_edit, self.ipinfo_help
        ]
        vpnapi_widgets = [
            self.findChild(QLabel, "vpnapi_title"),
            self.vpnapi_luz, self.vpnapi_edit, self.vpnapi_help
        ]
        buttons = [self.btn_save, self.btn_test]

        bloques = [abuse_widgets, ipinfo_widgets, vpnapi_widgets, buttons]
        delay = 0
        bloque_delay = 500  # ms entre bloques

        # Asegurar opacidad 0 antes de animar
        for bloque in bloques:
            for w in bloque:
                if w is not None:
                    effect = QGraphicsOpacityEffect(w)
                    w.setGraphicsEffect(effect)
                    effect.setOpacity(0.0)

        for i, bloque in enumerate(bloques):
            # Si es el último bloque (los botones), habilitar al terminar la animación
            if i == len(bloques) - 1:
                QTimer.singleShot(delay, lambda bloque=bloque: [animate_widget(w, duration=1400, on_finished=self.habilitar_botones_api) if w is self.btn_test else animate_widget(w, duration=1400) for w in bloque if w is not None])
            else:
                QTimer.singleShot(delay, lambda bloque=bloque: [animate_widget(w, duration=1400) for w in bloque if w is not None])
            delay += bloque_delay

        # --- Habilitar el atajo Ctrl+L para alternar modo día/oscuro tras 3 segundos ---
        QTimer.singleShot(3000, lambda: self.shortcut_light.setEnabled(True))

    def habilitar_botones_api(self):
        self.btn_save.setEnabled(True)
        self.btn_test.setEnabled(True)
        self.shortcut_api.setEnabled(True)  # Habilitar Ctrl+T al terminar la animación de entrada

# --- Animación de la luz de estado de API ---
def animar_luz_estado(luz_label, color_final):
    """
    Anima la opacidad (parpadeo) y el color de la luz de estado de una API.
    Cambia suavemente el color de la luz para indicar éxito o error.
    """
    from PySide6.QtGui import QColor
    import re
    # Fade (parpadeo)
    if not isinstance(luz_label.graphicsEffect(), QGraphicsOpacityEffect):
        effect = QGraphicsOpacityEffect(luz_label)
        luz_label.setGraphicsEffect(effect)
    else:
        effect = luz_label.graphicsEffect()
    anim = QPropertyAnimation(effect, b"opacity")
    anim.setDuration(700)
    anim.setKeyValueAt(0.0, 1.0)
    anim.setKeyValueAt(0.2, 0.2)
    anim.setKeyValueAt(0.5, 1.0)
    anim.setKeyValueAt(0.7, 0.2)
    anim.setKeyValueAt(1.0, 1.0)
    anim.setEasingCurve(QEasingCurve.InOutQuad)
    anim.start()
    luz_label._anim_opacidad = anim
    # Transición de color
    current_style = luz_label.styleSheet()
    match = re.search(r'color: (#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}|rgb\([^)]*\));', current_style)
    color_ini = match.group(1) if match else "#888"
    c_ini = QColor(color_ini)
    c_fin = QColor(color_final)
    steps = 12
    interval = 40
    def set_color_step(step):
        t = step / steps
        r = int(c_ini.red() + (c_fin.red() - c_ini.red()) * t)
        g = int(c_ini.green() + (c_fin.green() - c_ini.green()) * t)
        b = int(c_ini.blue() + (c_fin.blue() - c_ini.blue()) * t)
        luz_label.setStyleSheet(f"font-size: 18px; color: rgb({r},{g},{b}); margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
    def animate_color(step=0):
        set_color_step(step)
        if step < steps:
            QTimer.singleShot(interval, lambda: animate_color(step+1))
    animate_color(0)

class SimpleAnimatedButton(QPushButton):
    def __init__(self, text, *args, **kwargs):
        super().__init__(text, *args, **kwargs)
        self._bg_color = QColor(55, 156, 55)
        self._color_normal = QColor(55, 156, 55)
        self._color_hover = QColor(46, 174, 78)
        self._anim = QPropertyAnimation(self, b"bgColor")
        self._anim.setDuration(350)
        self._anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.setStyleSheet("QPushButton { color: #fff; border: 1px solid rgb(55,156,55); border-radius: 6px; min-height: 28px; max-height: 28px; outline: none; } QPushButton:focus { outline: none; } QPushButton:hover { border: 1px solid rgb(46, 174, 78); }")
        # --- Animación de escala ---
        self._scale = 1.0
        self._scale_anim = QPropertyAnimation(self, b"scale")
        self._scale_anim.setDuration(120)
        self._scale_anim.setEasingCurve(QEasingCurve.InOutQuad)

    def enterEvent(self, event):
        self._anim.stop()
        self._anim.setStartValue(self._bg_color)
        self._anim.setEndValue(self._color_hover)
        self._anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._anim.stop()
        self._anim.setStartValue(self._bg_color)
        self._anim.setEndValue(self._color_normal)
        self._anim.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        # Animar a escala 0.93
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(0.93)
        self._scale_anim.setDuration(80)
        self._scale_anim.start()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        # Animar de regreso a escala 1.0
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.setDuration(120)
        self._scale_anim.start()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # Aplicar transformación de escala centrada
        w, h = self.width(), self.height()
        painter.translate(w/2, h/2)
        painter.scale(self._scale, self._scale)
        painter.translate(-w/2, -h/2)
        painter.setBrush(QBrush(self._bg_color))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 6, 6)
        # --- Borde de foco verde oscuro si tiene el foco (igual que ShinyButton) ---
        if getattr(self, '_focus', False):
            pen = QPen(QColor(22, 80, 22), 1)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(self.rect().adjusted(1,1,-1,-1), 6, 6)
        # Pintar el texto blanco centrado
        painter.setPen(QColor("#fff"))
        font = self.font()
        painter.setFont(font)
        text = self.text()
        rect = self.rect()
        painter.drawText(rect, Qt.AlignCenter, text)
        # No llamar a super().paintEvent(event)

    def getBgColor(self):
        return self._bg_color

    def setBgColor(self, color):
        if isinstance(color, QColor):
            self._bg_color = color
        else:
            self._bg_color = QColor(color)
        self.update()

    bgColor = Property(QColor, getBgColor, setBgColor)

    # --- Propiedad de escala ---
    def getScale(self):
        return self._scale
    def setScale(self, value):
        self._scale = value
        self.update()
    scale = Property(float, getScale, setScale)

    def focusInEvent(self, event):
        self._focus = True
        self.update()
        super().focusInEvent(event)

    def focusOutEvent(self, event):
        self._focus = False
        self.update()
        super().focusOutEvent(event)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            # Animar a escala 0.93 (igual que mousePressEvent)
            self._scale_anim.stop()
            self._scale_anim.setStartValue(self._scale)
            self._scale_anim.setEndValue(0.93)
            self._scale_anim.setDuration(80)
            self._scale_anim.start()
            super().keyPressEvent(event)
            # Ejecutar el click
            self.click()
            # Animar de regreso a escala 1.0 (igual que mouseReleaseEvent)
            self._scale_anim.stop()
            self._scale_anim.setStartValue(0.93)
            self._scale_anim.setEndValue(1.0)
            self._scale_anim.setDuration(120)
            self._scale_anim.start()
        else:
            super().keyPressEvent(event)

# --- Worker para verificación de APIs ---
class ApiVerifierWorker(QObject):
    finished = Signal(list)
    def __init__(self, abuse_key, ipinfo_key, vpnapi_key):
        super().__init__()
        self.abuse_key = abuse_key
        self.ipinfo_key = ipinfo_key
        self.vpnapi_key = vpnapi_key
    def run(self):
        resultados = []
        import requests
        # Probar AbuseIPDB
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': self.abuse_key, 'Accept': 'application/json'},
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
        # Probar IPinfo
        if not self.ipinfo_key:
            resultados.append(("IPinfo", False, "No se ingresó clave"))
        else:
            try:
                r = requests.get(f'https://ipinfo.io/8.8.8.8/json', params={'token': self.ipinfo_key}, timeout=5)
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
        # Probar VPNAPI.IO
        try:
            r = requests.get(f'https://vpnapi.io/api/8.8.8.8?key={self.vpnapi_key}', timeout=5)
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
        self.finished.emit(resultados)

def get_icono_desde_base64():
    try:
        img_bytes = base64.b64decode(ICONO_BASE64)
        pixmap = QPixmap()
        pixmap.loadFromData(img_bytes)
        return QIcon(pixmap)
    except Exception:
        return QIcon()

ICONO_BASE64 = (
  "AAABAAEAAAAAAAEAIABuiwAAFgAAAIlQTkcNChoKAAAADUlIRFIAAA"
    "EAAAABAAgGAAAAXHKoZgAAgABJREFUeNrsvXe8bNdZ3/1dZbeZOf3c3u/VVbUsy3Jv2LgAxmDsIDABDI"
    "EAAUIglAR4k2BKnBBICAkEXvIJJJAYTCg2xcYYYxtwlYvcZLWrq9vb6WfKbmut94+19p65gjcEF11Jnk"
    "ef0Tl3zpQ9e/bTf8/vgalMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmcpUpjKVqU"
    "xlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmc"
    "pUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYyla"
    "lMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5"
    "nKVKYylalMZSpTmcpUpjKVqUxlKlOZylSmMpWpTGUqU5nKVKYylalMZSpTmcpUHg8irvUBTOWJL//u5I"
    "solKIjJVfseeraEauEEZsYmaOQuLoEIpRU1KKkK3cQM4OT0FUL1EajqwHDg8/ldeJ11/ojPWFkagCm8j"
    "mVf3Xyeazru5itb2RkN5FCEYmUWGUsiH38fP5m8VyTxDvjQ6mRRYI0WiK1M5UQaCelsrUo61jMlNaRnx"
    "b3F18hvsuc4z5yN8RQYp1kIV7gfO+jHFh/Ht9/4Peu9cd+3MrUAEzls5afOvEsfrV4P6+Oj2PskEzNcL"
    "BzO+/Z+M14Z3x0ZyTTA1omR2KZHHNWHcDJ3UpGy7GIeggRO5wWCAE4EBZcJYTKhWTdGnuuctVpK8zJyu"
    "UPGsqTF6szl5+VflVx0d3LoN4gVRm/9tEP8D3PfiE/uPyua306HlcyNQBT+YzkTncnBx66CxnPUhcrJP"
    "T46Rfcz/e+c9eOjl64TcvsGZHInhbJ9GaJ3i2F7iqhtEABIIRAIHE4JCCEwjmLtwMCiQyPU1hnsFhrXT"
    "0wrr5gRf0pQ/XhivL92/XKx3/m0D1XfvLs8xmYdXbN3sja4AL79+V8h/jwtT5Nj3mZGoCp/J3kzpOH2V"
    "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"
)

# --- Archivo de configuración general para modo claro/oscuro ---
MODO_CONFIG_FILE = os.path.join(NETTRACE_DIR, 'modo_config.json')

def cargar_modo_config():
    try:
        with open(MODO_CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('modo_dia', False)
    except Exception:
        return False  # Por defecto, modo oscuro

def guardar_modo_config(modo_dia):
    try:
        with open(MODO_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({'modo_dia': modo_dia}, f, indent=4)
    except Exception as e:
        print(f"Error guardando configuración de modo: {e}")

# Eliminar la variable global MODO_DIA_GLOBAL y usar la función de carga
# MODO_DIA_GLOBAL = False  # <-- Eliminar esta línea

def set_modo_claro_oscuro_mainwindow(window, modo_dia):
    """
    Aplica el modo claro u oscuro a la ventana principal y sus widgets.
    """
    if modo_dia:
        window.setStyleSheet("QWidget { background-color: #fff; }")
        window.input_combo.setStyleSheet(light_style)
        window.input_combo.set_arrow_color("black")
        window.output_combo.setStyleSheet(light_style)
        window.output_combo.set_arrow_color("black")
        window.ip_line.setStyleSheet("""
QLineEdit {
    background: rgb(224, 224, 224);
    color: #222;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 0px 15px;
    min-height: 28px;
    max-height: 28px;
    selection-background-color:rgba(170, 170, 170, 0.28); 

    selection-color: #222;
    qproperty-alignment: AlignCenter;
}
QLineEdit:focus {
    border: 1px solid rgb(170, 170, 170);
}
QLineEdit:hover {
    border: 1px solid rgb(170, 170, 170);
}
QComboBox {
    background: rgb(224, 224, 224);
    color: #222;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 0px 15px;
    min-height: 28px;
    max-height: 28px;
}
QComboBox QAbstractItemView {
    background: rgb(224, 224, 224);
    color: #222;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    selection-background-color: transparent;
    selection-color: #222;
    outline: none;
}
QComboBox QAbstractItemView::item {
    padding: 6px 0px;
    border: none;
    text-align: center;
}
QComboBox QAbstractItemView::item:hover {
    background: #f0f0f0;
    color: #222;
}
QComboBox:focus {
    border: 1px solid rgb(170, 170, 170);
}
QComboBox:hover {
    border: 1px solid rgb(170, 170, 170);
}
""")
        window.table.setStyleSheet("""
QTableWidget {
    background: #fff;
    color: #222;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    gridline-color: transparent;
    selection-background-color: transparent;
    selection-color: #222;
}
QHeaderView::section {
    background: transparent;
    color: #444;
    border: none;
    font-weight: bold;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 2px 0;
}
QHeaderView::down-arrow, QHeaderView::up-arrow {
    width: 0px;
    height: 0px;
}
QTableWidget QTableCornerButton::section {
    background: transparent;
    border: none;
}
QTableWidget::item {
    border: none;
    padding: 2px 4px;
}
QTableWidget::item:selected {
    background: #e0e0e0;
    color: #222;
}
QTableWidget::item:hover {
    background: #f0f0f0;
    color: #222;
}
QScrollBar:vertical {
    background: #f7f7f7;
    width: 12px;
    margin: 2px 0 2px 0;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #d0d0d0;
    min-height: 24px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover {
    background: #bdbdbd;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background: none;
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}
QScrollBar:horizontal {
    background: #f7f7f7;
    height: 12px;
    margin: 0 2px 0 2px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #d0d0d0;
    min-width: 24px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal:hover {
    background: #bdbdbd;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    background: none;
    width: 0px;
}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: none;
}
""")
        window.placeholder.setStyleSheet("background: transparent; border: none; color: #222;")
        window.inp_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: #222;
            background: transparent;
            font-weight: bold;
        """)
        window.out_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: #222;
            background: transparent;
            font-weight: bold;
        """)
        window.snackbar.setStyleSheet("color: rgba(0,0,0,80); font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; padding: 0; border: none;")
        # Actualizar tooltip personalizado si existe
        if hasattr(window, 'snackbar_tooltip'):
            window.snackbar_tooltip.set_modo_dia(modo_dia)
    else:
        window.setStyleSheet("QWidget { background-color: rgb(0,0,0); }")
        window.input_combo.setStyleSheet(common_style)
        window.input_combo.set_arrow_color("white")
        window.output_combo.setStyleSheet(common_style)
        window.output_combo.set_arrow_color("white")
        window.ip_line.setStyleSheet("""
QLineEdit {
    background: #161414;
    color: #f2f2f7;
    border: 1px solid #0e0e0e;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 0px 15px;
    min-height: 28px;
    max-height: 28px;
    qproperty-alignment: AlignCenter;
    selection-background-color: rgba(100, 100, 100, 0.28);
    selection-color: #fff;
}
QLineEdit:focus {
    border: 1px solid rgb(32, 32, 32);
}
QLineEdit:hover {
    border: 1px solid rgb(32, 32, 32);
}
""")
        window.table.setStyleSheet("""
QTableWidget {
    background: #000;
    color: #f2f2f7;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    gridline-color: transparent;
    selection-background-color: #181818;
    selection-color: #fff;
}
QHeaderView::section {
    background: transparent;
    color: #bdbdbd;
    border: none;
    font-weight: bold;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 2px 0;
}
QHeaderView::down-arrow, QHeaderView::up-arrow {
    width: 0px;
    height: 0px;
}
QTableWidget QTableCornerButton::section {
    background: transparent;
    border: none;
}
QTableWidget::item {
    border: none;
    padding: 2px 4px;
}
QTableWidget::item:selected {
    background: #181818;
    color: #fff;
}
QTableWidget::item:hover {
    background: #232323;
    color: #fff;
}
QScrollBar:vertical {
    background: #161414;
    width: 12px;
    margin: 2px 0 2px 0;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #393939;
    min-height: 24px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover {
    background: #5c5c5c;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background: none;
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}
QScrollBar:horizontal {
    background: #161414;
    height: 12px;
    margin: 0 2px 0 2px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #393939;
    min-width: 24px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal:hover {
    background: #5c5c5c;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    background: none;
    width: 0px;
}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: none;
}
""")
        window.placeholder.setStyleSheet("background: transparent; border: none;")
        window.inp_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: rgb(242,242,247);
            background: transparent;
            font-weight: bold;
        """)
        window.out_title.setStyleSheet("""
            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: rgb(242,242,247);
            background: transparent;
            font-weight: bold;
        """)
        window.snackbar.setStyleSheet("color: rgba(255,255,255,80); font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; padding: 0; border: none;")
        if hasattr(window, 'snackbar_tooltip'):
            window.snackbar_tooltip.set_modo_dia(modo_dia)
    # Spinner si existe
    if hasattr(window, 'circular_loader') and window.circular_loader is not None:
        window.circular_loader.set_modo_dia(modo_dia)

def set_modo_claro_oscuro_apiconfig(window, modo_dia):
    """
    Aplica el modo claro u oscuro a la ventana de configuración de APIs y sus widgets.
    """
    if modo_dia:
        window.setStyleSheet('''
            QWidget { background-color: #fff; }
            QLineEdit, QLabel, QFrame {
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            }
            QLineEdit {
                font-size: 13px;
                color: #222;
                padding: 0px 15px;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                background: #e0e0e0;
                min-height: 28px;
                max-height: 28px;
                selection-background-color: rgba(170, 170, 170, 0.28);
                selection-color: #222;
            }
            QLabel {
                font-size: 13px;
                color: #222;
            }
            QPushButton {
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                color: #222;
                padding: 0px 15px;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                background: #e0e0e0;
                min-height: 28px;
                max-height: 28px;
            }
        ''')
        # Cambiar color de las luces y labels
        for luz in [getattr(window, 'abuse_luz', None), getattr(window, 'ipinfo_luz', None), getattr(window, 'vpnapi_luz', None)]:
            if luz is not None:
                luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        # Títulos principales en el mismo color que la ventana principal, forzando repintado
        for label_name in ["abuse_title", "ipinfo_title", "vpnapi_title"]:
            label = window.findChild(QLabel, label_name)
            if label:
                label.setStyleSheet("font-weight: bold; color: #222 !important; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")
                label.repaint()
    else:
        window.setStyleSheet('''
            QWidget { background-color: #000; }
            QLineEdit, QLabel, QFrame {
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
            }
            QLineEdit {
                font-size: 13px;
                color: #f2f2f7;
                padding: 0px 15px;
                border: 1px solid rgb(22,20,20);
                border-radius: 6px;
                background: rgb(22,20,20);
                min-height: 28px;
                max-height: 28px;
                selection-background-color: rgba(100, 100, 100, 0.28);
                selection-color: #fff;
            }
            QLabel {
                font-size: 13px;
                color: #f2f2f7;
            }
            QPushButton {
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                color: rgb(242,242,247);
                padding: 0px 15px;
                border: 1px solid rgb(22,20,20);
                border-radius: 6px;
                background: rgb(22,20,20);
                min-height: 28px;
                max-height: 28px;
            }
        ''')
        for luz in [getattr(window, 'abuse_luz', None), getattr(window, 'ipinfo_luz', None), getattr(window, 'vpnapi_luz', None)]:
            if luz is not None:
                luz.setStyleSheet("font-size: 18px; color: #888; margin-left: 0px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;")
        for label_name in ["abuse_title", "ipinfo_title", "vpnapi_title"]:
            label = window.findChild(QLabel, label_name)
            if label:
                label.setStyleSheet("font-weight: bold; color: #f2f2f7; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")
                label.repaint()
        if hasattr(window, 'snackbar_tooltip'):
            window.snackbar_tooltip.set_modo_dia(modo_dia)

# --- Variable global para mantener viva la ventana de APIs ---
VENTANA_API_GLOBAL = None

# --- Variables globales para mantener vivas las ventanas principales ---
VENTANA_MAIN_GLOBAL = None

# --- Estilos para tooltips según el modo ---
TOOLTIP_STYLE_OSCURO = """
QToolTip {
    background-color: #232323;
    color: #f2f2f7;
    border: 1px solid #393939;
    border-radius: 8px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 6px 12px;
}
"""

TOOLTIP_STYLE_CLARO = """
QToolTip {
    background-color: #e0e0e0;  /* Igual que el combobox cerrado */
    color: #222;
    border: 1px solid #bdbdbd;  /* Borde más oscuro, siguiendo el patrón del combobox */
    border-radius: 8px;
    font-size: 13px;
    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
    padding: 6px 12px;
}
"""

# --- Tooltip personalizado ---
class CustomTooltip(QLabel):
    def __init__(self, parent=None, modo_dia=False):
        super().__init__(parent)
        self.setWindowFlags(Qt.ToolTip | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAlignment(Qt.AlignCenter)
        self.modo_dia = modo_dia
        self.set_modo_dia(modo_dia)
        self.hide()
        self._anim_in = None
        self._anim_out = None
        self._anim_pos_in = None
        self._anim_pos_out = None
        self._last_pos = None

    def set_modo_dia(self, modo_dia):
        self.modo_dia = modo_dia
        # Solo el color de texto y padding, sin fondo ni borde
        if modo_dia:
            self.setStyleSheet("""
                color: #222;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                padding: 6px 12px;
            """)
        else:
            self.setStyleSheet("""
                color: #f2f2f7;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                padding: 6px 12px;
            """)

    def show_tooltip(self, text, pos):
        self.setText(text)
        self.adjustSize()
        self._last_pos = pos
        # Posición inicial desplazada (10px arriba)
        pos_inicial = QPoint(pos.x(), pos.y() - 10)
        self.move(pos_inicial)
        self.setWindowOpacity(0.0)
        self.show()
        # Animación de opacidad (fade in)
        self._anim_in = QPropertyAnimation(self, b"windowOpacity")
        self._anim_in.setDuration(250)
        self._anim_in.setStartValue(0.0)
        self._anim_in.setEndValue(1.0)
        self._anim_in.setEasingCurve(QEasingCurve.InOutQuad)
        # Animación de posición (baja 10px)
        self._anim_pos_in = QPropertyAnimation(self, b"pos")
        self._anim_pos_in.setDuration(250)
        self._anim_pos_in.setStartValue(pos_inicial)
        self._anim_pos_in.setEndValue(pos)
        self._anim_pos_in.setEasingCurve(QEasingCurve.InOutQuad)
        self._anim_in.start()
        self._anim_pos_in.start()

    def hide_tooltip(self):
        if not self.isVisible():
            return
        # Animación de opacidad (fade out)
        self._anim_out = QPropertyAnimation(self, b"windowOpacity")
        self._anim_out.setDuration(200)
        self._anim_out.setStartValue(self.windowOpacity())
        self._anim_out.setEndValue(0.0)
        self._anim_out.setEasingCurve(QEasingCurve.InOutQuad)
        # Animación de posición (sube 10px)
        pos_actual = self.pos()
        pos_final = QPoint(pos_actual.x(), pos_actual.y() - 10)
        self._anim_pos_out = QPropertyAnimation(self, b"pos")
        self._anim_pos_out.setDuration(200)
        self._anim_pos_out.setStartValue(pos_actual)
        self._anim_pos_out.setEndValue(pos_final)
        self._anim_pos_out.setEasingCurve(QEasingCurve.InOutQuad)
        def ocultar():
            self.hide()
        self._anim_out.finished.connect(ocultar)
        self._anim_out.start()
        self._anim_pos_out.start()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        # Fondo igual que QComboBox QAbstractItemView abierto, borde igual
        if self.modo_dia:
            bg = QColor("#e0e0e0")  # Fondo igual que QComboBox QAbstractItemView (claro)
            border = QColor("#bdbdbd")  # Borde igual que QComboBox QAbstractItemView (claro)
            text = QColor("#222")
        else:
            bg = QColor(22, 20, 20)  # Fondo igual que QComboBox cerrado (oscuro)
            border = QColor("#232323")  # Borde igual que QComboBox QAbstractItemView (oscuro)
            text = QColor("#f2f2f7")
        # Fondo y borde redondeado igual que el combo
        painter.setBrush(bg)
        pen = QPen(border)
        pen.setWidthF(1.5)
        painter.setPen(pen)
        painter.drawRoundedRect(rect.adjusted(0, 0, -1, -1), 6, 6)
        # Dibuja el texto centrado
        painter.setPen(text)
        font = self.font()
        painter.setFont(font)
        # Ajustar el texto para respetar el padding
        padding_x = 12
        padding_y = 6
        rect_text = rect.adjusted(padding_x, padding_y, -padding_x, -padding_y)
        painter.drawText(rect_text, Qt.AlignCenter, self.text())

# Función para mostrar mensajes emergentes con colores adaptados ---
def mostrar_mensaje(parent, titulo, texto, modo_dia=True, icon=QMessageBox.Information):
    """
    Muestra un cuadro de diálogo de mensaje con estilos adaptados al modo claro u oscuro.
    """
    msg = QMessageBox(parent)
    msg.setWindowTitle(titulo)
    msg.setText(texto)
    msg.setIcon(icon)
    pal = QPalette()
    if modo_dia:
        pal.setColor(QPalette.Window, QColor("#f7f7f7"))  # Blanco menos intenso
        pal.setColor(QPalette.WindowText, QColor("#222"))
        pal.setColor(QPalette.Base, QColor("#f7f7f7"))
        pal.setColor(QPalette.Text, QColor("#222"))
        pal.setColor(QPalette.Button, QColor("#e0e0e0"))
        pal.setColor(QPalette.ButtonText, QColor("#222"))
        # Forzar color de texto y botones con stylesheet
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #f7f7f7;
                color: #222;
            }
            QLabel {
                color: #222;
                background: transparent;
            }
            QPushButton {
                color: #222;
                background-color: #e0e0e0;
                border: 1px solid #bdbdbd;
                border-radius: 6px;
                min-width: 64px;
                min-height: 24px;
            }
        """)
    else:
        pal.setColor(QPalette.Window, QColor("#232323"))
        pal.setColor(QPalette.WindowText, QColor("#f2f2f7"))
        pal.setColor(QPalette.Base, QColor("#232323"))
        pal.setColor(QPalette.Text, QColor("#f2f2f7"))
        pal.setColor(QPalette.Button, QColor("#161414"))
        pal.setColor(QPalette.ButtonText, QColor("#f2f2f7"))
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #232323;
                color: #f2f2f7;
            }
            QLabel {
                color: #f2f2f7;
                background: transparent;
            }
            QPushButton {
                color: #f2f2f7;
                background-color: #161414;
                border: 1px solid #393939;
                border-radius: 6px;
                min-width: 64px;
                min-height: 24px;
            }
        """)
    msg.setPalette(pal)
    msg.exec()

# Funciones utilitarias para diálogos estándar con contraste correcto ---
def get_file_dialog(parent, modo_dia=True, save=False, filter=None):
    dlg = QFileDialog(parent)
    dlg.setOption(QFileDialog.DontUseNativeDialog, True)  # <- ¡Clave!
    if filter:
        dlg.setNameFilter(filter)
    if modo_dia:
        dlg.setStyleSheet("""
            QFileDialog {
                background-color: #fff;
                color: #222;
            }
            QLabel, QLineEdit, QListView, QTreeView {
                color: #222;
                background: #fff;
            }
            QPushButton {
                color: #222;
                background-color: #e0e0e0;
                border: 1px solid #bdbdbd;
                border-radius: 6px;
            }
        """)
    else:
        dlg.setStyleSheet("""
            QFileDialog {
                background-color: #232323;
                color: #f2f2f7;
            }
            QLabel, QLineEdit, QListView, QTreeView {
                color: #f2f2f7;
                background: #232323;
            }
            QPushButton {
                color: #f2f2f7;
                background-color: #161414;
                border: 1px solid #393939;
                border-radius: 6px;
            }
        """)
    if save:
        return dlg.getSaveFileName()
    else:
        return dlg.getOpenFileName()

def get_input_dialog(parent, titulo, etiqueta, items=None, modo_dia=True):
    if items is not None:
        dlg = QInputDialog(parent)
        dlg.setWindowTitle(titulo)
        dlg.setLabelText(etiqueta)
        dlg.setComboBoxItems(items)
        # Aplicar estilo personalizado al ComboBox interno
        combo = dlg.findChild(QComboBox)
        if combo is not None:
            if modo_dia:
                combo.setStyleSheet(light_style + "\nQComboBox::drop-down { width: 20px; border: none; background: none; }\nQComboBox::down-arrow {\n    border: none;\n    background: none;\n    width: 16px;\n    height: 16px;\n} \nQComboBox::down-arrow:enabled {\n    border: none;\n    background: none;\n    width: 16px;\n    height: 16px;\n    color: black;\n} \nQComboBox::down-arrow {\n    margin-right: 4px;\n}")
            else:
                combo.setStyleSheet(common_style + "\nQComboBox::drop-down { width: 20px; border: none; background: none; }\nQComboBox::down-arrow {\n    border: none;\n    background: none;\n    width: 16px;\n    height: 16px;\n} \nQComboBox::down-arrow:enabled {\n    border: none;\n    background: none;\n    width: 16px;\n    height: 16px;\n    color: white;\n} \nQComboBox::down-arrow {\n    margin-right: 4px;\n}")
        if modo_dia:
            dlg.setStyleSheet("""
                QInputDialog {
                    background-color: #fff;
                    color: #222;
                }
                QLabel, QLineEdit, QComboBox {
                    color: #222;
                    background: #fff;
                }
                QPushButton {
                    color: #222;
                    background-color: #e0e0e0;
                    border: 1px solid #bdbdbd;
                    border-radius: 6px;
                }
            """)
        else:
            dlg.setStyleSheet("""
                QInputDialog {
                    background-color: #232323;
                    color: #f2f2f7;
                }
                QLabel, QLineEdit, QComboBox {
                    color: #f2f2f7;
                    background: #232323;
                }
                QPushButton {
                    color: #f2f2f7;
                    background-color: #161414;
                    border: 1px solid #393939;
                    border-radius: 6px;
                }
            """)
        ok = dlg.exec()
        return dlg.textValue(), ok == 1
    else:
        return QInputDialog.getText(parent, titulo, etiqueta)

# --- Diálogo personalizado para seleccionar columna con CustomComboBox ---
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox

class SeleccionarColumnaDialog(QDialog):
    def __init__(self, parent, columnas, modo_dia=False):
        super().__init__(parent)
        self.setWindowTitle("Seleccionar columna")
        self.setModal(True)
        self.setMinimumWidth(340)
        self.modo_dia = modo_dia
        layout = QVBoxLayout(self)
        label = QLabel("Columna de IPs:", self)
        label.setAlignment(Qt.AlignCenter)
        # --- Mejorar contraste y fondo en modo claro ---
        if modo_dia:
            self.setStyleSheet("background: #fff;")
            label.setStyleSheet("color: #222; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")
        else:
            self.setStyleSheet("background: #161414;")
            label.setStyleSheet("color: #f2f2f7; font-size: 13px; font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif; background: transparent;")
        layout.addWidget(label)
        self.combo = CustomComboBox(self)
        self.combo.addItems([str(c) for c in columnas])
        self.combo.setItemDelegate(CenteredComboDelegate(self.combo))
        self.combo.setEditable(True)
        self.combo.lineEdit().setAlignment(Qt.AlignCenter)
        self.combo.lineEdit().setReadOnly(True)
        # --- Centrado vertical del texto en el QLineEdit del combo ---
        if modo_dia:
            self.combo.setStyleSheet(light_style)
            self.combo.set_arrow_color("black")
            self.combo.lineEdit().setStyleSheet("""
                background: transparent;
                border: none;
                color: #222;
                padding-top: 0px;
                padding-bottom: 15px;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                qproperty-alignment: AlignCenter;
            """)
        else:
            self.combo.setStyleSheet(common_style + "\nQComboBox { background:rgb(8, 8, 8); }\n")
            self.combo.set_arrow_color("white")
            self.combo.lineEdit().setStyleSheet("""
                background: transparent;
                border: none;
                color: #f2f2f7;
                padding-top: 0px;
                padding-bottom: 15px;
                font-size: 13px;
                font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                qproperty-alignment: AlignCenter;
            """)
        layout.addWidget(self.combo)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        # --- Mejorar botones para que coincidan exactamente con el ComboBox en ambos modos ---
        if modo_dia:
            buttons.setStyleSheet(f"""
                QDialogButtonBox QPushButton {{
                    color: #222;
                    background: #e0e0e0;
                    border: 1px solid #e0e0e0;
                    border-radius: 6px;
                    min-width: 64px;
                    min-height: 24px;
                    font-size: 13px;
                    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                    outline: none;
                }}
                QDialogButtonBox QPushButton:hover, QDialogButtonBox QPushButton:focus {{
                    background: #f0f0f0;
                    border: 1px solid rgb(170, 170, 170);
                    color: #222;
                    outline: none;
                }}
            """)
        else:
            buttons.setStyleSheet(f"""
                QDialogButtonBox QPushButton {{
                    color: rgb(242,242,247);
                    background: rgb(8, 8, 8);
                    border: 1px solid #0e0e0e;
                    border-radius: 6px;
                    min-width: 64px;
                    min-height: 24px;
                    font-size: 13px;
                    font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                    outline: none;
                }}
                QDialogButtonBox QPushButton:hover, QDialogButtonBox QPushButton:focus {{
                    background: rgb(22, 20, 20);
                    border: 1px solid rgb(32, 32, 32);
                    color: rgb(242,242,247);
                    outline: none;
                }}
            """)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setLayout(layout)
    def get_selected(self):
        return self.combo.currentText()

# --- Icono invisible (PNG invisible) ---
ICONO_INVISIBLE_BASE64 = (
    )
def get_icono_invisible():
    try:
        img_bytes = base64.b64decode(ICONO_INVISIBLE_BASE64)
        pixmap = QPixmap()
        pixmap.loadFromData(img_bytes)
        return QIcon(pixmap)
    except Exception:
        return QIcon()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # --- Lógica de primera ejecución ---
    if es_primera_ejecucion():
        MODO_DIA_GLOBAL = False  # <-- Forzar modo oscuro en la primera ejecución
        app.setWindowIcon(get_icono_desde_base64())
        # --- Ventana de bienvenida con imagen ---
        from PySide6.QtWidgets import QDialog, QVBoxLayout
        class BienvenidaDialog(QDialog):
            def __init__(self, parent=None, modo_dia=False):
                super().__init__(parent)
                self.setWindowTitle("¡Bienvenido a NetTrace!")
                self.setWindowIcon(get_icono_desde_base64())
                self.setFixedSize(340, 170)
                self.setMinimumSize(340, 170)
                self.setMaximumSize(340, 170)
                self.setWindowFlags(self.windowFlags() | Qt.MSWindowsFixedSizeDialogHint)
                layout = QVBoxLayout(self)
                label_img = QLabel(self)
                pixmap = QPixmap()
                pixmap.loadFromData(base64.b64decode(ICONO_BASE64))
                pixmap = pixmap.scaled(86, 86, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                label_img.setPixmap(pixmap)
                label_img.setAlignment(Qt.AlignCenter)
                layout.addWidget(label_img)
                label_txt = QLabel("Gracias por instalar NetTrace\n\nPara comenzar, introduce tus claves de API", self)
                label_txt.setAlignment(Qt.AlignCenter)
                label_txt.setWordWrap(True)
                layout.addWidget(label_txt)
                # --- Espaciador entre el texto y el botón ---
                from PySide6.QtWidgets import QSpacerItem, QSizePolicy
                layout.addSpacerItem(QSpacerItem(15, 15, QSizePolicy.Minimum, QSizePolicy.Fixed))
                # --- Botón OK igual que QMessageBox modo oscuro ---
                from PySide6.QtWidgets import QPushButton
                ok_btn = QPushButton("OK", self)
                ok_btn.setMinimumWidth(64)
                ok_btn.setMinimumHeight(24)
                ok_btn.clicked.connect(self.accept)
                layout.addWidget(ok_btn, alignment=Qt.AlignCenter)
                self.setLayout(layout)
                self.set_modo_dia(modo_dia)

            def set_modo_dia(self, modo_dia):
                if modo_dia:
                    self.setStyleSheet("""
                        QDialog {
                            background-color: #fff;
                        }
                        QLabel {
                            color: #222;
                            background: transparent;
                            font-size: 13px;
                            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                        }
                        QPushButton {
                            color: #222;
                            background-color: #e0e0e0;
                            border: 1px solid #bdbdbd;
                            border-radius: 6px;
                            min-width: 64px;
                            min-height: 24px;
                            font-size: 13px;
                            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                        }
                        QPushButton:hover, QPushButton:focus {
                            background-color: #f0f0f0;
                            color: #222;
                            border: 1px solid #bdbdbd;
                        }
                    """)
                else:
                    self.setStyleSheet("""
                        QDialog {
                            background-color: #161414;
                        }
                        QLabel {
                            color: #f2f2f7;
                            background: transparent;
                            font-size: 13px;
                            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                        }
                        QPushButton {
                            color: #f2f2f7;
                            background-color: #161414;
                            border: 1px solid #393939;
                            border-radius: 6px;
                            min-width: 64px;
                            min-height: 24px;
                            font-size: 13px;
                            font-family: 'San Francisco', 'Segoe UI', Arial, sans-serif;
                        }
                        QPushButton:hover, QPushButton:focus {
                            background-color: #232323;
                            color: #f2f2f7;
                            border: 1px solid #393939;
                        }
                    """)
        modo_dia = cargar_modo_config()  # o False si es la primera vez
        dlg = BienvenidaDialog(modo_dia=modo_dia)
        dlg.exec()
        ventana = ApiConfigWindow()
        ventana.show()
        sys.exit(app.exec())
    else:
        ventana = MainWindow()
        ventana.show()
        sys.exit(app.exec())

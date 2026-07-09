import asyncio
import ipaddress
import socket
from typing import Optional

import aiohttp

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule


# ---------------------------------------------------------------------------
# Clasificación de puertos por severidad y servicio
#
# No todos los puertos abiertos tienen el mismo impacto.
# Esta tabla centraliza la lógica de clasificación para que sea
# fácil de mantener y extender sin tocar el resto del módulo.
# Formato: puerto → (nombre_servicio, severidad, descripción del riesgo)
# ---------------------------------------------------------------------------

PUERTOS_SENSIBLES: dict[int, tuple[str, str, str]] = {
    21:    ("FTP",           Severity.MEDIUM, "FTP expuesto — transferencia sin cifrado"),
    22:    ("SSH",           Severity.LOW,    "SSH expuesto — revisar versión y autenticación"),
    23:    ("Telnet",        Severity.HIGH,   "Telnet expuesto — protocolo sin cifrado"),
    25:    ("SMTP",          Severity.MEDIUM, "SMTP expuesto — posible open relay"),
    53:    ("DNS",           Severity.LOW,    "DNS expuesto — verificar recursión abierta"),
    80:    ("HTTP",          Severity.INFO,   "HTTP expuesto"),
    110:   ("POP3",          Severity.MEDIUM, "POP3 expuesto — correo sin cifrado"),
    135:   ("RPC",           Severity.HIGH,   "RPC expuesto — superficie de ataque Windows"),
    139:   ("NetBIOS",       Severity.HIGH,   "NetBIOS expuesto"),
    143:   ("IMAP",          Severity.MEDIUM, "IMAP expuesto — correo sin cifrado"),
    443:   ("HTTPS",         Severity.INFO,   "HTTPS expuesto"),
    445:   ("SMB",           Severity.HIGH,   "SMB expuesto — revisar EternalBlue"),
    1433:  ("MSSQL",         Severity.HIGH,   "SQL Server expuesto a Internet"),
    1521:  ("Oracle DB",     Severity.HIGH,   "Oracle DB expuesto a Internet"),
    2375:  ("Docker API",    Severity.HIGH,   "Docker API sin TLS — ejecución remota de código"),
    2376:  ("Docker TLS",    Severity.MEDIUM, "Docker API con TLS — verificar configuración"),
    3306:  ("MySQL",         Severity.HIGH,   "MySQL expuesto a Internet"),
    3389:  ("RDP",           Severity.HIGH,   "RDP expuesto — revisar BlueKeep y fuerza bruta"),
    4444:  ("Metasploit",    Severity.HIGH,   "Puerto Metasploit — posible backdoor activo"),
    5432:  ("PostgreSQL",    Severity.HIGH,   "PostgreSQL expuesto a Internet"),
    5900:  ("VNC",           Severity.HIGH,   "VNC expuesto — acceso remoto sin cifrado"),
    5984:  ("CouchDB",       Severity.HIGH,   "CouchDB expuesto — sin auth por defecto"),
    6379:  ("Redis",         Severity.HIGH,   "Redis expuesto — sin autenticación por defecto"),
    7001:  ("WebLogic",      Severity.HIGH,   "WebLogic expuesto — múltiples CVEs críticos"),
    8080:  ("HTTP-alt",      Severity.LOW,    "Puerto HTTP alternativo expuesto"),
    8443:  ("HTTPS-alt",     Severity.LOW,    "Puerto HTTPS alternativo expuesto"),
    8888:  ("HTTP-dev",      Severity.LOW,    "Puerto de desarrollo HTTP expuesto"),
    9200:  ("Elasticsearch", Severity.HIGH,   "Elasticsearch expuesto — sin auth por defecto"),
    9300:  ("Elastic-node",  Severity.HIGH,   "Nodo Elasticsearch expuesto"),
    11211: ("Memcached",     Severity.HIGH,   "Memcached expuesto — sin auth por defecto"),
    27017: ("MongoDB",       Severity.HIGH,   "MongoDB expuesto — sin auth por defecto"),
    27018: ("MongoDB",       Severity.HIGH,   "MongoDB expuesto en puerto alternativo"),
}

# Palabras clave en títulos HTTP que sugieren paneles de administración expuestos
PALABRAS_ADMIN = [
    "admin", "panel", "dashboard", "management", "control", "manager",
    "phpmyadmin", "grafana", "kibana", "jenkins", "gitlab", "portainer",
    "traefik", "netdata", "zabbix", "nagios", "prometheus", "rancher",
    "sonarqube", "nexus", "artifactory", "jupyter", "airflow",
]

# Proveedores cloud identificables por su descripción de ASN
PROVEEDORES_CLOUD = {
    "amazon":       "AWS",
    "google":       "GCP",
    "microsoft":    "Azure",
    "cloudflare":   "Cloudflare",
    "fastly":       "Fastly CDN",
    "akamai":       "Akamai CDN",
    "digitalocean": "DigitalOcean",
    "linode":       "Linode/Akamai",
    "ovh":          "OVHcloud",
    "hetzner":      "Hetzner",
}


class ShodanModule(BaseModule):
    """
    Módulo de reconocimiento de infraestructura expuesta.

    Usa tres fuentes en cascada, de mayor a menor detalle:

    1. Shodan API — fuente principal. Proporciona puertos, banners,
       CVEs detectados, sistema operativo, geolocalización y más.
       Requiere API key gratuita (free tier: 100 queries/mes,
       Membership completo con email académico universitario).
       Nota: /shodan/host/{ip} NO consume query credits, solo
       las búsquedas por texto libre los consumen.

    2. Censys Host Lookup — complemento gratuito sin créditos.
       Proporciona servicios, protocolos y certificados TLS por IP.
       Funciona sin API key para lookups básicos.

    3. ipinfo.io — fallback siempre disponible (50k req/mes sin key).
       Proporciona ASN, organización, país y ciudad.

    El módulo siempre está disponible aunque no haya API key de Shodan
    porque tiene fallbacks completamente gratuitos.
    """

    name = "shodan"
    description = "Mapeo de infraestructura expuesta: puertos, servicios, CVEs y banners"

    # URLs de las APIs
    SHODAN_HOST_URL  = "https://api.shodan.io/shodan/host/{ip}?key={key}"
    SHODAN_DNS_URL   = "https://api.shodan.io/dns/resolve?hostnames={domain}&key={key}"
    CENSYS_HOST_URL  = "https://search.censys.io/api/v2/hosts/{ip}"
    IPINFO_URL       = "https://ipinfo.io/{ip}/json"

    def requires_api_key(self) -> Optional[str]:
        return "shodan"

    def is_available(self) -> bool:
        """
        Siempre disponible aunque no haya API key de Shodan,
        porque Censys e ipinfo funcionan sin autenticación.
        """
        return True

    async def run(self, target: str) -> list[Finding]:
        """
        Resuelve el dominio a IPs y consulta cada una en paralelo
        usando las tres fuentes disponibles.
        """
        ips = await self._resolver_ips(target)
        if not ips:
            return self.findings

        # Analizamos cada IP en paralelo
        await asyncio.gather(
            *[self._analizar_ip(ip, target) for ip in ips],
            return_exceptions=True,
        )

        return self.findings

    async def _resolver_ips(self, dominio: str) -> list[str]:
        """
        Resuelve el dominio a sus IPs públicas.

        Intenta primero con la API DNS de Shodan si hay key disponible,
        ya que además de la IP puede devolver información adicional.
        Si no hay key o falla, usa socket.getaddrinfo como fallback.
        Las IPs privadas se filtran porque Shodan no las indexa.
        """
        ips: set[str] = set()

        # Intento 1: Shodan DNS resolve (si hay key)
        key = self.config.get_api_key("shodan")
        if key:
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    url = self.SHODAN_DNS_URL.format(domain=dominio, key=key)
                    async with session.get(url) as r:
                        if r.status == 200:
                            data = await r.json()
                            if dominio in data:
                                ip = data[dominio]
                                if not self._es_ip_privada(ip):
                                    ips.add(ip)
            except Exception:
                pass

        # Intento 2: resolución DNS estándar como fallback
        if not ips:
            try:
                infos = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(dominio, None, socket.AF_UNSPEC),
                )
                for info in infos:
                    ip = info[4][0]
                    if not self._es_ip_privada(ip):
                        ips.add(ip)
            except Exception:
                pass

        return list(ips)

    async def _analizar_ip(self, ip: str, dominio: str):
        """
        Lanza las tres consultas para una IP en paralelo.
        Si una falla, las otras dos siguen ejecutándose.
        """
        await asyncio.gather(
            self._consultar_shodan(ip, dominio),
            self._consultar_censys(ip, dominio),
            self._consultar_ipinfo(ip, dominio),
            return_exceptions=True,
        )

    async def _consultar_shodan(self, ip: str, dominio: str):
        """
        Consulta Shodan por IP.

        El endpoint /shodan/host/{ip} devuelve el perfil completo del host:
        todos los puertos y servicios observados, banners capturados,
        vulnerabilidades conocidas (CVEs), OS detectado y metadatos de red.

        Importante: este endpoint NO consume query credits de Shodan,
        solo los consume la búsqueda por texto libre (/shodan/search).
        """
        key = self.config.get_api_key("shodan")
        if not key:
            return
        try: 
            url = self.SHODAN_HOST_URL.format(ip=ip, key=key)
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as r:
                    if r.status == 404:
                        # IP no indexada en Shodan, es normal para IPs poco activas
                        return
                    if r.status == 401:
                        # API key inválida o expirada
                        return
                    if r.status != 200:
                        return
                    data = await r.json()

            # Información general del host
            self._procesar_info_host(data, ip, dominio)

            # Puertos abiertos
            for puerto in data.get("ports", []):
                self._procesar_puerto(puerto, ip)

            # Datos detallados por servicio (banners, HTTP, SSH...)
            for servicio in data.get("data", []):
                self._procesar_servicio(servicio, ip, dominio)

            # CVEs detectados por Shodan
            for cve_id, vuln_data in data.get("vulns", {}).items():
                self._procesar_cve(cve_id, vuln_data, ip)

        except Exception:
            pass

    def _procesar_info_host(self, data: dict, ip: str, dominio: str):
        """
        Extrae la información general del host desde la respuesta de Shodan:
        organización, ISP, ASN, sistema operativo, ubicación y hostnames.
        """
        self.add_finding(
            type="host_info",
            value=ip,
            severity=Severity.INFO,
            source="shodan",
            metadata={
                "domain":     dominio,
                "org":        data.get("org", ""),
                "isp":        data.get("isp", ""),
                "asn":        data.get("asn", ""),
                "os":         data.get("os", ""),
                "country":    data.get("country_name", ""),
                "city":       data.get("city", ""),
                "hostnames":  data.get("hostnames", []),
                "domains":    data.get("domains", []),
                "tags":       data.get("tags", []),
                "last_update": data.get("last_update", ""),
            },
        )

    def _procesar_puerto(self, puerto: int, ip: str):
        """
        Registra un puerto abierto con su severidad real.
        La clasificación viene de PUERTOS_SENSIBLES — no todos
        los puertos abiertos tienen el mismo impacto.
        """
        info = PUERTOS_SENSIBLES.get(puerto)
        severidad = info[1] if info else Severity.INFO
        servicio  = info[0] if info else ""
        nota      = info[2] if info else f"Puerto {puerto} abierto"

        self.add_finding(
            type="open_port",
            value=f"{ip}:{puerto}",
            severity=severidad,
            source="shodan",
            metadata={
                "ip":      ip,
                "port":    puerto,
                "service": servicio,
                "note":    nota,
            },
        )

    def _procesar_servicio(self, servicio: dict, ip: str, dominio: str):
        """
        Analiza los datos detallados de un servicio concreto.
        Cada elemento de data[] en la respuesta de Shodan corresponde
        a un puerto/protocolo con su banner completo y datos adicionales.
        """
        puerto    = servicio.get("port", 0)
        producto  = servicio.get("product", "")
        version   = servicio.get("version", "")
        banner    = servicio.get("data", "")[:500]  # limitamos a 500 chars

        # Si hay producto o versión identificada, es un hallazgo de tecnología
        if producto:
            tech = f"{producto} {version}".strip()
            self.add_finding(
                type="technology",
                value=tech,
                severity=Severity.INFO,
                source="shodan/banner",
                metadata={"ip": ip, "port": puerto, "banner": banner},
            )

        # Analizamos los datos HTTP si están presentes
        if "http" in servicio:
            self._procesar_http(servicio["http"], ip, puerto)

    def _procesar_http(self, http_data: dict, ip: str, puerto: int):
        """
        Analiza los datos HTTP que Shodan captura de los servicios web.
        Detecta paneles de administración expuestos y headers de seguridad
        ausentes, que son hallazgos frecuentes en auditorías reales.
        """
        titulo  = http_data.get("title", "") or ""
        servidor = http_data.get("server", "") or ""
        headers  = http_data.get("headers", {}) or {}

        # Server header: expone el software y versión exacta del servidor web
        if servidor:
            self.add_finding(
                type="http_server_header",
                value=f"{ip}:{puerto} → {servidor}",
                severity=Severity.LOW,
                source="shodan/http",
                metadata={"ip": ip, "port": puerto, "server": servidor},
            )

        # Panel de administración expuesto: alta severidad
        if titulo and any(kw in titulo.lower() for kw in PALABRAS_ADMIN):
            self.add_finding(
                type="exposed_admin_panel",
                value=f"{ip}:{puerto} — {titulo}",
                severity=Severity.HIGH,
                source="shodan/http",
                metadata={"ip": ip, "port": puerto, "title": titulo},
            )

        # Headers de seguridad ausentes
        headers_lower = {k.lower(): v for k, v in headers.items()}
        headers_seguridad = {
            "strict-transport-security": "HSTS ausente",
            "x-frame-options":           "X-Frame-Options ausente — riesgo de clickjacking",
            "x-content-type-options":    "X-Content-Type-Options ausente",
            "content-security-policy":   "Content-Security-Policy ausente",
        }
        ausentes = [
            desc for header, desc in headers_seguridad.items()
            if header not in headers_lower
        ]
        if ausentes:
            self.add_finding(
                type="missing_security_headers",
                value=f"{ip}:{puerto}",
                severity=Severity.LOW,
                source="shodan/http",
                metadata={"ip": ip, "port": puerto, "missing": ausentes},
            )

    def _procesar_cve(self, cve_id: str, vuln_data: dict, ip: str):
        """
        Registra un CVE detectado por Shodan en el host analizado.

        Shodan cruza los banners de los servicios con bases de datos
        de vulnerabilidades y devuelve los CVEs aplicables.
        Clasificamos por CVSS score para asignar la severidad correcta.
        """
        cvss = vuln_data.get("cvss", 0.0) or 0.0

        if cvss >= 7.0:
            severidad = Severity.HIGH
        elif cvss >= 4.0:
            severidad = Severity.MEDIUM
        else:
            severidad = Severity.LOW

        self.add_finding(
            type="cve",
            value=cve_id,
            severity=severidad,
            source="shodan/vulns",
            metadata={
                "ip":         ip,
                "cvss":       cvss,
                "summary":    vuln_data.get("summary", ""),
                "references": vuln_data.get("references", [])[:3],
                "verified":   vuln_data.get("verified", False),
            },
        )

    async def _consultar_censys(self, ip: str, dominio: str):
        """
        Consulta la API de Censys Host Lookup por IP.

        Censys ofrece lookups básicos por IP de forma gratuita sin créditos.
        Complementa a Shodan con datos de servicios y protocolos adicionales.
        Si hay credenciales configuradas, las usa para obtener más datos.
        """
        url = self.CENSYS_HOST_URL.format(ip=ip)
        timeout = aiohttp.ClientTimeout(total=15)

        headers = {"Accept": "application/json"}
        auth = None

        # Autenticación opcional — mejora los datos devueltos
        censys_id     = self.config.get_api_key("censys_id")
        censys_secret = self.config.get_api_key("censys_secret")
        if censys_id and censys_secret:
            auth = aiohttp.BasicAuth(censys_id, censys_secret)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, auth=auth) as r:
                # 206 = datos parciales en free tier, también válido
                if r.status not in (200, 206):
                    return
                data = await r.json()

        servicios = data.get("result", {}).get("services", [])
        for svc in servicios:
            puerto    = svc.get("port", 0)
            transporte = svc.get("transport_protocol", "TCP")
            servicio  = svc.get("extended_service_name", svc.get("service_name", ""))

            info = PUERTOS_SENSIBLES.get(puerto)
            severidad = info[1] if info else Severity.INFO

            self.add_finding(
                type="open_port",
                value=f"{ip}:{puerto}",
                severity=severidad,
                source="censys",
                metadata={
                    "ip":        ip,
                    "port":      puerto,
                    "transport": transporte,
                    "service":   servicio,
                    "domain":    dominio,
                },
            )

    async def _consultar_ipinfo(self, ip: str, dominio: str):
        """
        Consulta ipinfo.io para obtener datos de geolocalización y ASN.

        Gratuito hasta 50.000 requests/mes sin API key.
        Detecta automáticamente si la IP pertenece a un proveedor cloud
        conocido, lo que tiene implicaciones distintas en un análisis OSINT.
        """
        try:
            url = self.IPINFO_URL.format(ip=ip)
            ipinfo_key = self.config.get_api_key("ipinfo")
            if ipinfo_key:
                url += f"?token={ipinfo_key}"

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as r:
                    if r.status != 200:
                        return
                    data = await r.json()

            org = data.get("org", "")
            asn = org.split(" ")[0] if org else ""
            org_nombre = " ".join(org.split(" ")[1:]) if org else ""

            self.add_finding(
                type="ip_geolocation",
                value=ip,
                severity=Severity.INFO,
                source="ipinfo",
                metadata={
                    "ip":       ip,
                    "domain":   dominio,
                    "asn":      asn,
                    "org":      org_nombre,
                    "country":  data.get("country", ""),
                    "region":   data.get("region", ""),
                    "city":     data.get("city", ""),
                    "hostname": data.get("hostname", ""),
                    "timezone": data.get("timezone", ""),
                },
            )

            # Detección de proveedor cloud
            org_lower = org_nombre.lower()
            for keyword, nombre_proveedor in PROVEEDORES_CLOUD.items():
                if keyword in org_lower:
                    self.add_finding(
                        type="cloud_provider",
                        value=f"{ip} → {nombre_proveedor}",
                        severity=Severity.INFO,
                        source="ipinfo",
                        metadata={
                            "ip":       ip,
                            "provider": nombre_proveedor,
                            "asn":      asn,
                        },
                    )
                    break

            # El hostname de la IP puede revelar infraestructura interna
            hostname = data.get("hostname", "")
            if hostname and hostname != ip:
                self.add_finding(
                    type="ip_hostname",
                    value=hostname,
                    severity=Severity.INFO,
                    source="ipinfo",
                    metadata={"ip": ip},
                )
                
        except Exception:
            pass

    @staticmethod
    def _es_ip_privada(ip: str) -> bool:
        """
        Comprueba si una IP es privada o reservada.
        Shodan no indexa IPs privadas, así que las filtramos
        antes de hacer peticiones para no desperdiciar tiempo.
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
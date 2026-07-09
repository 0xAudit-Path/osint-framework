import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.shodan_module import (
    PUERTOS_SENSIBLES,
    PALABRAS_ADMIN,
    ShodanModule,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_sin_key():
    """
    Configuración sin API key de Shodan.
    El módulo funciona también con Censys e ipinfo.
    """
    config = MagicMock()
    config.get_api_key.return_value = None
    config.network.timeout = 5
    return config


@pytest.fixture
def config_con_key():
    """Configuración con API key de Shodan simulada."""
    config = MagicMock()
    config.get_api_key.side_effect = lambda k: "test_key_123" if k == "shodan" else None
    config.network.timeout = 5
    return config


@pytest.fixture
def modulo_sin_key(config_sin_key):
    """Instancia del módulo sin API key."""
    return ShodanModule(config_sin_key)


@pytest.fixture
def modulo_con_key(config_con_key):
    """Instancia del módulo con API key."""
    return ShodanModule(config_con_key)


def mock_sesion_http(status: int = 200, json_data: dict = None):
    """
    Construye un mock completo de aiohttp.ClientSession
    que devuelve la respuesta indicada.
    Es un helper reutilizable para todos los tests que hacen
    peticiones HTTP — evita repetir el mismo boilerplate.
    """
    mock_respuesta = MagicMock()
    mock_respuesta.status = status
    mock_respuesta.json = AsyncMock(return_value=json_data or {})

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    return mock_session


# Respuesta de Shodan realista para usada para múltiples tests
SHODAN_RESPUESTA_MOCK = {
    "ip_str":       "93.184.216.34",
    "org":          "EDGECAST",
    "isp":          "MCI Communications",
    "asn":          "AS15133",
    "os":           None,
    "country_name": "United States",
    "city":         "Los Angeles",
    "last_update":  "2024-01-15T10:30:00Z",
    "hostnames":    ["example.com"],
    "domains":      ["example.com"],
    "tags":         [],
    "ports":        [80, 443, 22, 3306],
    "vulns": {
        "CVE-2021-44228": {
            "cvss":       10.0,
            "summary":    "Log4Shell RCE vulnerability",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "verified":   True,
        },
        "CVE-2023-9999": {
            "cvss":    5.5,
            "summary": "Medium severity test vuln",
            "references": [],
            "verified": False,
        },
    },
    "data": [
        {
            "port":    80,
            "product": "Apache httpd",
            "version": "2.4.51",
            "data":    "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\n",
            "http": {
                "title":   "Admin Panel",
                "server":  "Apache/2.4.51",
                "headers": {},
                "status":  200,
            },
        },
        {
            "port":    3306,
            "product": "MySQL",
            "version": "8.0.32",
            "data":    "MySQL 8.0.32",
        },
    ],
}


# ---------------------------------------------------------------------------
# Tests de clase base
# ---------------------------------------------------------------------------

def test_shodan_module_hereda_de_base_module(modulo_sin_key):
    """ShodanModule debe heredar de BaseModule."""
    assert isinstance(modulo_sin_key, BaseModule)

def test_shodan_module_tiene_nombre(modulo_sin_key):
    """El nombre identifica el módulo en logs e informes."""
    assert modulo_sin_key.name == "shodan"

def test_shodan_module_requiere_api_key_shodan(modulo_sin_key):
    """El módulo declara que necesita key de Shodan."""
    assert modulo_sin_key.requires_api_key() == "shodan"

def test_shodan_module_siempre_disponible_sin_key(modulo_sin_key):
    """
    El módulo sigue disponible aunque no haya API KEY, 
    ya que tiene Censys e ipinfo como fallbacks gratuitos.
    """
    assert modulo_sin_key.is_available() is True

def test_shodan_module_disponible_con_key(modulo_con_key):
    """Con API key también debe estar disponible."""
    assert modulo_con_key.is_available() is True


# ---------------------------------------------------------------------------
# Tests de clasificación de puertos
# ---------------------------------------------------------------------------

def test_puertos_criticos_son_high():
    """
    Los puertos más peligrosos son clasificados como HIGH.
    Son servicios que habitualmente no deberían estar expuestos a Internet.
    """
    puertos_criticos = [3306, 3389, 5432, 6379, 9200, 27017, 2375, 445]
    for puerto in puertos_criticos:
        assert puerto in PUERTOS_SENSIBLES, f"Puerto {puerto} no está en PUERTOS_SENSIBLES"
        _, severidad, _ = PUERTOS_SENSIBLES[puerto]
        assert severidad == Severity.HIGH, (
            f"Puerto {puerto} debería ser HIGH pero es {severidad}"
        )


def test_ssh_es_low():
    """
    SSH es LOW. Es normal tenerlo expuesto pero hay que revisar 
    la versión y la configuración de autenticación.
    """
    assert 22 in PUERTOS_SENSIBLES
    _, severidad, _ = PUERTOS_SENSIBLES[22]
    assert severidad == Severity.LOW


def test_http_y_https_son_info():
    """HTTP y HTTPS son servicios web normales — solo informativos."""
    for puerto in [80, 443]:
        assert puerto in PUERTOS_SENSIBLES
        _, severidad, _ = PUERTOS_SENSIBLES[puerto]
        assert severidad == Severity.INFO


def test_procesar_puerto_high_para_mysql(modulo_sin_key):
    """MySQL expuesto a Internet debe generar un finding HIGH."""
    modulo_sin_key._procesar_puerto(3306, "1.2.3.4")

    findings = [f for f in modulo_sin_key.findings if f.type == "open_port"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].value == "1.2.3.4:3306"
    assert findings[0].metadata["service"] == "MySQL"


def test_procesar_puerto_info_para_desconocido(modulo_sin_key):
    """Un puerto no catalogado debe ser INFO por defecto."""
    modulo_sin_key._procesar_puerto(12345, "1.2.3.4")

    findings = [f for f in modulo_sin_key.findings if f.type == "open_port"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_procesar_puerto_incluye_metadatos(modulo_sin_key):
    """El finding de puerto tiene que incluir IP, puerto, servicio y nota."""
    modulo_sin_key._procesar_puerto(22, "1.2.3.4")

    finding = modulo_sin_key.findings[0]
    assert finding.metadata["ip"] == "1.2.3.4"
    assert finding.metadata["port"] == 22
    assert finding.metadata["service"] == "SSH"
    assert "note" in finding.metadata


# ---------------------------------------------------------------------------
# Tests de procesado de información del host
# ---------------------------------------------------------------------------


def test_procesar_info_host_crea_finding_info(modulo_sin_key):
    """La información general del host debe registrarse como INFO."""
    modulo_sin_key._procesar_info_host(SHODAN_RESPUESTA_MOCK, "93.184.216.34", "example.com")

    host_findings = [f for f in modulo_sin_key.findings if f.type == "host_info"]
    assert len(host_findings) == 1
    assert host_findings[0].severity == Severity.INFO
    assert host_findings[0].value == "93.184.216.34"
    assert host_findings[0].source == "shodan"


def test_procesar_info_host_incluye_metadatos(modulo_sin_key):
    """El finding del host tiene que incluir org, ASN, país y ciudad."""
    modulo_sin_key._procesar_info_host(SHODAN_RESPUESTA_MOCK, "93.184.216.34", "example.com")

    meta = modulo_sin_key.findings[0].metadata
    assert meta["org"] == "EDGECAST"
    assert meta["asn"] == "AS15133"
    assert meta["country"] == "United States"
    assert meta["city"] == "Los Angeles"
    assert meta["domain"] == "example.com"


# ---------------------------------------------------------------------------
# Tests de procesado de CVEs
# ---------------------------------------------------------------------------


def test_cve_con_cvss_alto_es_high(modulo_sin_key):
    """Un CVE con CVSS >= 7.0 tiene que clasificarse como HIGH."""
    modulo_sin_key._procesar_cve(
        "CVE-2021-44228",
        {"cvss": 10.0, "summary": "Log4Shell", "references": [], "verified": True},
        "1.2.3.4",
    )

    cve_findings = [f for f in modulo_sin_key.findings if f.type == "cve"]
    assert len(cve_findings) == 1
    assert cve_findings[0].severity == Severity.HIGH
    assert cve_findings[0].value == "CVE-2021-44228"
    assert cve_findings[0].metadata["cvss"] == 10.0
    assert cve_findings[0].metadata["verified"] is True


def test_cve_con_cvss_medio_es_medium(modulo_sin_key):
    """Un CVE con CVSS entre 4.0 y 6.9 tiene que clasificarse como MEDIUM."""
    modulo_sin_key._procesar_cve(
        "CVE-2023-9999",
        {"cvss": 5.5, "summary": "Test vuln", "references": [], "verified": False},
        "1.2.3.4",
    )

    cve_findings = [f for f in modulo_sin_key.findings if f.type == "cve"]
    assert cve_findings[0].severity == Severity.MEDIUM


def test_cve_con_cvss_bajo_es_low(modulo_sin_key):
    """Un CVE con CVSS < 4.0 tiene que clasificarse como LOW."""
    modulo_sin_key._procesar_cve(
        "CVE-2023-1111",
        {"cvss": 2.1, "summary": "Low severity", "references": [], "verified": False},
        "1.2.3.4",
    )

    cve_findings = [f for f in modulo_sin_key.findings if f.type == "cve"]
    assert cve_findings[0].severity == Severity.LOW


def test_cve_sin_cvss_es_low(modulo_sin_key):
    """
    Si Shodan no proporciona CVSS score, el finding debe ser LOW
    en lugar de fallar. Cvss None debe tratarse como 0.
    """
    modulo_sin_key._procesar_cve(
        "CVE-2023-2222",
        {"cvss": None, "summary": "No CVSS", "references": [], "verified": False},
        "1.2.3.4",
    )

    cve_findings = [f for f in modulo_sin_key.findings if f.type == "cve"]
    assert len(cve_findings) == 1
    assert cve_findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Tests de procesado HTTP
# ---------------------------------------------------------------------------


def test_procesar_http_detecta_panel_admin(modulo_sin_key):
    """
    Un título HTTP con palabras clave de administración debe
    generar un finding HIGH de panel de administración expuesto.
    """
    modulo_sin_key._procesar_http(
        {"title": "Grafana Dashboard", "server": "nginx", "headers": {}},
        "1.2.3.4",
        3000,
    )

    admin_findings = [f for f in modulo_sin_key.findings if f.type == "exposed_admin_panel"]
    assert len(admin_findings) == 1
    assert admin_findings[0].severity == Severity.HIGH
    assert "Grafana Dashboard" in admin_findings[0].value


def test_procesar_http_detecta_multiples_palabras_admin(modulo_sin_key):
    """Todas las palabras clave de admin deben detectarse."""
    for palabra in ["jenkins", "kibana", "phpmyadmin", "portainer"]:
        modulo = ShodanModule(modulo_sin_key.config)
        modulo._procesar_http(
            {"title": f"Bienvenido a {palabra}", "server": "", "headers": {}},
            "1.2.3.4",
            8080,
        )
        admin_findings = [f for f in modulo.findings if f.type == "exposed_admin_panel"]
        assert len(admin_findings) == 1, f"No detectó panel admin con palabra '{palabra}'"


def test_procesar_http_titulo_normal_no_es_admin(modulo_sin_key):
    """Un título HTTP normal no debe generar finding de panel admin."""
    modulo_sin_key._procesar_http(
        {"title": "Bienvenido a nuestra web", "server": "nginx", "headers": {}},
        "1.2.3.4",
        80,
    )

    admin_findings = [f for f in modulo_sin_key.findings if f.type == "exposed_admin_panel"]
    assert len(admin_findings) == 0


def test_procesar_http_detecta_server_header(modulo_sin_key):
    """El header Server revela el software del servidor web."""
    modulo_sin_key._procesar_http(
        {"title": "Home", "server": "Apache/2.4.51", "headers": {}},
        "1.2.3.4",
        80,
    )

    server_findings = [f for f in modulo_sin_key.findings if f.type == "http_server_header"]
    assert len(server_findings) == 1
    assert server_findings[0].severity == Severity.LOW
    assert "Apache/2.4.51" in server_findings[0].value


def test_procesar_http_sin_server_header_no_crea_finding(modulo_sin_key):
    """Si no hay header Server, no debe crearse finding de server header."""
    modulo_sin_key._procesar_http(
        {"title": "Home", "server": "", "headers": {}},
        "1.2.3.4",
        80,
    )

    server_findings = [f for f in modulo_sin_key.findings if f.type == "http_server_header"]
    assert len(server_findings) == 0


def test_procesar_http_detecta_headers_seguridad_ausentes(modulo_sin_key):
    """
    Si faltan headers de seguridad HTTP, tiene que crearse un finding LOW.
    Un servidor sin HSTS, CSP o X-Frame-Options es más vulnerable.
    """
    modulo_sin_key._procesar_http(
        {"title": "Home", "server": "nginx", "headers": {}},
        "1.2.3.4",
        80,
    )

    missing_findings = [
        f for f in modulo_sin_key.findings if f.type == "missing_security_headers"
    ]
    assert len(missing_findings) == 1
    assert missing_findings[0].severity == Severity.LOW
    assert "HSTS ausente" in missing_findings[0].metadata["missing"]


def test_procesar_http_con_todos_los_headers_no_crea_finding_missing(modulo_sin_key):
    """
    Si el servidor tiene todos los headers de seguridad configurados,
    no debe crearse finding de headers ausentes.
    """
    modulo_sin_key._procesar_http(
        {
            "title": "Home",
            "server": "nginx",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options":           "SAMEORIGIN",
                "X-Content-Type-Options":    "nosniff",
                "Content-Security-Policy":   "default-src 'self'",
            },
        },
        "1.2.3.4",
        443,
    )

    missing_findings = [
        f for f in modulo_sin_key.findings if f.type == "missing_security_headers"
    ]
    assert len(missing_findings) == 0


def test_procesar_http_titulo_none_no_falla(modulo_sin_key):
    """
    Shodan puede devolver title como None.
    El módulo no debe lanzar excepción en ese caso.
    """
    modulo_sin_key._procesar_http(
        {"title": None, "server": None, "headers": {}},
        "1.2.3.4",
        80,
    )
    assert True



# ---------------------------------------------------------------------------
# Tests de procesado de servicio
# ---------------------------------------------------------------------------

def test_procesar_servicio_con_producto_crea_finding_tecnologia(modulo_sin_key):
    """
    Si Shodan identifica el producto del servicio, debe registrarse
    como finding de tecnología para que la IA pueda generar dorks.
    """
    modulo_sin_key._procesar_servicio(
        {"port": 80, "product": "nginx", "version": "1.24.0", "data": "HTTP/1.1 200 OK"},
        "1.2.3.4",
        "example.com",
    )

    tech_findings = [f for f in modulo_sin_key.findings if f.type == "technology"]
    assert len(tech_findings) == 1
    assert "nginx" in tech_findings[0].value
    assert "1.24.0" in tech_findings[0].value

def test_procesar_servicio_sin_producto_no_crea_finding_tecnologia(modulo_sin_key):
    """Si Shodan no identifica el producto, no se crea finding de tecnología."""
    modulo_sin_key._procesar_servicio(
        {"port": 80, "product": "", "version": "", "data": "HTTP/1.1 200 OK"},
        "1.2.3.4",
        "example.com",
    )

    tech_findings = [f for f in modulo_sin_key.findings if f.type == "technology"]
    assert len(tech_findings) == 0



# ---------------------------------------------------------------------------
# Tests de consulta a Shodan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_consultar_shodan_sin_key_no_hace_peticion(modulo_sin_key):
    """
    Sin API key, el módulo no debe intentar contactar con Shodan.
    Evita peticiones fallidas en el log.
    """
    with patch("aiohttp.ClientSession") as mock_cls:
        await modulo_sin_key._consultar_shodan("1.2.3.4", "example.com")
        mock_cls.assert_not_called()

@pytest.mark.asyncio
async def test_consultar_shodan_respuesta_correcta(modulo_con_key):
    """Con API key y respuesta válida, se crean findings de host y puertos."""
    mock_session = mock_sesion_http(200, SHODAN_RESPUESTA_MOCK)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_key._consultar_shodan("93.184.216.34", "example.com")

    host_findings = [f for f in modulo_con_key.findings if f.type == "host_info"]
    port_findings = [f for f in modulo_con_key.findings if f.type == "open_port"]
    cve_findings  = [f for f in modulo_con_key.findings if f.type == "cve"]

    assert len(host_findings) == 1
    assert len(port_findings) == 4   # 4 puertos en la respuesta mock
    assert len(cve_findings)  == 2   # 2 CVEs en la respuesta mock


@pytest.mark.asyncio
async def test_consultar_shodan_404_no_crea_findings(modulo_con_key):
    """
    Una IP no indexada en Shodan devuelve 404.
    Es completamente normal y no debe crear ningún finding.
    """
    mock_session = mock_sesion_http(404)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_key._consultar_shodan("1.2.3.4", "example.com")

    assert len(modulo_con_key.findings) == 0


@pytest.mark.asyncio
async def test_consultar_shodan_401_no_falla(modulo_con_key):
    """
    Una API key inválida devuelve 401.
    El módulo debe manejarlo silenciosamente.
    """
    mock_session = mock_sesion_http(401)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_key._consultar_shodan("1.2.3.4", "example.com")

    assert len(modulo_con_key.findings) == 0


@pytest.mark.asyncio
async def test_consultar_shodan_error_red_no_falla(modulo_con_key):
    """
    Un error de red (timeout, conexión rechazada) no debe
    propagar la excepción hacia el orquestador.
    """
    with patch("aiohttp.ClientSession", side_effect=Exception("Connection timeout")):
        await modulo_con_key._consultar_shodan("1.2.3.4", "example.com")

    assert len(modulo_con_key.findings) == 0


@pytest.mark.asyncio
async def test_consultar_shodan_cve_log4shell_es_high(modulo_con_key):
    """Log4Shell (CVSS 10.0) debe clasificarse como HIGH."""
    mock_session = mock_sesion_http(200, SHODAN_RESPUESTA_MOCK)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_key._consultar_shodan("93.184.216.34", "example.com")

    log4shell = next(
        (f for f in modulo_con_key.findings
         if f.type == "cve" and f.value == "CVE-2021-44228"),
        None
    )
    assert log4shell is not None
    assert log4shell.severity == Severity.HIGH
    assert log4shell.metadata["verified"] is True


# ---------------------------------------------------------------------------
# Tests de consulta a ipinfo
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_consultar_ipinfo_crea_finding_geolocalizacion(modulo_sin_key):
    """ipinfo debe crear un finding de geolocalización con ASN y país."""
    datos_ipinfo = {
        "org":      "AS15169 Google LLC",
        "country":  "US",
        "region":   "California",
        "city":     "Mountain View",
        "hostname": "dns.google",
        "timezone": "America/Los_Angeles",
    }
    mock_session = mock_sesion_http(200, datos_ipinfo)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_ipinfo("8.8.8.8", "example.com")

    geo_findings = [f for f in modulo_sin_key.findings if f.type == "ip_geolocation"]
    assert len(geo_findings) == 1
    assert geo_findings[0].value == "8.8.8.8"
    assert geo_findings[0].metadata["asn"] == "AS15169"
    assert geo_findings[0].metadata["country"] == "US"
    assert geo_findings[0].metadata["city"] == "Mountain View"


@pytest.mark.asyncio
async def test_consultar_ipinfo_detecta_google_cloud(modulo_sin_key):
    """Una IP de Google tiene que detectarse como proveedor GCP."""
    datos_ipinfo = {
        "org":      "AS15169 Google LLC",
        "country":  "US",
        "region":   "California",
        "city":     "Mountain View",
        "hostname": "",
        "timezone": "America/Los_Angeles",
    }
    mock_session = mock_sesion_http(200, datos_ipinfo)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_ipinfo("8.8.8.8", "example.com")

    cloud_findings = [f for f in modulo_sin_key.findings if f.type == "cloud_provider"]
    assert len(cloud_findings) == 1
    assert cloud_findings[0].metadata["provider"] == "GCP"


@pytest.mark.asyncio
async def test_consultar_ipinfo_detecta_aws(modulo_sin_key):
    """Una IP de Amazon tiene que detectarse como proveedor AWS."""
    datos_ipinfo = {
        "org":      "AS16509 Amazon.com Inc.",
        "country":  "US",
        "region":   "Virginia",
        "city":     "Ashburn",
        "hostname": "",
        "timezone": "America/New_York",
    }
    mock_session = mock_sesion_http(200, datos_ipinfo)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_ipinfo("3.1.2.3", "example.com")

    cloud_findings = [f for f in modulo_sin_key.findings if f.type == "cloud_provider"]
    assert len(cloud_findings) == 1
    assert cloud_findings[0].metadata["provider"] == "AWS"


@pytest.mark.asyncio
async def test_consultar_ipinfo_registra_hostname(modulo_sin_key):
    """
    El hostname de una IP puede revelar infraestructura interna.
    Debe registrarse como finding separado.
    """
    datos_ipinfo = {
        "org":      "AS15169 Google LLC",
        "country":  "US",
        "region":   "California",
        "city":     "Mountain View",
        "hostname": "dns.google",
        "timezone": "America/Los_Angeles",
    }
    mock_session = mock_sesion_http(200, datos_ipinfo)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_ipinfo("8.8.8.8", "example.com")

    hostname_findings = [f for f in modulo_sin_key.findings if f.type == "ip_hostname"]
    assert len(hostname_findings) == 1
    assert hostname_findings[0].value == "dns.google"


@pytest.mark.asyncio
async def test_consultar_ipinfo_error_no_falla(modulo_sin_key):
    """Un error en ipinfo no debe propagar la excepción."""
    with patch("aiohttp.ClientSession", side_effect=Exception("Timeout")):
        await modulo_sin_key._consultar_ipinfo("1.2.3.4", "example.com")

    assert len(modulo_sin_key.findings) == 0


# ---------------------------------------------------------------------------
# Tests de filtrado de IPs privadas
# ---------------------------------------------------------------------------


def test_ip_privada_192_168(modulo_sin_key):
    """Las IPs del rango 192.168.x.x son privadas."""
    assert modulo_sin_key._es_ip_privada("192.168.1.1") is True


def test_ip_privada_10(modulo_sin_key):
    """Las IPs del rango 10.x.x.x son privadas."""
    assert modulo_sin_key._es_ip_privada("10.0.0.1") is True


def test_ip_privada_172_16(modulo_sin_key):
    """Las IPs del rango 172.16.x.x son privadas."""
    assert modulo_sin_key._es_ip_privada("172.16.0.1") is True


def test_ip_publica_no_es_privada(modulo_sin_key):
    """Las IPs públicas no deben filtrarse."""
    assert modulo_sin_key._es_ip_privada("93.184.216.34") is False
    assert modulo_sin_key._es_ip_privada("8.8.8.8") is False
    assert modulo_sin_key._es_ip_privada("1.1.1.1") is False


def test_ip_invalida_no_falla(modulo_sin_key):
    """Una cadena que no es una IP no debe lanzar excepción."""
    assert modulo_sin_key._es_ip_privada("no-es-una-ip") is False


# ---------------------------------------------------------------------------
# Tests de resolución de IPs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolver_ips_filtra_privadas(modulo_sin_key):
    """
    Las IPs privadas deben filtrarse antes de consultarlas.
    Shodan no las indexa y las consultas fallan.
    """
    infos_mock = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=infos_mock):
        ips = await modulo_sin_key._resolver_ips("example.com")

    assert len(ips) == 0


@pytest.mark.asyncio
async def test_resolver_ips_devuelve_publicas(modulo_sin_key):
    """Las IPs públicas deben incluirse en el resultado."""
    infos_mock = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=infos_mock):
        ips = await modulo_sin_key._resolver_ips("example.com")

    assert "93.184.216.34" in ips


@pytest.mark.asyncio
async def test_resolver_ips_deduplica(modulo_sin_key):
    """Si el dominio resuelve varias veces a la misma IP, solo aparece una."""
    infos_mock = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=infos_mock):
        ips = await modulo_sin_key._resolver_ips("example.com")

    assert ips.count("1.2.3.4") == 1


@pytest.mark.asyncio
async def test_resolver_ips_error_dns_no_falla(modulo_sin_key):
    """Si la resolución DNS falla, debe devolver lista vacía sin excepción."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        ips = await modulo_sin_key._resolver_ips("noexiste.invalido")

    assert ips == []


# ---------------------------------------------------------------------------
# Test de integración
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_aunque_todo_falle(config_sin_key):
    """
    run() nunca debe lanzar excepción hacia el orquestador.
    Aunque todas las fuentes fallen, devuelve una lista vacía.
    """
    modulo = ShodanModule(config_sin_key)

    with patch("socket.getaddrinfo", side_effect=Exception("DNS failure")):
        resultado = await modulo.run("example.com")

    assert isinstance(resultado, list)


@pytest.mark.asyncio
async def test_run_completo_sin_key_usa_fallbacks(config_sin_key):
    """
    Sin API key de Shodan, el módulo debe funcionar usando
    solo Censys e ipinfo y producir findings de geolocalización.
    """
    modulo = ShodanModule(config_sin_key)

    infos_mock = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
    ]

    datos_ipinfo = {
        "org":      "AS15169 Google LLC",
        "country":  "US",
        "region":   "California",
        "city":     "Mountain View",
        "hostname": "dns.google",
        "timezone": "America/Los_Angeles",
    }

    datos_censys = {"result": {"services": []}}

    def mock_sesion_segun_url(*args, **kwargs):
        """
        Devuelve distintas respuestas según la URL a consultar.
        Simula el comportamiento real de las APIs externas.
        """
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        def mock_get(url, **kw):
            respuesta = MagicMock()
            respuesta.__aenter__ = AsyncMock(return_value=respuesta)
            respuesta.__aexit__ = AsyncMock(return_value=None)

            if "censys" in url:
                respuesta.status = 200
                respuesta.json = AsyncMock(return_value=datos_censys)
            elif "ipinfo" in url:
                respuesta.status = 200
                respuesta.json = AsyncMock(return_value=datos_ipinfo)
            else:
                respuesta.status = 404
                respuesta.json = AsyncMock(return_value={})

            return respuesta

        session.get = mock_get
        return session

    with patch("socket.getaddrinfo", return_value=infos_mock):
        with patch("aiohttp.ClientSession", side_effect=mock_sesion_segun_url):
            resultado = await modulo.run("example.com")

    tipos = {f.type for f in resultado}
    assert "ip_geolocation" in tipos
    assert "cloud_provider" in tipos
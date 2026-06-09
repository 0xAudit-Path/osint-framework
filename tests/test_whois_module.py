from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.whois_module import WhoisModule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config_base():
    """Configuración mínima mockeada para los tests."""
    config = MagicMock()
    config.network.timeout = 5
    return config


@pytest.fixture
def whois_module(config_base):
    """Instancia del módulo WHOIS lista para cada test."""
    return WhoisModule(config_base)


def mock_whois_resultado(
    registrar="Test Registrar Inc.",
    creation_date=None,
    expiration_date=None,
    updated_date=None,
    name_servers=None,
    status="clientTransferProhibited",
    dnssec="unsigned",
    org="Test Organization",
    name=None,
    emails="admin@example.com",
    country="ES",
):
    """
    Construye un objeto mock que simula el resultado de python-whois.
    python-whois devuelve un objeto con atributos, no un diccionario,
    así que se usa MagicMock con spec para simularlo correctamente.
    """
    mock = MagicMock()
    mock.registrar = registrar
    mock.creation_date = creation_date or datetime(2010, 1, 1, tzinfo=timezone.utc)
    mock.expiration_date = expiration_date or datetime(2030, 1, 1, tzinfo=timezone.utc)
    mock.updated_date = updated_date or datetime(2023, 6, 1, tzinfo=timezone.utc)
    mock.name_servers = name_servers or ["ns1.example.com", "ns2.example.com"]
    mock.status = status
    mock.dnssec = dnssec
    mock.org = org
    mock.name = name
    mock.emails = emails
    mock.country = country
    return mock


# ---------------------------------------------------------------------------
# Tests de clase base
# ---------------------------------------------------------------------------


def test_whois_module_hereda_de_base_module(whois_module):
    """WhoisModule debe heredar de BaseModule para que el orquestador lo acepte."""
    assert isinstance(whois_module, BaseModule)


def test_whois_module_tiene_nombre(whois_module):
    """El nombre identifica el módulo en logs e informes."""
    assert whois_module.name == "whois"


def test_whois_module_no_requiere_api_key(whois_module):
    """python-whois e ipwhois son gratuitos y sin autenticación."""
    assert whois_module.requires_api_key() is None


def test_whois_module_siempre_disponible(whois_module):
    """Sin API key requerida, el módulo siempre está disponible."""
    assert whois_module.is_available() is True


# ---------------------------------------------------------------------------
# Tests de helpers de extracción de campos
# ---------------------------------------------------------------------------


def test_extraer_campo_string(whois_module):
    """
    Cuando el campo es un string, debe devolverse tal cual.
    Es el caso más sencillo y el más habitual en dominios .com.
    """
    mock = MagicMock()
    mock.registrar = "GoDaddy LLC"
    assert whois_module._extraer_campo(mock, "registrar") == "GoDaddy LLC"


def test_extraer_campo_lista_devuelve_primer_elemento(whois_module):
    """
    python-whois a veces devuelve listas aunque haya un solo valor.
    Siempre se debe devolver el primer elemento como string.
    """
    mock = MagicMock()
    mock.registrar = ["GoDaddy LLC", "GoDaddy LLC"]
    assert whois_module._extraer_campo(mock, "registrar") == "GoDaddy LLC"


def test_extraer_campo_none_devuelve_cadena_vacia(whois_module):
    """
    Si el campo no existe o es None, devuelve cadena vacía.
    Esto evita que el resto del código tenga que comprobar None constantemente.
    """
    mock = MagicMock()
    mock.registrar = None
    assert whois_module._extraer_campo(mock, "registrar") == ""


def test_extraer_campo_lista_vacia_devuelve_cadena_vacia(whois_module):
    """Una lista vacía equivale a campo ausente."""
    mock = MagicMock()
    mock.registrar = []
    assert whois_module._extraer_campo(mock, "registrar") == ""


def test_extraer_lista_con_lista(whois_module):
    """
    _extraer_lista devuelve todos los elementos cuando el campo es una lista.
    Se usa para nameservers y status, que pueden tener varios valores.
    """
    mock = MagicMock()
    mock.name_servers = ["ns1.example.com", "ns2.example.com"]
    result = whois_module._extraer_lista(mock, "name_servers")
    assert result == ["ns1.example.com", "ns2.example.com"]


def test_extraer_lista_con_string(whois_module):
    """Si el campo es un string, lo envuelve en lista para uniformidad."""
    mock = MagicMock()
    mock.name_servers = "ns1.example.com"
    result = whois_module._extraer_lista(mock, "name_servers")
    assert result == ["ns1.example.com"]


def test_extraer_lista_none_devuelve_lista_vacia(whois_module):
    """Si el campo no existe, devolvemos lista vacía."""
    mock = MagicMock()
    mock.name_servers = None
    result = whois_module._extraer_lista(mock, "name_servers")
    assert result == []


def test_formatear_fecha_datetime(whois_module):
    """
    Cuando python-whois devuelve un objeto datetime, lo convertimos a ISO 8601.
    Es el formato estándar que usaremos en los informes.
    """
    fecha = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    resultado = whois_module._formatear_fecha(fecha)
    assert "2024-06-15" in resultado


def test_formatear_fecha_cadena_vacia(whois_module):
    """Una cadena vacía debe devolverse tal cual."""
    assert whois_module._formatear_fecha("") == ""


def test_formatear_fecha_none(whois_module):
    """None debe devolver cadena vacía sin lanzar excepción."""
    assert whois_module._formatear_fecha(None) == ""


# ---------------------------------------------------------------------------
# Tests de procesado del resultado WHOIS de dominio
# ---------------------------------------------------------------------------


def test_procesar_whois_dominio_crea_finding_info(whois_module):
    """
    El procesado básico debe crear un finding informativo
    con todos los metadatos del registro WHOIS.
    """
    datos = mock_whois_resultado()
    whois_module._procesar_whois_dominio(datos, "example.com")

    dominio_findings = [f for f in whois_module.findings if f.type == "whois_domain"]
    assert len(dominio_findings) == 1
    assert dominio_findings[0].severity == Severity.INFO
    assert dominio_findings[0].value == "example.com"
    assert dominio_findings[0].source == "whois"
    assert dominio_findings[0].metadata["registrar"] == "Test Registrar Inc."


def test_procesar_whois_dominio_crea_finding_registrante(whois_module):
    """
    Si hay información del registrante (org o name), debe crear
    un finding separado. Es un dato de inteligencia valioso.
    """
    datos = mock_whois_resultado(org="ACME Corporation")
    whois_module._procesar_whois_dominio(datos, "example.com")

    registrante_findings = [f for f in whois_module.findings if f.type == "whois_registrant"]
    assert len(registrante_findings) == 1
    assert registrante_findings[0].value == "ACME Corporation"
    assert registrante_findings[0].metadata["domain"] == "example.com"


def test_procesar_whois_dominio_sin_registrante_no_crea_finding(whois_module):
    """
    Si org y name son None (registrante anónimo / privacy guard),
    no debe crear finding de registrante.
    """
    datos = mock_whois_resultado(org=None, name=None)
    # Forzamos que getattr devuelva None para org y name
    datos.org = None
    datos.name = None
    whois_module._procesar_whois_dominio(datos, "example.com")

    registrante_findings = [f for f in whois_module.findings if f.type == "whois_registrant"]
    assert len(registrante_findings) == 0


def test_procesar_whois_dominio_crea_findings_nameservers(whois_module):
    """
    Cada nameserver debe registrarse como finding individual.
    Los nameservers revelan el proveedor DNS del objetivo.
    """
    datos = mock_whois_resultado(
        name_servers=["ns1.cloudflare.com", "ns2.cloudflare.com"]
    )
    whois_module._procesar_whois_dominio(datos, "example.com")

    ns_findings = [f for f in whois_module.findings if f.type == "whois_nameserver"]
    assert len(ns_findings) == 2
    valores = [f.value for f in ns_findings]
    assert "ns1.cloudflare.com" in valores
    assert "ns2.cloudflare.com" in valores


def test_procesar_whois_nameservers_se_normalizan_a_minusculas(whois_module):
    """
    Los nameservers deben almacenarse en minúsculas para facilitar
    comparaciones y deduplicación posteriores.
    """
    datos = mock_whois_resultado(name_servers=["NS1.EXAMPLE.COM"])
    whois_module._procesar_whois_dominio(datos, "example.com")

    ns_findings = [f for f in whois_module.findings if f.type == "whois_nameserver"]
    assert ns_findings[0].value == "ns1.example.com"


# ---------------------------------------------------------------------------
# Tests de comprobación de expiración del dominio
# ---------------------------------------------------------------------------


def test_dominio_expirado_crea_finding_high(whois_module):
    """
    Un dominio expirado puede ser comprado por un atacante para
    phishing o intercepción de correo. Severidad HIGH.
    """
    fecha_pasada = datetime.now(timezone.utc) - timedelta(days=30)
    whois_module._comprobar_expiracion_dominio(fecha_pasada, "example.com")

    expired_findings = [f for f in whois_module.findings if f.type == "domain_expired"]
    assert len(expired_findings) == 1
    assert expired_findings[0].severity == Severity.HIGH
    assert 29 <= expired_findings[0].metadata["expired_days_ago"] <= 31


def test_dominio_expira_pronto_crea_finding_medium(whois_module):
    """
    Un dominio que expira en menos de 30 días merece atención
    pero no es una emergencia inmediata. Severidad MEDIUM.
    """
    fecha_pronto = datetime.now(timezone.utc) + timedelta(days=15)
    whois_module._comprobar_expiracion_dominio(fecha_pronto, "example.com")

    expiring_findings = [f for f in whois_module.findings if f.type == "domain_expiring_soon"]
    assert len(expiring_findings) == 1
    assert expiring_findings[0].severity == Severity.MEDIUM
    assert 14 <= expiring_findings[0].metadata["days_remaining"] <= 15


def test_dominio_con_larga_validez_no_crea_finding_expiracion(whois_module):
    """
    Un dominio que no expira hasta dentro de años no debe
    generar ningún finding de expiración.
    """
    fecha_lejana = datetime.now(timezone.utc) + timedelta(days=365 * 3)
    whois_module._comprobar_expiracion_dominio(fecha_lejana, "example.com")

    expiracion_findings = [
        f for f in whois_module.findings
        if f.type in ("domain_expired", "domain_expiring_soon")
    ]
    assert len(expiracion_findings) == 0


def test_expiracion_acepta_lista_de_fechas(whois_module):
    """
    python-whois a veces devuelve expiration_date como lista.
    El módulo debe usar el primer elemento sin error.
    """
    fecha_pronto = datetime.now(timezone.utc) + timedelta(days=10)
    lista_fechas = [fecha_pronto, fecha_pronto]
    whois_module._comprobar_expiracion_dominio(lista_fechas, "example.com")

    expiring_findings = [f for f in whois_module.findings if f.type == "domain_expiring_soon"]
    assert len(expiring_findings) == 1


def test_expiracion_acepta_datetime_sin_timezone(whois_module):
    """
    python-whois a veces devuelve datetimes naive (sin timezone).
    El módulo debe tratarlos como UTC sin lanzar excepción.
    """
    # datetime naive: sin tzinfo
    fecha_naive = datetime.now() + timedelta(days=10)
    assert fecha_naive.tzinfo is None

    whois_module._comprobar_expiracion_dominio(fecha_naive, "example.com")

    expiring_findings = [f for f in whois_module.findings if f.type == "domain_expiring_soon"]
    assert len(expiring_findings) == 1


def test_expiracion_fecha_invalida_no_falla(whois_module):
    """
    Una fecha con formato incorrecto no debe lanzar excepción.
    El módulo debe capturarla silenciosamente.
    """
    whois_module._comprobar_expiracion_dominio("no-es-una-fecha", "example.com")
    assert len(whois_module.findings) == 0


# ---------------------------------------------------------------------------
# Tests de WHOIS de dominio completo (con mock de whois.whois)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_whois_dominio_llama_a_whois_whois(whois_module):
    """
    Comprueba que _whois_dominio llama a la librería python-whois
    y procesa el resultado correctamente.
    """
    datos_mock = mock_whois_resultado()

    with patch("osint.modules.whois_module.whois") as mock_whois_lib:
        mock_whois_lib.whois.return_value = datos_mock
        await whois_module._whois_dominio("example.com")

    dominio_findings = [f for f in whois_module.findings if f.type == "whois_domain"]
    assert len(dominio_findings) == 1


@pytest.mark.asyncio
async def test_whois_dominio_error_no_falla(whois_module):
    """
    Si python-whois lanza una excepción (servidor inaccesible,
    dominio sin WHOIS público), el módulo no debe propagarla.
    """
    with patch("osint.modules.whois_module.whois") as mock_whois_lib:
        mock_whois_lib.whois.side_effect = Exception("Connection refused")
        await whois_module._whois_dominio("example.com")

    assert len(whois_module.findings) == 0


@pytest.mark.asyncio
async def test_whois_dominio_resultado_none_no_falla(whois_module):
    """
    python-whois puede devolver None para algunos dominios.
    El módulo debe manejarlo sin crear findings ni errores.
    """
    with patch("osint.modules.whois_module.whois") as mock_whois_lib:
        mock_whois_lib.whois.return_value = None
        await whois_module._whois_dominio("example.com")

    assert len(whois_module.findings) == 0


# ---------------------------------------------------------------------------
# Tests de WHOIS de IP y ASN
# ---------------------------------------------------------------------------


def test_procesar_whois_ip_crea_finding_asn(whois_module):
    """
    El resultado del WHOIS de una IP debe crear un finding
    con el ASN, bloque CIDR y organización propietaria.
    """
    datos_rdap = {
        "asn": "AS15169",
        "asn_description": "GOOGLE",
        "asn_cidr": "8.8.8.0/24",
        "asn_country_code": "US",
        "network": {"name": "GOOGLE"},
    }
    whois_module._procesar_whois_ip(datos_rdap, "8.8.8.8", "example.com")

    asn_findings = [f for f in whois_module.findings if f.type == "ip_asn"]
    assert len(asn_findings) == 1
    assert asn_findings[0].value == "8.8.8.8"
    assert asn_findings[0].metadata["asn"] == "AS15169"
    assert asn_findings[0].metadata["cidr"] == "8.8.8.0/24"
    assert asn_findings[0].metadata["country"] == "US"


def test_procesar_whois_ip_detecta_proveedor_cloud_google(whois_module):
    """
    Si el ASN pertenece a Google (GCP), debe crear un finding
    adicional indicando el proveedor cloud. Es relevante para
    entender la infraestructura del objetivo.
    """
    datos_rdap = {
        "asn": "AS15169",
        "asn_description": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "asn_country_code": "US",
        "network": {"name": "GOOGLE"},
    }
    whois_module._procesar_whois_ip(datos_rdap, "8.8.8.8", "example.com")

    cloud_findings = [f for f in whois_module.findings if f.type == "cloud_provider"]
    assert len(cloud_findings) == 1
    assert cloud_findings[0].metadata["provider"] == "GCP"


def test_procesar_whois_ip_detecta_proveedor_cloud_aws(whois_module):
    """Comprueba la detección de AWS específicamente."""
    datos_rdap = {
        "asn": "AS16509",
        "asn_description": "Amazon.com Inc.",
        "asn_cidr": "3.0.0.0/8",
        "asn_country_code": "US",
        "network": {"name": "AMAZON-02"},
    }
    whois_module._procesar_whois_ip(datos_rdap, "3.1.2.3", "example.com")

    cloud_findings = [f for f in whois_module.findings if f.type == "cloud_provider"]
    assert len(cloud_findings) == 1
    assert cloud_findings[0].metadata["provider"] == "AWS"


def test_procesar_whois_ip_sin_proveedor_cloud_no_crea_finding_cloud(whois_module):
    """
    Si el ASN no es de un proveedor cloud conocido, no debe
    crear ningún finding de cloud_provider.
    """
    datos_rdap = {
        "asn": "AS1234",
        "asn_description": "Small ISP Spain",
        "asn_cidr": "192.0.2.0/24",
        "asn_country_code": "ES",
        "network": {"name": "SMALL-ISP"},
    }
    whois_module._procesar_whois_ip(datos_rdap, "192.0.2.1", "example.com")

    cloud_findings = [f for f in whois_module.findings if f.type == "cloud_provider"]
    assert len(cloud_findings) == 0


def test_consultar_ipwhois_devuelve_none_en_error(whois_module):
    """
    Si IPWhois lanza una excepción, _consultar_ipwhois debe
    devolver None sin propagarla hacia el módulo.
    """
    with patch("osint.modules.whois_module.IPWhois") as mock_ipwhois:
        mock_ipwhois.return_value.lookup_rdap.side_effect = Exception("Timeout")
        resultado = whois_module._consultar_ipwhois("1.2.3.4")

    assert resultado is None


@pytest.mark.asyncio
async def test_whois_ip_error_no_falla(whois_module):
    """
    Si la consulta RDAP falla, _whois_ip debe terminar
    silenciosamente sin crear findings ni lanzar excepción.
    """
    with patch.object(whois_module, "_consultar_ipwhois", return_value=None):
        await whois_module._whois_ip("1.2.3.4", "example.com")

    asn_findings = [f for f in whois_module.findings if f.type == "ip_asn"]
    assert len(asn_findings) == 0


# ---------------------------------------------------------------------------
# Tests de resolución de IPs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_whois_ips_deduplica_ips(whois_module):
    """
    Si el dominio tiene múltiples registros A apuntando a la misma IP
    (balanceo con registro duplicado), solo debe consultarse una vez.
    """
    import socket

    # socket.getaddrinfo devuelve una lista de tuplas
    # Simulamos que el dominio resuelve dos veces a la misma IP
    ip_duplicada = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
    ]

    consultas_realizadas = []

    async def mock_whois_ip(ip, dominio):
        consultas_realizadas.append(ip)

    with patch("socket.getaddrinfo", return_value=ip_duplicada):
        with patch.object(whois_module, "_whois_ip", side_effect=mock_whois_ip):
            await whois_module._whois_ips("example.com")

    assert consultas_realizadas.count("1.2.3.4") == 1


@pytest.mark.asyncio
async def test_whois_ips_error_resolucion_no_falla(whois_module):
    """
    Si la resolución DNS del dominio falla (dominio inexistente),
    el módulo debe terminar sin findings ni excepciones.
    """
    with patch("socket.getaddrinfo", side_effect=Exception("NXDOMAIN")):
        await whois_module._whois_ips("noexiste.invalido")

    assert len(whois_module.findings) == 0


# ---------------------------------------------------------------------------
# Test de integración del módulo completo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_aunque_todo_falle(config_base):
    """
    run() nunca debe lanzar una excepción hacia el orquestador.
    Aunque todas las fuentes fallen, devuelve una lista vacía.
    """
    modulo = WhoisModule(config_base)

    with patch("osint.modules.whois_module.whois") as mock_whois_lib:
        mock_whois_lib.whois.side_effect = Exception("Timeout")
        with patch("socket.getaddrinfo", side_effect=Exception("NXDOMAIN")):
            resultado = await modulo.run("example.com")

    assert isinstance(resultado, list)


@pytest.mark.asyncio
async def test_run_completo_produce_findings(config_base):
    """
    Con datos válidos, run() debe producir findings de los
    tipos esperados: whois_domain, whois_registrant,
    whois_nameserver e ip_asn.
    """
    modulo = WhoisModule(config_base)
    datos_mock = mock_whois_resultado()

    datos_rdap = {
        "asn": "AS15169",
        "asn_description": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "asn_country_code": "US",
        "network": {"name": "GOOGLE"},
    }

    import socket
    ips_mock = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

    with patch("osint.modules.whois_module.whois") as mock_whois_lib:
        mock_whois_lib.whois.return_value = datos_mock
        with patch("socket.getaddrinfo", return_value=ips_mock):
            with patch.object(modulo, "_consultar_ipwhois", return_value=datos_rdap):
                resultado = await modulo.run("example.com")

    tipos = {f.type for f in resultado}
    assert "whois_domain" in tipos
    assert "whois_registrant" in tipos
    assert "whois_nameserver" in tipos
    assert "ip_asn" in tipos
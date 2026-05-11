from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.dns_module import DnsModule


# ---------------------------------------------------------------------------
# Fixtures: objetos reutilizables en todos los tests
# ---------------------------------------------------------------------------


@pytest.fixture
def config_base():
    """
    Configuración mínima para los tests.
    Usamos MagicMock para no depender de un config.yaml real.
    Cada atributo que el módulo necesita lo definimos explícitamente.
    """
    config = MagicMock()
    config.modules.dns.resolvers = ["8.8.8.8"]
    config.modules.dns.bruteforce = False
    config.modules.dns.wordlist = None
    config.network.timeout = 5
    return config


@pytest.fixture
def dns_module(config_base):
    """
    Instancia del módulo DNS lista para usar en cada test.
    Se crea de nuevo para cada test para que los findings
    no se acumulen entre pruebas.
    """
    return DnsModule(config_base)


# ---------------------------------------------------------------------------
# Tests de la clase base
# ---------------------------------------------------------------------------


def test_dns_module_hereda_de_base_module(dns_module):
    """
    Comprueba que DnsModule hereda correctamente de BaseModule.
    Si esto falla, el orquestador no podrá registrar el módulo.
    """
    assert isinstance(dns_module, BaseModule)


def test_dns_module_tiene_nombre(dns_module):
    """El módulo debe tener un nombre definido para identificarse en los logs."""
    assert dns_module.name == "dns"
    assert len(dns_module.name) > 0


def test_dns_module_no_requiere_api_key(dns_module):
    """
    El módulo DNS no necesita API key.
    Si esto cambia, el orquestador empezaría a pedir una key inexistente.
    """
    assert dns_module.requires_api_key() is None


def test_dns_module_siempre_disponible(dns_module):
    """
    Sin API key requerida, el módulo debe estar siempre disponible
    independientemente de lo que haya en config.yaml.
    """
    assert dns_module.is_available() is True


# ---------------------------------------------------------------------------
# Tests de resolución de registros
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consulta_registro_a_crea_finding(dns_module):
    """
    Comprueba que al resolver un registro A se crea un finding
    con los campos correctos.
    """
    # Simulamos la respuesta de aiodns para un registro A
    mock_registro = MagicMock()
    mock_registro.__str__ = MagicMock(return_value="93.184.216.34")

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(return_value=[mock_registro])

    await dns_module._consultar_registro(mock_resolver, "example.com", "A")

    assert len(dns_module.findings) == 1
    finding = dns_module.findings[0]
    assert finding.type == "dns_a"
    assert finding.value == "93.184.216.34"
    assert finding.module == "dns"
    assert finding.severity == Severity.INFO


@pytest.mark.asyncio
async def test_consulta_registro_mx_crea_finding(dns_module):
    """
    Comprueba que los registros MX se registran correctamente.
    Los MX son importantes porque revelan el proveedor de email.
    """
    mock_registro = MagicMock()
    mock_registro.__str__ = MagicMock(return_value="mail.example.com")

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(return_value=[mock_registro])

    await dns_module._consultar_registro(mock_resolver, "example.com", "MX")

    assert len(dns_module.findings) == 1
    assert dns_module.findings[0].type == "dns_mx"


@pytest.mark.asyncio
async def test_consulta_registro_inexistente_no_crea_finding(dns_module):
    """
    Cuando un registro no existe, aiodns lanza DNSError.
    El módulo debe capturarla y no crear ningún finding ni lanzar excepción.
    """
    import aiodns

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(side_effect=aiodns.error.DNSError)

    await dns_module._consultar_registro(mock_resolver, "example.com", "AAAA")

    assert len(dns_module.findings) == 0


@pytest.mark.asyncio
async def test_multiples_registros_crean_multiples_findings(dns_module):
    """
    Un dominio puede tener varios registros del mismo tipo, por ejemplo
    varios registros A para balanceo de carga. Todos deben registrarse.
    """
    registros = []
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
        mock = MagicMock()
        mock.__str__ = MagicMock(return_value=ip)
        registros.append(mock)

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(return_value=registros)

    await dns_module._consultar_registro(mock_resolver, "example.com", "A")

    assert len(dns_module.findings) == 3


# ---------------------------------------------------------------------------
# Tests de clasificación de severidad
# ---------------------------------------------------------------------------


def test_severidad_registro_a_es_info(dns_module):
    """Los registros A son informativos por defecto."""
    assert dns_module._clasificar_severidad("A", "93.184.216.34") == Severity.INFO


def test_severidad_registro_ns_es_low(dns_module):
    """
    Los registros NS son LOW porque revelan el proveedor DNS
    y pueden usarse para intentar transferencias de zona.
    """
    assert dns_module._clasificar_severidad("NS", "ns1.example.com") == Severity.LOW


def test_severidad_txt_con_spf_es_low(dns_module):
    """
    Los registros TXT con SPF son LOW porque una mala configuración
    de SPF puede permitir suplantación de identidad por email.
    """
    resultado = dns_module._clasificar_severidad("TXT", "v=spf1 include:example.com ~all")
    assert resultado == Severity.LOW


def test_severidad_txt_con_dmarc_es_low(dns_module):
    """DMARC es otra política de email que merece revisión."""
    resultado = dns_module._clasificar_severidad("TXT", "_dmarc v=DMARC1; p=none")
    assert resultado == Severity.LOW


def test_severidad_txt_generico_es_info(dns_module):
    """Un TXT genérico sin contenido sensible es solo informativo."""
    resultado = dns_module._clasificar_severidad("TXT", "google-site-verification=abc123")
    assert resultado == Severity.INFO


# ---------------------------------------------------------------------------
# Tests de transferencia de zona
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transferencia_zona_exitosa_crea_findings_high(dns_module):
    """
    Si la transferencia de zona funciona, es una misconfiguration grave.
    Todos los registros obtenidos deben tener severidad HIGH.
    """
    # Simulamos un nameserver y una zona con dos registros
    mock_ns = MagicMock()
    mock_ns.target.__str__ = MagicMock(return_value="ns1.example.com.")

    mock_nodo_1 = MagicMock()
    mock_nodo_1.__str__ = MagicMock(return_value="www")
    mock_nodo_2 = MagicMock()
    mock_nodo_2.__str__ = MagicMock(return_value="mail")

    mock_zona = MagicMock()
    mock_zona.nodes = [mock_nodo_1, mock_nodo_2]

    with patch("dns.resolver.resolve", return_value=[mock_ns]):
        with patch("dns.zone.from_xfr", return_value=mock_zona):
            with patch("dns.query.xfr", return_value=MagicMock()):
                await dns_module._intentar_transferencia_zona("example.com")

    assert len(dns_module.findings) == 2
    for finding in dns_module.findings:
        assert finding.severity == Severity.HIGH
        assert finding.type == "zone_transfer_record"


@pytest.mark.asyncio
async def test_transferencia_zona_bloqueada_no_crea_findings(dns_module):
    """
    En servidores bien configurados la transferencia falla.
    El módulo debe manejarlo silenciosamente sin crear findings ni errores.
    """
    with patch("dns.resolver.resolve", side_effect=Exception("REFUSED")):
        await dns_module._intentar_transferencia_zona("example.com")

    assert len(dns_module.findings) == 0


# ---------------------------------------------------------------------------
# Tests de fuerza bruta de subdominios
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bruteforce_encuentra_subdominio_activo(dns_module, tmp_path):
    """
    Si un subdominio resuelve a una IP, debe registrarse como finding LOW.
    Usamos tmp_path (fixture de pytest) para crear un wordlist temporal.
    """
    # Creamos una wordlist temporal con una sola palabra
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n")
    dns_module.config.modules.dns.wordlist = wordlist

    mock_registro = MagicMock()
    mock_registro.__str__ = MagicMock(return_value="10.0.0.1")

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(return_value=[mock_registro])

    await dns_module._fuerza_bruta_subdominios(mock_resolver, "example.com")

    assert len(dns_module.findings) == 1
    finding = dns_module.findings[0]
    assert finding.type == "subdomain"
    assert finding.value == "dev.example.com"
    assert finding.severity == Severity.LOW


@pytest.mark.asyncio
async def test_bruteforce_subdominio_inexistente_no_crea_finding(dns_module, tmp_path):
    """
    Si el subdominio no existe la consulta falla y no debe crear ningún finding.
    """
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("noexiste\n")
    dns_module.config.modules.dns.wordlist = wordlist

    mock_resolver = MagicMock()
    mock_resolver.query = AsyncMock(side_effect=Exception("NXDOMAIN"))

    await dns_module._fuerza_bruta_subdominios(mock_resolver, "example.com")

    assert len(dns_module.findings) == 0


@pytest.mark.asyncio
async def test_bruteforce_sin_wordlist_no_falla(dns_module):
    """
    Si no hay wordlist configurada el módulo debe terminar silenciosamente
    sin lanzar ninguna excepción.
    """
    dns_module.config.modules.dns.wordlist = None
    mock_resolver = MagicMock()

    await dns_module._fuerza_bruta_subdominios(mock_resolver, "example.com")

    assert len(dns_module.findings) == 0


# ---------------------------------------------------------------------------
# Test de integración del módulo completo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_de_findings(config_base):
    """
    Test de integración: comprueba que run() devuelve una lista
    aunque todas las consultas fallen. El módulo nunca debe lanzar
    una excepción sin capturar hacia el orquestador.
    """
    modulo = DnsModule(config_base)

    with patch("aiodns.DNSResolver") as mock_resolver_cls:
        instancia = mock_resolver_cls.return_value
        instancia.query = AsyncMock(side_effect=Exception("timeout"))

        with patch("dns.resolver.resolve", side_effect=Exception("timeout")):
            resultado = await modulo.run("example.com")

    assert isinstance(resultado, list)
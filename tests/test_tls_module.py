from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.tls_module import TlsModule


# ---------------------------------------------------------------------------
# Helpers: generadores de certificados de prueba
# ---------------------------------------------------------------------------


def generar_clave_rsa(bits: int = 2048):
    """
    Genera una clave RSA real para usar en los tests.
    Usa claves reales en lugar de mocks porque cryptography
    necesita objetos válidos para firmar certificados.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )


def generar_certificado(
    dominio: str = "example.com",
    dias_validez: int = 365,
    autofirmado: bool = True,
    sans: list[str] | None = None,
    bits_clave: int = 2048,
    algoritmo_firma=None,
) -> bytes:
    """
    Genera un certificado X.509 real en formato DER para los tests.

    Esto es necesario porque TlsModule usa la librería cryptography
    para parsear certificados reales. Un MagicMock no funcionaría aquí
    porque cryptography opera sobre bytes reales, no sobre objetos simulados.

    Parámetros:
    - dominio: CN del certificado
    - dias_validez: días desde hoy hasta la expiración (negativo = ya expirado)
    - autofirmado: si True, el emisor es el mismo que el sujeto
    - sans: lista de Subject Alternative Names adicionales
    - bits_clave: tamaño de la clave RSA
    - algoritmo_firma: algoritmo de hash (por defecto SHA256)
    """
    clave = generar_clave_rsa(bits_clave)
    algoritmo = algoritmo_firma or hashes.SHA256()
    ahora = datetime.now(timezone.utc)

    # Construye el subject (identidad del certificado)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, dominio),
    ])

    # En un certificado autofirmado el issuer es igual al subject
    issuer = subject if autofirmado else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])

    # Si dias_validez es negativo el certificado debe haber expirado.
    # Ponemos not_valid_before suficientemente atrás para que
    # not_valid_after siempre sea posterior a not_valid_before.
    not_before = ahora - timedelta(days=abs(dias_validez) + 1)
    not_after = ahora + timedelta(days=dias_validez)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Añade los SANs si se han especificado
    nombres_san = [x509.DNSName(dominio)]
    if sans:
        for san in sans:
            nombres_san.append(x509.DNSName(san))

    builder = builder.add_extension(
        x509.SubjectAlternativeName(nombres_san),
        critical=False,
    )

    # Firma el certificado con la clave privada
    cert = builder.sign(clave, algoritmo)

    # Devuelve en formato DER (bytes), que es lo que usa TlsModule
    return cert.public_bytes(serialization.Encoding.DER)


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
def tls_module(config_base):
    """Instancia del módulo TLS lista para cada test."""
    return TlsModule(config_base)


# ---------------------------------------------------------------------------
# Tests de la clase base
# ---------------------------------------------------------------------------


def test_tls_module_hereda_de_base_module(tls_module):
    """TlsModule debe heredar de BaseModule para que el orquestador lo acepte."""
    assert isinstance(tls_module, BaseModule)


def test_tls_module_tiene_nombre(tls_module):
    """El nombre identifica el módulo en logs e informes."""
    assert tls_module.name == "tls"


def test_tls_module_no_requiere_api_key(tls_module):
    """crt.sh y la conexión TLS directa son gratuitas y sin autenticación."""
    assert tls_module.requires_api_key() is None


def test_tls_module_siempre_disponible(tls_module):
    """Sin API key requerida, el módulo siempre está disponible."""
    assert tls_module.is_available() is True


# ---------------------------------------------------------------------------
# Tests de severidad por expiración
# ---------------------------------------------------------------------------


def test_severidad_certificado_expirado(tls_module):
    """
    Un certificado con fecha de expiración en el pasado debe ser MEDIUM.
    En crt.sh aparecen muchos certificados históricos expirados, es normal.
    Lo marcamos MEDIUM porque podría seguir en uso.
    """
    fecha_pasada = "2020-01-01T00:00:00Z"
    assert tls_module._severidad_por_expiracion(fecha_pasada) == Severity.MEDIUM


def test_severidad_certificado_expira_pronto(tls_module):
    """Un certificado que expira en menos de 30 días merece atención."""
    pronto = (datetime.now(timezone.utc) + timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert tls_module._severidad_por_expiracion(pronto) == Severity.LOW


def test_severidad_certificado_vigente(tls_module):
    """Un certificado con larga validez es solo informativo."""
    futuro = (datetime.now(timezone.utc) + timedelta(days=300)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert tls_module._severidad_por_expiracion(futuro) == Severity.INFO


def test_severidad_fecha_vacia(tls_module):
    """Si no hay fecha de expiración, el hallazgo es informativo por defecto."""
    assert tls_module._severidad_por_expiracion("") == Severity.INFO


def test_severidad_fecha_malformada(tls_module):
    """Una fecha con formato incorrecto no debe lanzar excepción."""
    assert tls_module._severidad_por_expiracion("no-es-una-fecha") == Severity.INFO


# ---------------------------------------------------------------------------
# Tests de consulta a crt.sh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crt_sh_crea_findings_por_subdominio(tls_module):
    """
    Comprueba que cada entrada de crt.sh genera un finding
    con los campos correctos.
    """
    respuesta_mock = [
        {
            "id": 1,
            "name_value": "sub.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        }
    ]

    mock_respuesta = MagicMock()
    mock_respuesta.status = 200
    mock_respuesta.json = AsyncMock(return_value=respuesta_mock)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await tls_module._consultar_crt_sh("example.com")

    assert len(tls_module.findings) == 1
    finding = tls_module.findings[0]
    assert finding.type == "certificate_subdomain"
    assert finding.value == "sub.example.com"
    assert finding.module == "tls"
    assert finding.source == "crt.sh"


@pytest.mark.asyncio
async def test_crt_sh_elimina_wildcards(tls_module):
    """
    Los nombres con comodín (*.example.com) deben limpiarse
    antes de registrarse como finding.
    """
    respuesta_mock = [
        {
            "id": 2,
            "name_value": "*.example.com",
            "issuer_name": "Test CA",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        }
    ]

    mock_respuesta = MagicMock()
    mock_respuesta.status = 200
    mock_respuesta.json = AsyncMock(return_value=respuesta_mock)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await tls_module._consultar_crt_sh("example.com")

    assert tls_module.findings[0].value == "example.com"


@pytest.mark.asyncio
async def test_crt_sh_deduplica_subdominios(tls_module):
    """
    Si crt.sh devuelve el mismo subdominio varias veces
    (certificados distintos para el mismo dominio), solo
    debe registrarse una vez.
    """
    respuesta_mock = [
        {
            "id": 1,
            "name_value": "sub.example.com",
            "issuer_name": "CA 1",
            "not_before": "2023-01-01T00:00:00Z",
            "not_after": "2024-01-01T00:00:00Z",
        },
        {
            "id": 2,
            "name_value": "sub.example.com",
            "issuer_name": "CA 2",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        },
    ]

    mock_respuesta = MagicMock()
    mock_respuesta.status = 200
    mock_respuesta.json = AsyncMock(return_value=respuesta_mock)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await tls_module._consultar_crt_sh("example.com")

    assert len(tls_module.findings) == 1


@pytest.mark.asyncio
async def test_crt_sh_ignora_dominios_ajenos(tls_module):
    """
    crt.sh puede devolver dominios que contienen el nombre del objetivo
    pero no pertenecen a él. Deben filtrarse.
    Por ejemplo: si buscamos 'example.com', ignoramos 'notexample.com'.
    """
    respuesta_mock = [
        {
            "id": 3,
            "name_value": "notexample.com",
            "issuer_name": "CA",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        }
    ]

    mock_respuesta = MagicMock()
    mock_respuesta.status = 200
    mock_respuesta.json = AsyncMock(return_value=respuesta_mock)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await tls_module._consultar_crt_sh("example.com")

    assert len(tls_module.findings) == 0


@pytest.mark.asyncio
async def test_crt_sh_status_error_no_falla(tls_module):
    """Si crt.sh devuelve un error HTTP, el módulo no debe lanzar excepción."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = 503

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await tls_module._consultar_crt_sh("example.com")

    assert len(tls_module.findings) == 0


# ---------------------------------------------------------------------------
# Tests de análisis del certificado activo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_certificado_valido_crea_finding_info(tls_module):
    """
    Un certificado válido y bien configurado debe generar
    un finding informativo con los datos básicos.
    """
    cert_der = generar_certificado("example.com", dias_validez=365)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    info = [f for f in tls_module.findings if f.type == "certificate_info"]
    assert len(info) == 1
    assert info[0].severity == Severity.INFO
    assert info[0].metadata["subject_cn"] == "example.com"


@pytest.mark.asyncio
async def test_certificado_expirado_crea_finding_high(tls_module):
    """
    Un certificado expirado en producción es un hallazgo de severidad HIGH
    porque el navegador mostrará advertencias y puede indicar abandono.
    """
    cert_der = generar_certificado("example.com", dias_validez=-30)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    expirados = [f for f in tls_module.findings if f.type == "expired_certificate"]
    assert len(expirados) == 1
    assert expirados[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_certificado_expira_pronto_high(tls_module):
    """Un certificado que expira en menos de 15 días es HIGH."""
    cert_der = generar_certificado("example.com", dias_validez=10)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    expirando = [f for f in tls_module.findings if f.type == "expiring_certificate"]
    assert len(expirando) == 1
    assert expirando[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_certificado_expira_pronto_medium(tls_module):
    """Un certificado que expira entre 15 y 30 días es MEDIUM."""
    cert_der = generar_certificado("example.com", dias_validez=20)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    expirando = [f for f in tls_module.findings if f.type == "expiring_certificate"]
    assert len(expirando) == 1
    assert expirando[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_certificado_autofirmado_detectado(tls_module):
    """
    Un certificado autofirmado en producción es MEDIUM porque cualquiera
    puede emitir uno para cualquier dominio sin validación.
    """
    cert_der = generar_certificado("example.com", autofirmado=True)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    autofirmados = [
        f for f in tls_module.findings if f.type == "self_signed_certificate"
    ]
    assert len(autofirmados) == 1
    assert autofirmados[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_clave_rsa_debil_detectada(tls_module):
    """
    Una clave RSA de 1024 bits se considera insegura desde 2010.
    Debe detectarse como HIGH.
    """
    cert_der = generar_certificado("example.com", bits_clave=1024)

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    claves_debiles = [f for f in tls_module.findings if f.type == "weak_rsa_key"]
    assert len(claves_debiles) == 1
    assert claves_debiles[0].severity == Severity.HIGH
    assert "1024" in claves_debiles[0].value


@pytest.mark.asyncio
async def test_sans_se_registran_como_findings(tls_module):
    """
    Los SANs del certificado son dominios adicionales que cubre.
    Cada uno debe registrarse como finding informativo.
    """
    cert_der = generar_certificado(
        "example.com",
        sans=["www.example.com", "api.example.com"],
    )

    with patch.object(tls_module, "_obtener_cert_der", return_value=cert_der):
        await tls_module._analizar_certificado_activo("example.com")

    sans = [f for f in tls_module.findings if f.type == "san_domain"]
    valores = [f.value for f in sans]
    assert "www.example.com" in valores
    assert "api.example.com" in valores


@pytest.mark.asyncio
async def test_servidor_sin_https_no_falla(tls_module):
    """
    Si el servidor no tiene HTTPS o rechaza la conexión,
    el módulo debe terminar sin findings y sin excepciones.
    """
    with patch.object(
        tls_module,
        "_obtener_cert_der",
        side_effect=ConnectionRefusedError,
    ):
        await tls_module._analizar_certificado_activo("example.com")

    assert len(tls_module.findings) == 0


# ---------------------------------------------------------------------------
# Test de integración
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_aunque_todo_falle(config_base):
    """
    run() nunca debe lanzar una excepción hacia el orquestador.
    Aunque todas las fuentes fallen, devuelve una lista vacía.
    """
    modulo = TlsModule(config_base)

    mock_respuesta = MagicMock()
    mock_respuesta.status = 500

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        with patch.object(modulo, "_obtener_cert_der", side_effect=Exception):
            resultado = await modulo.run("example.com")

    assert isinstance(resultado, list)
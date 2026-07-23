from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.leaks_module import LeaksModule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config_sin_key():
    """Configuración sin ninguna API key — usa breach.directory."""
    config = MagicMock()
    config.get_api_key.return_value = None
    config.network.timeout = 5
    return config


@pytest.fixture
def config_con_hibp():
    """Configuración con API key de HIBP."""
    config = MagicMock()
    config.get_api_key.side_effect = lambda k: "test_hibp_key" if k == "hibp" else None
    config.network.timeout = 5
    return config


@pytest.fixture
def modulo_sin_key(config_sin_key):
    """Instancia del módulo sin API key."""
    return LeaksModule(config_sin_key)


@pytest.fixture
def modulo_con_hibp(config_con_hibp):
    """Instancia del módulo con key de HIBP."""
    return LeaksModule(config_con_hibp)


def mock_sesion_http(status: int = 200, json_data=None):
    """
    Helper reutilizable para mockear aiohttp.ClientSession.
    Evita repetir el mismo boilerplate en cada test.
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


# Respuesta mock de HIBP para el endpoint /breacheddomain/{domain}
HIBP_DOMINIO_MOCK = {
    "admin":    ["Adobe", "LinkedIn"],
    "info":     ["RockYou2024"],
    "john.doe": ["Adobe"],
}

# Respuesta mock de HIBP para el endpoint /breach/{name}
HIBP_BRECHA_DETALLE_MOCK = {
    "Name":        "Adobe",
    "Title":       "Adobe",
    "BreachDate":  "2013-10-04",
    "PwnCount":    152445165,
    "DataClasses": ["Email addresses", "Passwords", "Usernames"],
    "IsVerified":  True,
    "IsSpamList":  False,
}

# Respuesta mock de breach.directory con resultados
BREACH_DIRECTORY_CON_RESULTADOS = {
    "found": True,
    "result": [
        {"email": "admin@ejemplo.com",    "sources": ["BreachA"]},
        {"email": "info@ejemplo.com",     "sources": ["BreachB"]},
        {"email": "contacto@ejemplo.com", "sources": ["BreachA", "BreachC"]},
    ],
}

# Respuesta mock de breach.directory sin resultados
BREACH_DIRECTORY_SIN_RESULTADOS = {
    "found":  False,
    "result": [],
}


# ---------------------------------------------------------------------------
# Tests de clase base
# ---------------------------------------------------------------------------


def test_leaks_module_hereda_de_base_module(modulo_sin_key):
    """LeaksModule debe heredar de BaseModule."""
    assert isinstance(modulo_sin_key, BaseModule)


def test_leaks_module_tiene_nombre(modulo_sin_key):
    """El nombre identifica el módulo en logs e informes."""
    assert modulo_sin_key.name == "leaks"


def test_leaks_module_requiere_api_key_hibp(modulo_sin_key):
    """El módulo declara que usa la key de HIBP si está disponible."""
    assert modulo_sin_key.requires_api_key() == "hibp"


def test_leaks_module_disponible_sin_key(modulo_sin_key):
    """
    Sin key el módulo sigue disponible porque tiene
    breach.directory como alternativa gratuita.
    """
    assert modulo_sin_key.is_available() is True


def test_leaks_module_disponible_con_key(modulo_con_hibp):
    """Con key de HIBP también debe estar disponible."""
    assert modulo_con_hibp.is_available() is True


# ---------------------------------------------------------------------------
# Tests de extracción de dominio raíz
# ---------------------------------------------------------------------------


def test_extrae_dominio_raiz_de_fqdn(modulo_sin_key):
    """
    Un FQDN con subdominios debe reducirse al dominio raíz
    porque HIBP trabaja a nivel de dominio, no de subdominio.
    """
    assert modulo_sin_key._extraer_dominio_raiz("sub.ejemplo.com") == "ejemplo.com"


def test_extrae_dominio_raiz_de_dominio_simple(modulo_sin_key):
    """Un dominio sin subdominio debe devolverse tal cual."""
    assert modulo_sin_key._extraer_dominio_raiz("ejemplo.com") == "ejemplo.com"


def test_extrae_dominio_raiz_normaliza_mayusculas(modulo_sin_key):
    """El dominio extraído debe estar en minúsculas."""
    assert modulo_sin_key._extraer_dominio_raiz("EJEMPLO.COM") == "ejemplo.com"


def test_extrae_dominio_raiz_multiple_subdominios(modulo_sin_key):
    """Con múltiples niveles de subdominio solo se queda con los dos últimos."""
    assert modulo_sin_key._extraer_dominio_raiz("a.b.c.ejemplo.com") == "ejemplo.com"


# ---------------------------------------------------------------------------
# Tests del proveedor HIBP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hibp_sin_key_no_hace_peticion(modulo_sin_key):
    """Sin key de HIBP no debe intentar contactar con la API."""
    with patch("aiohttp.ClientSession") as mock_cls:
        await modulo_sin_key._consultar_brechas_dominio("ejemplo.com")
        mock_cls.assert_not_called()


@pytest.mark.asyncio
async def test_hibp_404_crea_finding_no_leaks(modulo_con_hibp):
    """
    Un 404 de HIBP significa que el dominio no aparece en ninguna brecha.
    Es una buena noticia y debe registrarse como INFO.
    """
    mock_session = mock_sesion_http(404)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_hibp._consultar_brechas_dominio("ejemplo.com")

    findings = [f for f in modulo_con_hibp.findings if f.type == "no_leaks_found"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_hibp_401_no_falla(modulo_con_hibp):
    """Una key inválida devuelve 401 y no debe propagar excepción."""
    mock_session = mock_sesion_http(401)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_con_hibp._consultar_brechas_dominio("ejemplo.com")

    assert len(modulo_con_hibp.findings) == 0


@pytest.mark.asyncio
async def test_hibp_procesa_respuesta_con_brechas(modulo_con_hibp):
    """
    Con una respuesta válida de HIBP debe crearse un finding de resumen
    y un finding por cada alias comprometido.
    """
    with patch.object(
        modulo_con_hibp,
        "_consultar_detalle_brecha",
        new_callable=AsyncMock,
    ):
        await modulo_con_hibp._procesar_respuesta_dominio(
            HIBP_DOMINIO_MOCK, "ejemplo.com"
        )

    resumen = [f for f in modulo_con_hibp.findings if f.type == "domain_breach_summary"]
    emails   = [f for f in modulo_con_hibp.findings if f.type == "compromised_email"]

    assert len(resumen) == 1
    assert resumen[0].metadata["compromised_accounts"] == 3
    assert resumen[0].metadata["unique_breaches"] == 3
    assert len(emails) == 3


@pytest.mark.asyncio
async def test_hibp_severidad_alta_con_muchas_cuentas(modulo_con_hibp):
    """Con 10 o más cuentas comprometidas el resumen debe ser HIGH."""
    datos = {f"user{i}": ["BreachA"] for i in range(10)}
    with patch.object(
        modulo_con_hibp,
        "_consultar_detalle_brecha",
        new_callable=AsyncMock,
    ):
        await modulo_con_hibp._procesar_respuesta_dominio(datos, "ejemplo.com")

    resumen = [f for f in modulo_con_hibp.findings if f.type == "domain_breach_summary"]
    assert resumen[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_hibp_severidad_medium_con_pocas_cuentas(modulo_con_hibp):
    """Con 3 a 9 cuentas comprometidas el resumen debe ser MEDIUM."""
    datos = {"user1": ["BreachA"], "user2": ["BreachB"], "user3": ["BreachC"]}
    with patch.object(
        modulo_con_hibp,
        "_consultar_detalle_brecha",
        new_callable=AsyncMock,
    ):
        await modulo_con_hibp._procesar_respuesta_dominio(datos, "ejemplo.com")

    resumen = [f for f in modulo_con_hibp.findings if f.type == "domain_breach_summary"]
    assert resumen[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_hibp_severidad_low_con_una_cuenta(modulo_con_hibp):
    """Con menos de 3 cuentas comprometidas el resumen debe ser LOW."""
    datos = {"user1": ["BreachA"]}
    with patch.object(
        modulo_con_hibp,
        "_consultar_detalle_brecha",
        new_callable=AsyncMock,
    ):
        await modulo_con_hibp._procesar_respuesta_dominio(datos, "ejemplo.com")

    resumen = [f for f in modulo_con_hibp.findings if f.type == "domain_breach_summary"]
    assert resumen[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Tests de detalle de brecha HIBP
# ---------------------------------------------------------------------------

def test_detalle_brecha_con_passwords_verificada_es_high(modulo_con_hibp):
    """
    Una brecha verificada que expuso contraseñas es el caso más grave.
    Debe clasificarse siempre como HIGH.
    """
    modulo_con_hibp._procesar_detalle_brecha(HIBP_BRECHA_DETALLE_MOCK, "ejemplo.com")

    detalle = [f for f in modulo_con_hibp.findings if f.type == "breach_detail"]
    assert len(detalle) == 1
    assert detalle[0].severity == Severity.HIGH
    assert detalle[0].metadata["has_passwords"] is True
    assert detalle[0].metadata["is_verified"] is True


def test_detalle_brecha_con_passwords_no_verificada_es_medium(modulo_con_hibp):
    """Una brecha con contraseñas pero no verificada es MEDIUM."""
    datos = {**HIBP_BRECHA_DETALLE_MOCK, "IsVerified": False}
    modulo_con_hibp._procesar_detalle_brecha(datos, "ejemplo.com")

    detalle = [f for f in modulo_con_hibp.findings if f.type == "breach_detail"]
    assert detalle[0].severity == Severity.MEDIUM


def test_detalle_brecha_solo_emails_verificada_es_low(modulo_con_hibp):
    """
    Una brecha que solo expuso emails verificada es LOW.
    Los emails no permiten acceso directo a sistemas.
    """
    datos = {
        **HIBP_BRECHA_DETALLE_MOCK,
        "DataClasses": ["Email addresses"],
        "IsVerified":  True,
    }
    modulo_con_hibp._procesar_detalle_brecha(datos, "ejemplo.com")

    detalle = [f for f in modulo_con_hibp.findings if f.type == "breach_detail"]
    assert detalle[0].severity == Severity.LOW


def test_detalle_brecha_spam_list_se_ignora(modulo_con_hibp):
    """
    Las spam lists no son relevantes en OSINT corporativo.
    No deben crear ningún finding.
    """
    datos = {**HIBP_BRECHA_DETALLE_MOCK, "IsSpamList": True}
    modulo_con_hibp._procesar_detalle_brecha(datos, "ejemplo.com")

    detalle = [f for f in modulo_con_hibp.findings if f.type == "breach_detail"]
    assert len(detalle) == 0


def test_detalle_brecha_incluye_metadatos(modulo_con_hibp):
    """El finding de detalle debe incluir fecha, total de afectados y datos expuestos."""
    modulo_con_hibp._procesar_detalle_brecha(HIBP_BRECHA_DETALLE_MOCK, "ejemplo.com")

    meta = modulo_con_hibp.findings[0].metadata
    assert meta["breach_date"]  == "2013-10-04"
    assert meta["total_pwned"]  == 152445165
    assert "Passwords" in meta["data_classes"]


# ---------------------------------------------------------------------------
# Tests del proveedor breach.directory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_breach_directory_con_resultados_crea_findings(modulo_sin_key):
    """
    Con resultados de breach.directory debe crearse un finding
    de resumen y uno por cada email comprometido encontrado.
    """
    mock_session = mock_sesion_http(200, BREACH_DIRECTORY_CON_RESULTADOS)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_breach_directory("ejemplo.com")

    resumen = [f for f in modulo_sin_key.findings if f.type == "domain_breach_summary"]
    emails   = [f for f in modulo_sin_key.findings if f.type == "compromised_email"]

    assert len(resumen) == 1
    assert resumen[0].source == "breach.directory"
    assert len(emails) == 3


@pytest.mark.asyncio
async def test_breach_directory_sin_resultados_crea_finding_info(modulo_sin_key):
    """
    Si breach.directory no encuentra nada, debe registrarse
    como INFO — el dominio no aparece en filtraciones conocidas.
    """
    mock_session = mock_sesion_http(200, BREACH_DIRECTORY_SIN_RESULTADOS)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_breach_directory("ejemplo.com")

    no_leaks = [f for f in modulo_sin_key.findings if f.type == "no_leaks_found"]
    assert len(no_leaks) == 1
    assert no_leaks[0].severity == Severity.INFO
    assert no_leaks[0].source == "breach.directory"


@pytest.mark.asyncio
async def test_breach_directory_429_crea_finding_rate_limited(modulo_sin_key):
    """
    Un 429 de breach.directory significa que se agotaron las
    10 búsquedas diarias gratuitas. Debe registrarse como INFO
    con un mensaje que indica cómo solucionar el límite.
    """
    mock_session = mock_sesion_http(429)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_key._consultar_breach_directory("ejemplo.com")

    rate_limited = [f for f in modulo_sin_key.findings if f.type == "leaks_rate_limited"]
    assert len(rate_limited) == 1
    assert rate_limited[0].severity == Severity.INFO
    assert "HIBP" in rate_limited[0].metadata["message"]


@pytest.mark.asyncio
async def test_breach_directory_error_red_no_falla(modulo_sin_key):
    """Un error de red no debe propagar la excepción al orquestador."""
    with patch("aiohttp.ClientSession", side_effect=Exception("Timeout")):
        await modulo_sin_key._consultar_breach_directory("ejemplo.com")

    assert len(modulo_sin_key.findings) == 0


def test_breach_directory_severidad_high_muchos_resultados(modulo_sin_key):
    """Con 10 o más registros el resumen de breach.directory es HIGH."""
    datos = {
        "found":  True,
        "result": [{"email": f"user{i}@ejemplo.com", "sources": ["BreachA"]}
                   for i in range(10)],
    }
    modulo_sin_key._procesar_breach_directory(datos, "ejemplo.com")

    resumen = [f for f in modulo_sin_key.findings if f.type == "domain_breach_summary"]
    assert resumen[0].severity == Severity.HIGH


def test_breach_directory_emails_se_registran_como_high(modulo_sin_key):
    """Cada email comprometido encontrado debe ser HIGH."""
    modulo_sin_key._procesar_breach_directory(
        BREACH_DIRECTORY_CON_RESULTADOS, "ejemplo.com"
    )

    emails = [f for f in modulo_sin_key.findings if f.type == "compromised_email"]
    for email_finding in emails:
        assert email_finding.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Tests de selección de proveedor en run()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_usa_breach_directory_sin_key(modulo_sin_key):
    """
    Sin key de HIBP, run() debe usar breach.directory.
    Verifica que se llama al método correcto.
    """
    with patch.object(
        modulo_sin_key,
        "_consultar_breach_directory",
        new_callable=AsyncMock,
    ) as mock_bd:
        with patch.object(
            modulo_sin_key,
            "_consultar_brechas_dominio",
            new_callable=AsyncMock,
        ) as mock_hibp:
            await modulo_sin_key.run("ejemplo.com")

    mock_bd.assert_called_once_with("ejemplo.com")
    mock_hibp.assert_not_called()


@pytest.mark.asyncio
async def test_run_usa_hibp_con_key(modulo_con_hibp):
    """
    Con key de HIBP, run() debe usar HIBP en lugar de breach.directory.
    HIBP tiene datos más completos y verificados.
    """
    with patch.object(
        modulo_con_hibp,
        "_consultar_brechas_dominio",
        new_callable=AsyncMock,
    ) as mock_hibp:
        with patch.object(
            modulo_con_hibp,
            "_consultar_breach_directory",
            new_callable=AsyncMock,
        ) as mock_bd:
            await modulo_con_hibp.run("ejemplo.com")

    mock_hibp.assert_called_once_with("ejemplo.com")
    mock_bd.assert_not_called()


@pytest.mark.asyncio
async def test_run_extrae_dominio_raiz_antes_de_consultar(modulo_sin_key):
    """
    run() debe extraer el dominio raíz antes de consultar.
    Si se pasa sub.ejemplo.com debe consultar por ejemplo.com.
    """
    with patch.object(
        modulo_sin_key,
        "_consultar_breach_directory",
        new_callable=AsyncMock,
    ) as mock_bd:
        await modulo_sin_key.run("sub.ejemplo.com")

    mock_bd.assert_called_once_with("ejemplo.com")


# ---------------------------------------------------------------------------
# Test de integración
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_aunque_todo_falle(config_sin_key):
    """
    run() nunca debe lanzar excepción al orquestador.
    Aunque todas las fuentes fallen devuelve lista vacía.
    """
    modulo = LeaksModule(config_sin_key)

    with patch("aiohttp.ClientSession", side_effect=Exception("Network error")):
        resultado = await modulo.run("ejemplo.com")

    assert isinstance(resultado, list)
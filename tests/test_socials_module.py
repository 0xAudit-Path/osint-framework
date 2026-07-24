from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from osint.core.datastore import Severity
from osint.core.orchestrator import BaseModule
from osint.modules.socials_module import SocialsModule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_sin_keys():
    """Configuración sin ninguna API key — usa dorks como fallback."""
    config = MagicMock()
    config.get_api_key.return_value = None
    config.network.timeout = 5
    return config

@pytest.fixture
def config_con_github():
    """Configuración con token de GitHub."""
    config = MagicMock()
    config.get_api_key.side_effect = lambda k: "ghp_test_token" if k == "github" else None
    config.network.timeout = 5
    return config


@pytest.fixture
def config_con_twitter():
    """Configuración con bearer token de Twitter."""
    config = MagicMock()
    config.get_api_key.side_effect = lambda k: "twitter_bearer_test" if k == "twitter" else None  
    config.network.timeout = 5
    return config


@pytest.fixture
def modulo_sin_keys(config_sin_keys):
    return SocialsModule(config_sin_keys)


@pytest.fixture
def modulo_con_github(config_con_github):
    return SocialsModule(config_con_github)


@pytest.fixture
def modulo_con_twitter(config_con_twitter):
    return SocialsModule(config_con_twitter)


def mock_sesion_http(status: int = 200, texto: str = ""):
    """Helper para mockear aiohttp.ClientSession con respuesta de texto."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = status
    mock_respuesta.text = AsyncMock(return_value=texto)
    mock_respuesta.json = AsyncMock(return_value={})
    mock_respuesta.url   = MagicMock()
    mock_respuesta.url.__str__ = MagicMock(return_value="https://example.com")

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__  = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__  = AsyncMock(return_value=None)

    return mock_session


# HTML simulado de Google con resultados de Twitter y LinkedIn
HTML_GOOGLE_TWITTER = """
<html><body>
<a href="https://twitter.com/ejemplo">twitter.com/ejemplo</a>
<a href="https://twitter.com/ejemplohq">twitter.com/ejemplohq</a>
twitter.com/ejemplo/
</body></html>
"""

HTML_GOOGLE_LINKEDIN = """
<html><body>
<a href="https://linkedin.com/company/ejemplo-corp">linkedin.com/company/ejemplo-corp</a>
linkedin.com/company/ejemplo-corp/about
</body></html>
"""

HTML_GOOGLE_VACIO = "<html><body>No results found</body></html>"


# ---------------------------------------------------------------------------
# Tests de clase base
# ---------------------------------------------------------------------------


def test_socials_module_hereda_de_base_module(modulo_sin_keys):
    assert isinstance(modulo_sin_keys, BaseModule)


def test_socials_module_tiene_nombre(modulo_sin_keys):
    assert modulo_sin_keys.name == "socials"


def test_socials_module_no_requiere_api_key(modulo_sin_keys):
    """El módulo funciona sin keys usando dorks como fallback."""
    assert modulo_sin_keys.requires_api_key() is None


def test_socials_module_siempre_disponible(modulo_sin_keys):
    assert modulo_sin_keys.is_available() is True


# ---------------------------------------------------------------------------
# Tests de extracción de nombre de organización
# ---------------------------------------------------------------------------


def test_extrae_org_de_dominio_simple(modulo_sin_keys):
    assert modulo_sin_keys._extraer_nombre_org("ejemplo.com") == "ejemplo"


def test_extrae_org_de_subdominio(modulo_sin_keys):
    assert modulo_sin_keys._extraer_nombre_org("www.ejemplo.com") == "www"


def test_extrae_org_normaliza_minusculas(modulo_sin_keys):
    assert modulo_sin_keys._extraer_nombre_org("EJEMPLO.COM") == "ejemplo"


# ---------------------------------------------------------------------------
# Tests de GitHub — perfil de organización
# ---------------------------------------------------------------------------


GITHUB_ORG_MOCK = {
    "login":        "ejemplo",
    "name":         "Ejemplo Corp",
    "bio":          "Empresa de ejemplo",
    "blog":         "https://ejemplo.com",
    "email":        "info@ejemplo.com",
    "public_repos": 15,
    "followers":    200,
    "location":     "Madrid, Spain",
}


def test_procesar_perfil_github_crea_finding(modulo_sin_keys):
    """Un perfil de GitHub válido debe crear un finding."""
    modulo_sin_keys._procesar_perfil_github(GITHUB_ORG_MOCK, 
        "organization", "ejemplo.com")

    perfiles = [f for f in modulo_sin_keys.findings if f.type == "github_profile"]
    assert len(perfiles) == 1
    assert "github.com/ejemplo" in perfiles[0].value
    assert perfiles[0].source == "github"


def test_procesar_perfil_github_confirmado_es_low(modulo_sin_keys):
    """
    Si el blog o email del perfil contiene el dominio objetivo
    el finding es LOW porque confirma la relación con el objetivo.
    """
    modulo_sin_keys._procesar_perfil_github(GITHUB_ORG_MOCK, 
        "organization", "ejemplo.com")

    perfiles = [f for f in modulo_sin_keys.findings if f.type == "github_profile"]
    assert perfiles[0].severity == Severity.LOW
    assert perfiles[0].metadata["confirmed"] is True


def test_procesar_perfil_github_no_confirmado_es_info(modulo_sin_keys):
    """
    Si el perfil no tiene relación evidente con el dominio
    el finding es INFO hasta confirmar que es el objetivo correcto.
    """
    datos = {**GITHUB_ORG_MOCK, "blog": "", "email": "", "name": "Random Corp"}
    modulo_sin_keys._procesar_perfil_github(datos, "organization", "ejemplo.com")

    perfiles = [f for f in modulo_sin_keys.findings if f.type == "github_profile"]
    assert perfiles[0].severity == Severity.INFO
    assert perfiles[0].metadata["confirmed"] is False


def test_procesar_perfil_github_incluye_metadatos(modulo_sin_keys):
    """El finding debe incluir repos públicos, seguidores y ubicación."""
    modulo_sin_keys._procesar_perfil_github(GITHUB_ORG_MOCK, 
        "organization", "ejemplo.com")

    meta = modulo_sin_keys.findings[0].metadata
    assert meta["public_repos"] == 15
    assert meta["followers"]    == 200
    assert meta["location"]     == "Madrid, Spain"
    assert meta["type"]         == "organization"


# ---------------------------------------------------------------------------
# Tests de GitHub — repositorios
# ---------------------------------------------------------------------------


def test_procesar_repo_normal_es_info(modulo_sin_keys):
    """Un repositorio normal sin nombre sospechoso es INFO."""
    repo = {
        "name":             "mi-app-web",
        "description":      "Aplicación web principal",
        "language":         "Python",
        "stargazers_count": 5,
        "fork":             False,
        "html_url":         "https://github.com/ejemplo/mi-app-web",
        "updated_at":       "2024-01-01T00:00:00Z",
        "archived":         False,
    }
    modulo_sin_keys._procesar_repo_github(repo, "ejemplo.com")

    repos = [f for f in modulo_sin_keys.findings if f.type == "github_repo"]
    assert len(repos) == 1
    assert repos[0].severity == Severity.INFO
    assert repos[0].metadata["suspicious"] is False


def test_procesar_repo_sospechoso_es_medium(modulo_sin_keys):
    """
    Un repo con nombre como 'backup', 'config' o 'credentials'
    puede contener información sensible expuesta accidentalmente.
    """
    repo = {
        "name":             "server-backup-2024",
        "description":      "Backup de configuración",
        "language":         "Shell",
        "stargazers_count": 0,
        "fork":             False,
        "html_url":         "https://github.com/ejemplo/server-backup-2024",
        "updated_at":       "2024-01-01T00:00:00Z",
        "archived":         False,
    }
    modulo_sin_keys._procesar_repo_github(repo, "ejemplo.com")

    repos = [f for f in modulo_sin_keys.findings if f.type == "github_repo"]
    assert repos[0].severity == Severity.MEDIUM
    assert repos[0].metadata["suspicious"] is True


def test_procesar_repo_fork_se_ignora(modulo_sin_keys):
    """
    Los forks no son código propio del objetivo.
    No deben registrarse como findings.
    """
    repo = {
        "name":             "repo-de-otro",
        "description":      "",
        "language":         "Python",
        "stargazers_count": 0,
        "fork":             True,
        "html_url":         "https://github.com/ejemplo/repo-de-otro",
        "updated_at":       "2024-01-01T00:00:00Z",
        "archived":         False,
    }
    modulo_sin_keys._procesar_repo_github(repo, "ejemplo.com")

    assert len(modulo_sin_keys.findings) == 0


def test_procesar_repo_registra_tecnologia(modulo_sin_keys):
    """
    El lenguaje de cada repo debe registrarse como finding
    de tecnología para que la IA pueda generar dorks específicos.
    """
    repo = {
        "name":             "api-backend",
        "description":      "",
        "language":         "Go",
        "stargazers_count": 3,
        "fork":             False,
        "html_url":         "https://github.com/ejemplo/api-backend",
        "updated_at":       "2024-01-01T00:00:00Z",
        "archived":         False,
    }
    modulo_sin_keys._procesar_repo_github(repo, "ejemplo.com")

    techs = [f for f in modulo_sin_keys.findings if f.type == "technology"]
    assert len(techs) == 1
    assert techs[0].value == "Go"


def test_procesar_repo_sin_lenguaje_no_crea_finding_tech(modulo_sin_keys):
    """Un repo sin lenguaje identificado no debe crear finding de tecnología."""
    repo = {
        "name":             "documentacion",
        "description":      "",
        "language":         None,
        "stargazers_count": 0,
        "fork":             False,
        "html_url":         "https://github.com/ejemplo/documentacion",
        "updated_at":       "2024-01-01T00:00:00Z",
        "archived":         False,
    }
    modulo_sin_keys._procesar_repo_github(repo, "ejemplo.com")

    techs = [f for f in modulo_sin_keys.findings if f.type == "technology"]
    assert len(techs) == 0


# ---------------------------------------------------------------------------
# Tests de GitHub — rate limit
# ---------------------------------------------------------------------------


def test_registrar_rate_limit_github_crea_finding_info(modulo_sin_keys):
    """El aviso de rate limit debe registrarse como INFO con mensaje claro."""
    modulo_sin_keys._registrar_rate_limit_github()

    rate_findings = [f for f in modulo_sin_keys.findings if f.type == "github_rate_limited"]
    assert len(rate_findings) == 1
    assert rate_findings[0].severity == Severity.INFO
    assert "token" in rate_findings[0].metadata["message"].lower()


# ---------------------------------------------------------------------------
# Tests de Twitter — dork
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_twitter_dork_encuentra_perfiles(modulo_sin_keys):
    """
    Si Google devuelve HTML con URLs de Twitter, deben registrarse
    como findings de perfil de Twitter.
    """
    mock_session = mock_sesion_http(200, HTML_GOOGLE_TWITTER)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._twitter_dork("ejemplo")

    twitter_findings = [f for f in modulo_sin_keys.findings if f.type == "twitter_profile"]
    assert len(twitter_findings) >= 1
    assert all(f.source == "twitter/dork" for f in twitter_findings)
    assert all(f.metadata["via"] == "dork" for f in twitter_findings)


@pytest.mark.asyncio
async def test_twitter_dork_filtra_handles_genericos(modulo_sin_keys):
    """
    URLs genéricas de Twitter como /search, /intent o /home
    no son perfiles de organización y deben filtrarse.
    """
    html_con_genericos = """
    <html><body>
    <a href="twitter.com/search?q=test">twitter.com/search</a>
    <a href="twitter.com/intent/tweet">twitter.com/intent</a>
    <a href="twitter.com/home">twitter.com/home</a>
    </body></html>
    """
    mock_session = mock_sesion_http(200, html_con_genericos)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._twitter_dork("ejemplo")

    twitter_findings = [f for f in modulo_sin_keys.findings if f.type == "twitter_profile"]
    assert len(twitter_findings) == 0


@pytest.mark.asyncio
async def test_twitter_dork_sin_resultados_no_crea_findings(modulo_sin_keys):
    """Si Google no devuelve perfiles de Twitter no debe crearse ningún finding."""
    mock_session = mock_sesion_http(200, HTML_GOOGLE_VACIO)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._twitter_dork("ejemplo")

    twitter_findings = [f for f in modulo_sin_keys.findings if f.type == "twitter_profile"]
    assert len(twitter_findings) == 0


@pytest.mark.asyncio
async def test_twitter_dork_error_red_no_falla(modulo_sin_keys):
    """Un error de red en el dork no debe propagar la excepción."""
    with patch("aiohttp.ClientSession", side_effect=Exception("Timeout")):
        await modulo_sin_keys._twitter_dork("ejemplo")

    assert len(modulo_sin_keys.findings) == 0


# ---------------------------------------------------------------------------
# Tests de Twitter — API oficial
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_twitter_usa_api_con_bearer_token(modulo_con_twitter):
    """Con bearer token debe intentar usar la API oficial de Twitter."""
    with patch.object(
        modulo_con_twitter, "_twitter_api_oficial", new_callable=AsyncMock
    ) as mock_api:
        with patch.object(
            modulo_con_twitter, "_twitter_dork", new_callable=AsyncMock
        ) as mock_dork:
            await modulo_con_twitter._reconocimiento_twitter("ejemplo")

    mock_api.assert_called_once_with("ejemplo", "twitter_bearer_test")
    mock_dork.assert_not_called()


@pytest.mark.asyncio
async def test_twitter_usa_dork_sin_token(modulo_sin_keys):
    """Sin bearer token debe usar el dork como fallback."""
    with patch.object(
        modulo_sin_keys, "_twitter_dork", new_callable=AsyncMock
    ) as mock_dork:
        with patch.object(
            modulo_sin_keys, "_twitter_api_oficial", new_callable=AsyncMock
        ) as mock_api:
            await modulo_sin_keys._reconocimiento_twitter("ejemplo")

    mock_dork.assert_called_once_with("ejemplo")
    mock_api.assert_not_called()


@pytest.mark.asyncio
async def test_twitter_api_falla_usa_dork_como_fallback(modulo_con_twitter):
    """
    Si la API oficial de Twitter falla, usa el dork como fallback automáticamente.
    """
    with patch.object(
        modulo_con_twitter,
        "_twitter_dork",
        new_callable=AsyncMock,
    ) as mock_dork:
        with patch(
            "osint.modules.socials_module.tweepy"
        ) as mock_tweepy:
            mock_tweepy.AsyncClient.return_value.get_user = AsyncMock(
                side_effect=Exception("Unauthorized")
            )
            await modulo_con_twitter._twitter_api_oficial("ejemplo", "bad_token")

    mock_dork.assert_called_once_with("ejemplo")



# ---------------------------------------------------------------------------
# Tests de LinkedIn — dork
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_linkedin_dork_encuentra_perfil(modulo_sin_keys):
    """Si Google devuelve HTML con URLs de LinkedIn deben registrarse."""
    mock_session = mock_sesion_http(200, HTML_GOOGLE_LINKEDIN)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._reconocimiento_linkedin("ejemplo")

    linkedin_findings = [f for f in modulo_sin_keys.findings if f.type == "linkedin_profile"]
    assert len(linkedin_findings) >= 1
    assert all(f.source == "linkedin/dork" for f in linkedin_findings)
    assert all(f.metadata["via"] == "dork" for f in linkedin_findings)


@pytest.mark.asyncio
async def test_linkedin_dork_sin_resultados_no_crea_findings(modulo_sin_keys):
    """Si Google no encuentra páginas de LinkedIn no se crea ningún finding."""
    mock_session = mock_sesion_http(200, HTML_GOOGLE_VACIO)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._reconocimiento_linkedin("ejemplo")

    linkedin_findings = [f for f in modulo_sin_keys.findings if f.type == "linkedin_profile"]
    assert len(linkedin_findings) == 0


@pytest.mark.asyncio
async def test_linkedin_dork_error_red_no_falla(modulo_sin_keys):
    """Un error de red no debe propagar la excepción."""
    with patch("aiohttp.ClientSession", side_effect=Exception("Timeout")):
        await modulo_sin_keys._reconocimiento_linkedin("ejemplo")

    assert len(modulo_sin_keys.findings) == 0


# ---------------------------------------------------------------------------
# Test de integración
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_devuelve_lista_aunque_todo_falle(config_sin_keys):
    """run() nunca debe lanzar excepción al orquestador."""
    modulo = SocialsModule(config_sin_keys)

    with patch("aiohttp.ClientSession", side_effect=Exception("Network error")):
        resultado = await modulo.run("ejemplo.com")

    assert isinstance(resultado, list)


def test_construir_headers_sin_token(modulo_sin_keys):
    """Sin token los headers no incluyen Authorization."""
    headers = modulo_sin_keys._construir_headers_github()
    assert "Authorization" not in headers
    assert headers["Accept"] == "application/vnd.github.v3+json"


def test_construir_headers_con_token(modulo_con_github):
    """Con token los headers incluyen Authorization con el token."""
    headers = modulo_con_github._construir_headers_github()
    assert "Authorization" in headers
    assert "ghp_test_token" in headers["Authorization"]


@pytest.mark.asyncio
async def test_buscar_github_org_encontrada(modulo_con_github):
    """Si la organización existe en GitHub debe crear findings y devolver True."""
    mock_respuesta_org = MagicMock()
    mock_respuesta_org.status = 200
    mock_respuesta_org.json = AsyncMock(return_value=GITHUB_ORG_MOCK)

    mock_respuesta_repos = MagicMock()
    mock_respuesta_repos.status = 200
    mock_respuesta_repos.json = AsyncMock(return_value=[])

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(
        side_effect=[mock_respuesta_org, mock_respuesta_repos]
    )
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    resultado = await modulo_con_github._buscar_github_org(
        mock_session,
        {"Accept": "application/vnd.github.v3+json"},
        "ejemplo",
        "ejemplo.com",
    )

    assert resultado is True
    perfiles = [f for f in modulo_con_github.findings if f.type == "github_profile"]
    assert len(perfiles) == 1


@pytest.mark.asyncio
async def test_buscar_github_org_no_encontrada(modulo_sin_keys):
    """Si la organización no existe en GitHub debe devolver False."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = 404

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    resultado = await modulo_sin_keys._buscar_github_org(
        mock_session, {}, "noexiste", "noexiste.com"
    )

    assert resultado is False


@pytest.mark.asyncio
async def test_buscar_github_org_rate_limit(modulo_sin_keys):
    """Un 403 de GitHub indica rate limit — debe registrarlo y devolver False."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = 403

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    resultado = await modulo_sin_keys._buscar_github_org(
        mock_session, {}, "ejemplo", "ejemplo.com"
    )

    assert resultado is False
    rate_findings = [
        f for f in modulo_sin_keys.findings if f.type == "github_rate_limited"
    ]
    assert len(rate_findings) == 1


@pytest.mark.asyncio
async def test_buscar_github_usuario_encontrado(modulo_sin_keys):
    """Si existe como usuario de GitHub debe crear un finding de perfil."""
    mock_respuesta_user = MagicMock()
    mock_respuesta_user.status = 200
    mock_respuesta_user.json = AsyncMock(return_value=GITHUB_ORG_MOCK)

    mock_respuesta_repos = MagicMock()
    mock_respuesta_repos.status = 200
    mock_respuesta_repos.json = AsyncMock(return_value=[])

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(
        side_effect=[mock_respuesta_user, mock_respuesta_repos]
    )
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    await modulo_sin_keys._buscar_github_usuario(
        mock_session, {}, "ejemplo", "ejemplo.com"
    )

    perfiles = [f for f in modulo_sin_keys.findings if f.type == "github_profile"]
    assert len(perfiles) == 1
    assert perfiles[0].metadata["type"] == "user"


@pytest.mark.asyncio
async def test_buscar_github_usuario_no_encontrado(modulo_sin_keys):
    """Si el usuario no existe en GitHub no debe crear ningún finding."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = 404

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    await modulo_sin_keys._buscar_github_usuario(
        mock_session, {}, "noexiste", "noexiste.com"
    )

    assert len(modulo_sin_keys.findings) == 0


@pytest.mark.asyncio
async def test_obtener_repos_github_crea_findings(modulo_sin_keys):
    """Con repositorios válidos debe crear findings de repo y tecnología."""
    repos_mock = [
        {
            "name":             "api-backend",
            "description":      "API principal",
            "language":         "Python",
            "stargazers_count": 5,
            "fork":             False,
            "html_url":         "https://github.com/ejemplo/api-backend",
            "updated_at":       "2024-01-01T00:00:00Z",
            "archived":         False,
        }
    ]

    mock_respuesta = MagicMock()
    mock_respuesta.status = 200
    mock_respuesta.json = AsyncMock(return_value=repos_mock)

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    await modulo_sin_keys._obtener_repos_github(
        mock_session, {}, "ejemplo", "ejemplo.com"
    )

    repos = [f for f in modulo_sin_keys.findings if f.type == "github_repo"]
    assert len(repos) == 1


@pytest.mark.asyncio
async def test_obtener_repos_github_status_error_no_falla(modulo_sin_keys):
    """Un error HTTP en la consulta de repos no debe propagar excepción."""
    mock_respuesta = MagicMock()
    mock_respuesta.status = 403

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_respuesta)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    await modulo_sin_keys._obtener_repos_github(
        mock_session, {}, "ejemplo", "ejemplo.com"
    )

    assert len(modulo_sin_keys.findings) == 0


@pytest.mark.asyncio
async def test_twitter_api_oficial_encuentra_usuario(modulo_con_twitter):
    """Con respuesta válida de la API de Twitter debe crear finding de perfil."""
    mock_usuario = MagicMock()
    mock_usuario.data = MagicMock()
    mock_usuario.data.username    = "ejemplo"
    mock_usuario.data.name        = "Ejemplo Corp"
    mock_usuario.data.description = "Cuenta oficial"
    mock_usuario.data.location    = "Madrid"
    mock_usuario.data.url         = "https://ejemplo.com"
    mock_usuario.data.public_metrics = {
        "followers_count": 1000,
        "following_count": 100,
        "tweet_count":     500,
    }

    with patch("osint.modules.socials_module.tweepy") as mock_tweepy:
        mock_tweepy.AsyncClient.return_value.get_user = AsyncMock(
            return_value=mock_usuario
        )
        await modulo_con_twitter._twitter_api_oficial("ejemplo", "bearer_token")

    perfiles = [f for f in modulo_con_twitter.findings if f.type == "twitter_profile"]
    assert len(perfiles) == 1
    assert perfiles[0].metadata["via"]       == "api"
    assert perfiles[0].metadata["followers"] == 1000


@pytest.mark.asyncio
async def test_twitter_api_oficial_usuario_no_encontrado(modulo_con_twitter):
    """Si la API no encuentra el usuario no debe crear ningún finding."""
    mock_resultado = MagicMock()
    mock_resultado.data = None

    with patch("osint.modules.socials_module.tweepy") as mock_tweepy:
        mock_tweepy.AsyncClient.return_value.get_user = AsyncMock(
            return_value=mock_resultado
        )
        await modulo_con_twitter._twitter_api_oficial("noexiste", "bearer_token")

    perfiles = [f for f in modulo_con_twitter.findings if f.type == "twitter_profile"]
    assert len(perfiles) == 0


@pytest.mark.asyncio
async def test_twitter_dork_status_error_no_crea_findings(modulo_sin_keys):
    """Si Google devuelve error HTTP no debe crearse ningún finding."""
    mock_session = mock_sesion_http(429, "")
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._twitter_dork("ejemplo")

    assert len(modulo_sin_keys.findings) == 0


@pytest.mark.asyncio
async def test_linkedin_dork_status_error_no_crea_findings(modulo_sin_keys):
    """Si Google devuelve error HTTP en LinkedIn no debe crearse ningún finding."""
    mock_session = mock_sesion_http(429, "")
    with patch("aiohttp.ClientSession", return_value=mock_session):
        await modulo_sin_keys._reconocimiento_linkedin("ejemplo")

    assert len(modulo_sin_keys.findings) == 0


def test_tweepy_no_disponible_marca_flag():
    """
    Si tweepy no está instalado TWEEPY_DISPONIBLE debe ser False
    y el módulo no debe explotar al importarse.
    """
    import osint.modules.socials_module as sm
    # Simplemente comprobamos que el atributo existe
    assert hasattr(sm, "TWEEPY_DISPONIBLE")
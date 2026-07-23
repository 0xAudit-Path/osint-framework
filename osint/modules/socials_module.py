import asyncio
import re
from typing import Optional

import aiohttp

try:
    import tweepy
    TWEEPY_DISPONIBLE = True
except ImportError:
    TWEEPY_DISPONIBLE = False

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule


class SocialsModule(BaseModule):
    """
    Módulo de reconocimiento en redes sociales y repositorios públicos.

    Recopila información pública de tres fuentes sin necesidad de
    autenticación en la mayoría de casos:

    1. GitHub API — repositorios públicos de la organización, lenguajes
       usados, descripción, topics y fecha de último commit. Detecta
       además repositorios con nombres sospechosos que podrían contener
       información sensible como backups, configs o credenciales.
       Requiere token de GitHub para evitar el límite de 60 req/hora
       del tier sin autenticación (con token: 5000 req/hora).

    2. Twitter/X — comprueba si existe perfil público de la organización
       y extrae información básica disponible sin autenticación mediante
       la API pública no oficial. Sin autenticación obtenemos datos
       limitados pero útiles para el reconocimiento inicial.

    3. LinkedIn — comprueba existencia de página de empresa y extrae
       información pública disponible sin autenticación: sector,
       tamaño de empresa y ubicación mediante scraping ligero.

    Todas las fuentes son pasivas: no interactuamos con sistemas
    del objetivo, solo consultamos información públicamente disponible.
    """

    name = "socials"
    description = "Reconocimiento en GitHub, Twitter/X y LinkedIn"

    # URLs de las APIs y perfiles públicos
    GITHUB_ORG_URL   = "https://api.github.com/orgs/{org}"
    GITHUB_REPOS_URL = "https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated"
    GITHUB_USER_URL  = "https://api.github.com/users/{user}"
    TWITTER_URL      = "https://twitter.com/{handle}"
    LINKEDIN_URL     = "https://www.linkedin.com/company/{company}"

    # Dorks para busqueda pasiva en LinkedIn y Twitter (no depende del HTML de la web)
    DORKS_LINKEDIN = 'site:linkedin.com/company "{org}"'
    DORKS_TWITTER  = 'site:twitter.com "{org}"'
    GOOGLE_SEARCH_URL = "https://www.google.com/search?q={query}"

    # Palabras clave en nombres de repositorios que sugieren contenido sensible
    REPOS_SOSPECHOSOS = [
        "backup", "secret", "private", "password", "credential", "config",
        "dotfiles", "env", "key", "token", "api", "internal", "prod",
        "production", "staging", "deploy", "infrastructure", "infra",
    ]

    def is_available(self) -> bool:
        """
        Siempre disponible. Sin token de GitHub funciona con límite
        reducido (60 req/hora). Twitter y LinkedIn no requieren key.
        """
        return True

    async def run(self, target: str) -> list[Finding]:
        """
        Lanza en paralelo el reconocimiento en las tres plataformas.
        Deriva el nombre de organización del dominio objetivo.
        """
        # Extraemos el nombre de organización del dominio
        # ejemplo.com → ejemplo
        org = self._extraer_nombre_org(target)

        await asyncio.gather(
            self._reconocimiento_github(org, target),
            self._reconocimiento_twitter(org),
            self._reconocimiento_linkedin(org),
            return_exceptions=True,
        )

        return self.findings

    def _extraer_nombre_org(self, target: str) -> str:
        """
        Extrae el nombre de la organización del dominio objetivo.
        Es una aproximación heurística: ejemplo.com → ejemplo.
        El usuario puede sobreescribir esto en la config en el futuro.
        """
        partes = target.lower().strip().split(".")
        return partes[0] if partes else target.lower()

    def _construir_headers_github(self) -> dict:
        """
        Construye los headers para la API de GitHub.
        Con token: 5000 req/hora. Sin token: 60 req/hora.
        Ambos son suficientes para un escaneo OSINT normal.
        """
        headers = {
            "Accept":     "application/vnd.github.v3+json",
            "User-Agent": "osint-framework-tfg",
        }
        token = self.config.get_api_key("github")
        if token:
            headers["Authorization"] = f"token {token}"
        return headers

    async def _reconocimiento_github(self, org: str, dominio: str):
        """
        Reconocimiento en GitHub en dos pasos:
        1. Intenta buscar como organización (/orgs/{org})
        2. Si no existe como org, intenta como usuario (/users/{org})

        Muchas empresas tienen cuenta de usuario en lugar de organización
        en GitHub, especialmente las más pequeñas.
        """
        headers = self._construir_headers_github()
        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Intento 1: como organización
            encontrado = await self._buscar_github_org(session, headers, org, dominio)

            # Intento 2: como usuario si no existe como org
            if not encontrado:
                await self._buscar_github_usuario(session, headers, org, dominio)

    async def _buscar_github_org(
        self,
        session: aiohttp.ClientSession,
        headers: dict,
        org: str,
        dominio: str,
    ) -> bool:
        """
        Busca la organización en GitHub y extrae su información pública.
        Devuelve True si la encontró, False si no existe.
        """
        try:
            url = self.GITHUB_ORG_URL.format(org=org)
            async with session.get(url, headers=headers) as r:
                if r.status == 404:
                    return False
                if r.status == 403:
                    # Rate limit alcanzado sin token
                    self._registrar_rate_limit_github()
                    return False
                if r.status != 200:
                    return False
                data = await r.json()

            self._procesar_perfil_github(data, "organization", dominio)

            # Consultamos los repositorios públicos de la organización
            await self._obtener_repos_github(session, headers, org, dominio)
            return True

        except Exception:
            return False

    async def _buscar_github_usuario(
        self,
        session: aiohttp.ClientSession,
        headers: dict,
        org: str,
        dominio: str,
    ):
        """
        Busca como cuenta de usuario si no existe como organización.
        """
        try:
            url = self.GITHUB_USER_URL.format(user=org)
            async with session.get(url, headers=headers) as r:
                if r.status != 200:
                    return
                data = await r.json()

            self._procesar_perfil_github(data, "user", dominio)
            await self._obtener_repos_github(session, headers, org, dominio)

        except Exception:
            pass

    def _procesar_perfil_github(self, data: dict, tipo: str, dominio: str):
        """
        Extrae la información relevante del perfil de GitHub.
        Registra el perfil como INFO y eleva a LOW si tiene
        datos que confirman la relación con el dominio objetivo.
        """
        nombre    = data.get("name", "") or ""
        login     = data.get("login", "") or ""
        bio       = data.get("bio", "") or ""
        blog      = data.get("blog", "") or ""
        email     = data.get("email", "") or ""
        repos     = data.get("public_repos", 0)
        seguidores = data.get("followers", 0)
        ubicacion  = data.get("location", "") or ""

        # Si el blog o email confirman el dominio, es más relevante
        dominio_raiz = dominio.split(".")[0]
        confirmado = (
            dominio_raiz in blog.lower() or
            dominio_raiz in email.lower() or
            dominio_raiz in nombre.lower()
        )

        self.add_finding(
            type="github_profile",
            value=f"https://github.com/{login}",
            severity=Severity.LOW if confirmado else Severity.INFO,
            source="github",
            metadata={
                "login":        login,
                "name":         nombre,
                "type":         tipo,
                "bio":          bio,
                "blog":         blog,
                "email":        email,
                "public_repos": repos,
                "followers":    seguidores,
                "location":     ubicacion,
                "domain":       dominio,
                "confirmed":    confirmado,
            },
        )

    async def _obtener_repos_github(
        self,
        session: aiohttp.ClientSession,
        headers: dict,
        org: str,
        dominio: str,
    ):
        """
        Obtiene los repositorios públicos y los analiza.
        Detecta repositorios con nombres sospechosos que podrían
        contener información sensible expuesta accidentalmente.
        """
        try:
            url = self.GITHUB_REPOS_URL.format(org=org)
            async with session.get(url, headers=headers) as r:
                if r.status != 200:
                    return
                repos = await r.json()

            if not isinstance(repos, list):
                return

            for repo in repos:
                self._procesar_repo_github(repo, dominio)

        except Exception:
            pass

    def _procesar_repo_github(self, repo: dict, dominio: str):
        """
        Analiza un repositorio público individual.
        La mayoría son informativos, pero algunos merecen atención:
        - Repos con nombres sospechosos (backup, config, credentials...)
        - Repos con descripción que menciona infraestructura interna
        - Repos con muchas estrellas (tecnología usada públicamente conocida)
        """
        nombre      = repo.get("name", "") or ""
        descripcion = repo.get("description", "") or ""
        lenguaje    = repo.get("language", "") or ""
        estrellas   = repo.get("stargazers_count", 0)
        fork        = repo.get("fork", False)
        url         = repo.get("html_url", "") or ""
        actualizado = repo.get("updated_at", "") or ""
        archivado   = repo.get("archived", False)

        # Los forks no son propios del objetivo, los ignoramos
        if fork:
            return

        nombre_lower = nombre.lower()
        desc_lower   = descripcion.lower()

        # Detectamos nombres de repositorio sospechosos
        es_sospechoso = any(
            kw in nombre_lower or kw in desc_lower
            for kw in self.REPOS_SOSPECHOSOS
        )

        severidad = Severity.MEDIUM if es_sospechoso else Severity.INFO

        self.add_finding(
            type="github_repo",
            value=url,
            severity=severidad,
            source="github",
            metadata={
                "name":        nombre,
                "description": descripcion,
                "language":    lenguaje,
                "stars":       estrellas,
                "archived":    archivado,
                "updated_at":  actualizado,
                "suspicious":  es_sospechoso,
                "domain":      dominio,
            },
        )

        # Si el lenguaje revela tecnología usada, lo registramos también
        if lenguaje and not fork:
            self.add_finding(
                type="technology",
                value=lenguaje,
                severity=Severity.INFO,
                source="github/repos",
                metadata={"domain": dominio, "repo": nombre},
            )

    def _registrar_rate_limit_github(self):
        """
        Registra un aviso cuando se alcanza el rate limit de GitHub.
        Sucede cuando no hay token configurado y se han hecho
        más de 60 peticiones en una hora desde la misma IP.
        """
        self.add_finding(
            type="github_rate_limited",
            value="api.github.com",
            severity=Severity.INFO,
            source="github",
            metadata={
                "message": "Rate limit de GitHub alcanzado (60 req/hora sin token). "
                           "Configura un token en apis.github de config.yaml "
                           "para aumentar el límite a 5000 req/hora.",
            },
        )

    async def _reconocimiento_twitter(self, org: str):
        """
        Reconocimiento en Twitter/X usando dos estrategias:

        1. API oficial de Twitter v2 via tweepy si hay bearer token
        configurado en apis.twitter de config.yaml.
        Proporciona datos estructurados: bio, seguidores, tweets recientes.

        2. Google Dork pasivo como fallback sin autenticación.
        Busca 'site:twitter.com "{org}"' para encontrar perfiles
        públicos sin interactuar directamente con Twitter.
        """
        bearer_token = self.config.get_api_key("twitter")

        if bearer_token:
            await self._twitter_api_oficial(org, bearer_token)
        else:
            await self._twitter_dork(org)

    async def _twitter_api_oficial(self, org: str, bearer_token: str):
        """
        Busca el perfil de Twitter usando la API v2 oficial via tweepy.
        Requiere bearer token gratuito obtenible en developer.twitter.com.
        Proporciona datos verificados: nombre, bio, seguidores y ubicación.
        """

        # Si tweepy no está instalado el módulo degrada a dorks automáticamente.
        if not TWEEPY_DISPONIBLE:
            await self._twitter_dork(org)
            return

        try:
            client = tweepy.AsyncClient(bearer_token=bearer_token)

            # Buscamos el usuario por nombre de usuario
            usuario = await client.get_user(
                username=org,
                user_fields=["description", "public_metrics", "location", "url"],
            )

            if not usuario.data:
                return

            data     = usuario.data
            metricas = data.public_metrics or {}

            self.add_finding(
                type="twitter_profile",
                value=f"https://twitter.com/{data.username}",
                severity=Severity.INFO,
                source="twitter/api",
                metadata={
                    "username":   data.username,
                    "name":       data.name,
                    "bio":        data.description or "",
                    "followers":  metricas.get("followers_count", 0),
                    "following":  metricas.get("following_count", 0),
                    "tweets":     metricas.get("tweet_count", 0),
                    "location":   data.location or "",
                    "url":        data.url or "",
                    "via":        "api",
                },
            )

        except Exception:
            # Si la API falla por cualquier motivo usamos el dork como fallback
            await self._twitter_dork(org)


    async def _twitter_dork(self, org: str):
        """
        Búsqueda pasiva de perfil Twitter mediante Google Dork.
        No interactúa con Twitter directamente — consulta Google
        buscando páginas de twitter.com que mencionen la organización.
        Es la técnica estándar en OSINT cuando no hay credenciales.
        """
        query   = self.DORKS_TWITTER.format(org=org)
        url     = self.GOOGLE_SEARCH_URL.format(query=query.replace(" ", "+"))
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        timeout = aiohttp.ClientTimeout(total=10)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as r:
                    if r.status != 200:
                        return
                    html = await r.text()

            # Extraemos URLs de Twitter de los resultados de Google
            # El patrón busca twitter.com/{usuario} en el HTML devuelto
            patron  = r'twitter\.com/([A-Za-z0-9_]{1,50})(?:["\'/]|&amp;)'
            matches = set(re.findall(patron, html))

            # Filtramos resultados genéricos de Twitter que no son perfiles
            excluir = {
                "intent", "search", "share", "home", "explore",
                "notifications", "messages", "i", "hashtag",
            }

            for handle in matches:
                if handle.lower() in excluir:
                    continue
                self.add_finding(
                    type="twitter_profile",
                    value=f"https://twitter.com/{handle}",
                    severity=Severity.INFO,
                    source="twitter/dork",
                    metadata={
                        "handle": handle,
                        "dork":   query,
                        "via":    "dork",
                    },
                )

        except Exception:
            pass

    async def _comprobar_perfil_twitter(
        self,
        session: aiohttp.ClientSession,
        headers: dict,
        handle: str,
    ):
        """
        Comprueba si un handle concreto existe en Twitter/X.
        Solo verificamos existencia, no extraemos contenido.
        """
        try:
            url = self.TWITTER_URL.format(handle=handle)
            async with session.get(
                url, headers=headers, allow_redirects=True
            ) as r:
                if r.status == 200:
                    self.add_finding(
                        type="twitter_profile",
                        value=url,
                        severity=Severity.INFO,
                        source="twitter",
                        metadata={"handle": handle},
                    )
        except Exception:
            pass

    async def _reconocimiento_linkedin(self, org: str):
        """
        Reconocimiento en LinkedIn mediante Google Dork pasivo.

        LinkedIn bloquea activamente el scraping y su API oficial
        requiere aprobación de empresa. La alternativa estándar en
        OSINT es buscar 'site:linkedin.com/company "{org}"' en Google,
        que devuelve páginas de empresa indexadas públicamente sin
        interactuar con LinkedIn directamente.

        Esta es la misma técnica que usa theHarvester para LinkedIn
        y está documentada en el framework MITRE ATT&CK (T1593.001).
        """
        query   = self.DORKS_LINKEDIN.format(org=org)
        url     = self.GOOGLE_SEARCH_URL.format(query=query.replace(" ", "+"))
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        timeout = aiohttp.ClientTimeout(total=10)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as r:
                    if r.status != 200:
                        return
                    html = await r.text()

            # Extraemos URLs de LinkedIn de los resultados de Google
            patron  = r'linkedin\.com/company/([A-Za-z0-9_-]{1,100})(?:["\'/]|&amp;)'
            matches = set(re.findall(patron, html))

            for company_slug in matches:
                self.add_finding(
                    type="linkedin_profile",
                    value=f"https://linkedin.com/company/{company_slug}",
                    severity=Severity.INFO,
                    source="linkedin/dork",
                    metadata={
                        "company_slug": company_slug,
                        "dork":         query,
                        "via":          "dork",
                    },
                )

        except Exception:
            pass

    async def _comprobar_perfil_linkedin(
        self,
        session: aiohttp.ClientSession,
        headers: dict,
        nombre: str,
    ):
        """
        Comprueba si una página de empresa existe en LinkedIn.
        """
        try:
            url = self.LINKEDIN_URL.format(company=nombre)
            async with session.get(
                url, headers=headers, allow_redirects=True
            ) as r:
                # LinkedIn devuelve 200 para páginas existentes
                # y redirige a /404 para las que no existen
                url_final = str(r.url)
                if r.status == 200 and "/404" not in url_final:
                    self.add_finding(
                        type="linkedin_profile",
                        value=url,
                        severity=Severity.INFO,
                        source="linkedin",
                        metadata={"company": nombre},
                    )
        except Exception:
            pass
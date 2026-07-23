import asyncio
from typing import Optional

import aiohttp

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule


class LeaksModule(BaseModule):
    """
    Módulo de detección de filtraciones de credenciales.

    Usa la API de HaveIBeenPwned (HIBP) para comprobar si el dominio
    objetivo aparece en brechas de seguridad conocidas. 
    HIBP es la base de datos de filtraciones más completa públicamente 
    disponible, con más de 12 mil millones de cuentas comprometidas indexadas.

    En caso de no disponer de una API key de HIBP, el módulo consulta
    la alternativa gratuita breach.directory, que tiene un límite de
    10 búsquedas diarias, suficiente para pruebas y demos.

    El módulo busca:
    - Brechas de seguridad donde aparece el dominio del objetivo,
      lo que implica que correos corporativos fueron comprometidos.
    - Para cada brecha: nombre, fecha, número de cuentas afectadas
      y tipos de datos expuestos (contraseñas, emails, teléfonos, etc.).

    La API de HIBP requiere una key obtenible en:
    https://haveibeenpwned.com/API/Key

    """

    name = "leaks"
    description = "Detección de filtraciones de credenciales corporativas via HaveIBeenPwned"

    # URL base de la API v3 de HIBP
    HIBP_DOMAIN_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breach/{name}"

    # URL de breach.directory — gratuito sin API key, 10 búsquedas/día
    BREACH_DIRECTORY_URL = "https://breachdirectory.org/api?func=auto&term={domain}"

    # Tipos de datos en una filtración que implican mayor riesgo
    DATOS_CRITICOS = {
        "Passwords",
        "Password hints",
        "Security questions and answers",
        "Auth tokens",
        "Partial credit card data",
        "Credit cards",
        "Bank account numbers",
    }

    def requires_api_key(self) -> Optional[str]:
        return "hibp"

    def is_available(self) -> bool:
        """
        Siempre disponible aunque no haya key de HIBP,
        porque breach.directory funciona sin autenticación.
        """
        return True

    async def run(self, target: str) -> list[Finding]:
        """
        Consulta filtraciones usando el proveedor disponible.
        Prioridad: HIBP si hay key configurada, breach.directory si no.
        """
        dominio = self._extraer_dominio_raiz(target)

        key = self.config.get_api_key("hibp")
        if key:
            # HIBP tiene datos más completos y verificados
            await self._consultar_brechas_dominio(dominio)
        else:
            # breach.directory como alternativa gratuita sin key
            await self._consultar_breach_directory(dominio)

        return self.findings

    def _extraer_dominio_raiz(self, target: str) -> str:
        """
        Extrae el dominio raíz de un target que puede ser un FQDN.
        La API de HIBP trabaja a nivel de dominio raíz, no de subdominio.
        Ejemplo: sub.ejemplo.com → ejemplo.com
        """
        partes = target.lower().strip().split(".")
        if len(partes) >= 2:
            return ".".join(partes[-2:])
        return target.lower().strip()

    async def _consultar_brechas_dominio(self, dominio: str):
        """
        Consulta el endpoint /breacheddomain/{domain} de HIBP.

        Este endpoint devuelve un diccionario donde cada clave es un
        alias de email del dominio (la parte antes de la @) y el valor
        es una lista de nombres de brechas en las que aparece ese alias.

        Ejemplo de respuesta:
        {
          "admin": ["Adobe", "LinkedIn"],
          "info":  ["RockYou2024"],
          "john.doe": ["Adobe"]
        }

        Esto nos permite saber cuántas cuentas únicas del dominio
        están comprometidas y en qué brechas aparecen.
        """
        key = self.config.get_api_key("hibp")
        if not key:
            return

        url = self.HIBP_DOMAIN_URL.format(domain=dominio)
        headers = {
            "hibp-api-key": key,
            "User-Agent":   "osint-framework-tfg",
        }
        timeout = aiohttp.ClientTimeout(total=15)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as r:
                    if r.status == 404:
                        # 404 significa que el dominio no aparece en ninguna brecha
                        # Es una buena noticia, no un error
                        self.add_finding(
                            type="no_leaks_found",
                            value=dominio,
                            severity=Severity.INFO,
                            source="hibp",
                            metadata={"domain": dominio},
                        )
                        return
                    if r.status == 401:
                        # API key inválida o no proporcionada
                        return
                    if r.status == 429:
                        # Rate limit superado — esperamos y reintentamos una vez
                        await asyncio.sleep(2.0)
                        async with session.get(url, headers=headers) as r2:
                            if r2.status != 200:
                                return
                            data = await r2.json()
                    elif r.status != 200:
                        return
                    else:
                        data = await r.json()

            await self._procesar_respuesta_dominio(data, dominio)

        except Exception:
            pass

    async def _procesar_respuesta_dominio(self, data: dict, dominio: str):
        """
        Procesa la respuesta del endpoint de dominio de HIBP.

        Calcula métricas agregadas: cuántas cuentas únicas están
        comprometidas y en qué brechas aparecen. Luego registra
        un finding por cada brecha encontrada con sus detalles.
        """
        if not data:
            return

        # Contamos cuentas únicas comprometidas
        aliases_comprometidos = list(data.keys())
        total_cuentas = len(aliases_comprometidos)

        # Recopilamos todas las brechas únicas donde aparece el dominio
        brechas_unicas: set[str] = set()
        for brechas in data.values():
            for brecha in brechas:
                brechas_unicas.add(brecha)

        # Severidad según el número de cuentas comprometidas
        if total_cuentas >= 10:
            severidad_resumen = Severity.HIGH
        elif total_cuentas >= 3:
            severidad_resumen = Severity.MEDIUM
        else:
            severidad_resumen = Severity.LOW

        # Finding de resumen con el panorama general
        self.add_finding(
            type="domain_breach_summary",
            value=dominio,
            severity=severidad_resumen,
            source="hibp",
            metadata={
                "domain":               dominio,
                "compromised_accounts": total_cuentas,
                "unique_breaches":      len(brechas_unicas),
                "aliases":              aliases_comprometidos[:20],
                "breaches":             list(brechas_unicas),
            },
        )

        # Finding individual por cada alias comprometido
        # Limitado a 50 para no saturar el DataStore en dominios muy expuestos
        for alias in aliases_comprometidos[:50]:
            brechas_del_alias = data[alias]
            self.add_finding(
                type="compromised_email",
                value=f"{alias}@{dominio}",
                severity=Severity.HIGH,
                source="hibp",
                metadata={
                    "alias":   alias,
                    "domain":  dominio,
                    "breaches": brechas_del_alias,
                    "breach_count": len(brechas_del_alias),
                },
            )

        # Consulta los detalles de cada brecha en paralelo
        # para obtener fechas, número de afectados y tipos de datos expuestos
        await asyncio.gather(
            *[self._consultar_detalle_brecha(nombre, dominio)
              for nombre in list(brechas_unicas)[:20]],
            return_exceptions=True,
        )

    async def _consultar_detalle_brecha(self, nombre_brecha: str, dominio: str):
        """
        Consulta los detalles de una brecha concreta.

        El endpoint /breach/{name} devuelve metadatos completos:
        fecha de la brecha, número total de cuentas afectadas globalmente,
        tipos de datos expuestos y si la brecha está verificada.

        Esto permite clasificar las brechas por gravedad real:
        una brecha que expuso contraseñas en texto plano es mucho más
        grave que una que solo expuso direcciones de email.
        """
        key = self.config.get_api_key("hibp")
        if not key:
            return

        url = self.HIBP_BREACH_URL.format(name=nombre_brecha)
        headers = {
            "hibp-api-key": key,
            "User-Agent":   "osint-framework-tfg",
        }
        timeout = aiohttp.ClientTimeout(total=10)

        try:
            # Respetamos el rate limit de HIBP: 1 petición cada 1500ms
            await asyncio.sleep(1.5)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as r:
                    if r.status != 200:
                        return
                    data = await r.json()

            self._procesar_detalle_brecha(data, dominio)

        except Exception:
            pass

    def _procesar_detalle_brecha(self, data: dict, dominio: str):
        """
        Procesa los detalles de una brecha y determina su severidad.

        La severidad depende de qué tipos de datos fueron expuestos.
        Una brecha con contraseñas es HIGH independientemente de su tamaño.
        Una brecha solo con emails es LOW porque no permite acceso directo.
        """
        nombre       = data.get("Name", "")
        titulo       = data.get("Title", nombre)
        fecha        = data.get("BreachDate", "")
        total_pwned  = data.get("PwnCount", 0)
        tipos_datos  = data.get("DataClasses", [])
        verificada   = data.get("IsVerified", False)
        es_spam_list = data.get("IsSpamList", False)

        # Las spam lists son menos relevantes en OSINT corporativo
        if es_spam_list:
            return

        # Determinamos severidad según los datos expuestos
        datos_expuestos = set(tipos_datos)
        tiene_datos_criticos = bool(datos_expuestos & self.DATOS_CRITICOS)

        if tiene_datos_criticos and verificada:
            severidad = Severity.HIGH
        elif tiene_datos_criticos:
            severidad = Severity.MEDIUM
        elif verificada:
            severidad = Severity.LOW
        else:
            severidad = Severity.INFO

        self.add_finding(
            type="breach_detail",
            value=nombre,
            severity=severidad,
            source="hibp/breach",
            metadata={
                "domain":          dominio,
                "title":           titulo,
                "breach_date":     fecha,
                "total_pwned":     total_pwned,
                "data_classes":    tipos_datos,
                "has_passwords":   "Passwords" in datos_expuestos,
                "is_verified":     verificada,
            },
        )

    async def _consultar_breach_directory(self, dominio: str):
        """
        Consulta breach.directory como alternativa gratuita a HIBP.

        breach.directory es una base de datos pública de filtraciones
        que no requiere API key ni registro. Tiene un límite de
        10 búsquedas diarias en el tier gratuito.

        La respuesta incluye si el dominio aparece en filtraciones
        conocidas y una muestra de los registros encontrados.
        """
        url = self.BREACH_DIRECTORY_URL.format(domain=dominio)
        headers = {"User-Agent": "osint-framework-tfg"}
        timeout = aiohttp.ClientTimeout(total=15)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as r:
                    if r.status == 429:
                        # Límite diario alcanzado
                        self.add_finding(
                            type="leaks_rate_limited",
                            value=dominio,
                            severity=Severity.INFO,
                            source="breach.directory",
                            metadata={
                                "message": "Límite diario de breach.directory alcanzado (10/día). "
                                        "Configura una key de HIBP para sin límites.",
                            },
                        )
                        return
                    if r.status != 200:
                        return
                    data = await r.json()

            self._procesar_breach_directory(data, dominio)

        except Exception:
            pass

    def _procesar_breach_directory(self, data: dict, dominio: str):
        """
        Procesa la respuesta de breach.directory.

        La API devuelve un campo found indicando si hay resultados
        y una lista result con los registros encontrados. Cada registro
        incluye el email o usuario comprometido y la fuente de la filtración.
        """
        encontrado = data.get("found", False)

        if not encontrado:
            self.add_finding(
                type="no_leaks_found",
                value=dominio,
                severity=Severity.INFO,
                source="breach.directory",
                metadata={"domain": dominio},
            )
            return

        resultados = data.get("result", [])
        total = len(resultados)

        # Severidad según volumen de registros encontrados
        if total >= 10:
            severidad = Severity.HIGH
        elif total >= 3:
            severidad = Severity.MEDIUM
        else:
            severidad = Severity.LOW

        self.add_finding(
            type="domain_breach_summary",
            value=dominio,
            severity=severidad,
            source="breach.directory",
            metadata={
                "domain":               dominio,
                "compromised_accounts": total,
                "sample":               resultados[:10],
            },
        )

        # Finding individual por cada registro comprometido
        for registro in resultados[:50]:
            email = registro.get("email", registro.get("username", ""))
            fuente = registro.get("sources", [])
            if email:
                self.add_finding(
                    type="compromised_email",
                    value=email,
                    severity=Severity.HIGH,
                    source="breach.directory",
                    metadata={
                        "domain":  dominio,
                        "sources": fuente,
                    },
                )
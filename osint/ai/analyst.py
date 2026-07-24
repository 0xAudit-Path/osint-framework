import asyncio
import json
from dataclasses import dataclass, field

import structlog

from osint.ai.providers import BaseProvider
from osint.core.datastore import DataStore, Severity

log = structlog.get_logger()

# Prompt del sistema que define el rol del modelo para toda la sesión.
# Cuanto más contexto de seguridad tenga, menos "alucinaciones" y más respuestas 
# técnicas precisas producirá.
SYSTEM_PROMPT = """Eres un analista experto en ciberseguridad ofensiva y OSINT.
Has realizado un reconocimiento pasivo sobre un objetivo usando fuentes públicas.
Tu función es analizar los hallazgos recopilados, identificar riesgos reales,
correlacionar evidencias entre distintas fuentes y comunicar los resultados
con precisión técnica.

Reglas estrictas:
- Nunca inventes hallazgos que no estén en los datos proporcionados
- Si algo no está claro en los datos, indícalo explícitamente
- Usa terminología técnica de seguridad apropiada
- Prioriza por impacto real, no por cantidad de hallazgos
- Responde siempre en español"""


@dataclass
class AIInsight:
    """
    Resultado de un análisis generado por la IA.
    Cada tipo de análisis produce un AIInsight distinto que se
    incluye en el informe final junto a los hallazgos del escaneo.
    """
    type:      str            # executive_summary | correlation | 
                              # dork_suggestion | risk_score
    title:     str            # título legible para el informe
    content:   str            # texto generado por el modelo
    confidence: float         # 0.0 – 1.0, indica la fiabilidad estimada
    severity:  str | None = None
    related_finding_types: list[str] = field(default_factory=list)


class AIAnalyst:
    """
    Capa de análisis inteligente post-escaneo.

    Procesa el DataStore completo tras la ejecución de todos los módulos
    y genera insights que ningún módulo individual puede producir, ya que
    requieren visión cruzada de todos los hallazgos simultáneamente.

    Los cuatro análisis que genera en paralelo son:
    1. Resumen ejecutivo — texto en lenguaje natural
    2. Correlaciones — relaciones entre hallazgos de distintos módulos
    3. Google Dorks — consultas personalizadas basadas en tecnología detectada
    4. Risk score — puntuación 0-100 con justificación
    """

    def __init__(self, provider: BaseProvider):
        self.provider = provider
        self._context_cache: str | None = None

    async def analizar(self, datastore: DataStore, target: str) -> list[AIInsight]:
        """
        Ejecuta los cuatro análisis en paralelo sobre el DataStore.
        Construye el contexto una sola vez y lo reutiliza en todos.
        """
        log.info("ai.analisis.inicio", target=target, findings=len(datastore))

        # Construye el contexto una vez porque es costoso y todos los 
        # análisis lo necesitan
        self._context_cache = self._construir_contexto(datastore, target)

        resultados = await asyncio.gather(
            self._resumen_ejecutivo(target),
            self._encontrar_correlaciones(datastore),
            self._generar_dorks(datastore, target),
            self._calcular_risk_score(datastore),
            return_exceptions=True,
        )

        insights = []
        for r in resultados:
            if isinstance(r, AIInsight):
                insights.append(r)
            elif isinstance(r, Exception):
                log.warning("ai.analisis.tarea_fallida", error=str(r))

        log.info("ai.analisis.completado", insights=len(insights))
        return insights

    async def _resumen_ejecutivo(self, target: str) -> AIInsight:
        """
        Genera un resumen ejecutivo de máximo 250 palabras.
        Temperatura baja (0.2) para respuestas deterministas y técnicas.
        """
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""Objetivo del reconocimiento: {target}

Hallazgos recopilados:
{self._context_cache}

Redacta un resumen ejecutivo conciso (máximo 250 palabras) para un responsable técnico.
Estructura tu respuesta así:
1. Superficie de ataque identificada (2-3 frases)
2. Los 3 hallazgos más críticos con su riesgo real
3. Recomendaciones de acción inmediata

Sé directo y técnico. No repitas los datos crudos, interprètalos.""",
            },
        ]

        response = await self.provider.complete(
            messages=messages,
            temperature=0.2,
            max_tokens=600,
        )

        return AIInsight(
            type="executive_summary",
            title="Resumen Ejecutivo",
            content=response.content,
            confidence=0.88,
            severity="high",
        )

    async def _encontrar_correlaciones(self, datastore: DataStore) -> AIInsight:
        """
        Detecta relaciones entre hallazgos de módulos distintos.

        Es el análisis más valioso porque identifica patrones que
        un analista humano podría pasar por alto al revisar los
        hallazgos de cada módulo por separado.

        Ejemplo real: subdominio dev. con certificado expirado +
        puerto 8080 abierto + credenciales filtradas del dominio
        = entorno de desarrollo expuesto accidentalmente.
        """
        # Extraemos datos estructurados por tipo para el prompt
        estructurado = {
            "subdominios":             
                [f.value for f in datastore.by_type("subdomain")][:20],
            "puertos_abiertos":        
                [f.value for f in datastore.by_type("open_port")][:20],
            "credenciales_filtradas":  
                [f.value for f in datastore.by_type("compromised_email")][:10],
            "certificados_expirados":  
                [f.value for f in datastore.by_type("expired_certificate")][:10],
            "tecnologias_detectadas":  
                [f.value for f in datastore.by_type("technology")][:15],
            "paneles_admin_expuestos": 
                [f.value for f in datastore.by_type("exposed_admin_panel")][:10],
            "cves_detectados":         
                [f.value for f in datastore.by_type("cve")][:10],
        }

        # Filtramos secciones vacías para no desperdiciar tokens de contexto
        no_vacios = {k: v for k, v in estructurado.items() if v}

        if len(no_vacios) < 2:
            return AIInsight(
                type="correlation",
                title="Correlaciones entre Módulos",
                content="Datos insuficientes de múltiples fuentes para establecer " \
                        "correlaciones significativas.",
                confidence=0.3,
            )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""Analiza estos hallazgos OSINT de múltiples módulos 
                               y detecta correlaciones de seguridad.

Datos recopilados:
{json.dumps(no_vacios, ensure_ascii=False, indent=2)}

Identifica máximo 3 correlaciones relevantes. Para cada una indica:
- Qué hallazgos de distintos módulos se relacionan
- Qué escenario de ataque o riesgo representa
- Severidad: ALTA / MEDIA / BAJA
- Acción recomendada

Solo incluye correlaciones que aporten valor real. 
Si no hay correlaciones claras, indícalo.""",
            },
        ]

        response = await self.provider.complete(
            messages=messages,
            temperature=0.2,
            max_tokens=700,
        )

        return AIInsight(
            type="correlation",
            title="Correlaciones entre Módulos",
            content=response.content,
            confidence=0.78,
            related_finding_types=list(no_vacios.keys()),
        )

    async def _generar_dorks(self, datastore: DataStore, target: str) -> AIInsight:
        """
        Genera Google Dorks personalizados basados en la tecnología detectada.

        Mucho más efectivos que un diccionario estático porque se adaptan
        a lo que realmente usa el objetivo: CMS detectado, versiones
        concretas de software, subdominios descubiertos, etc.
        """
        tecnologias = [
            f.value for f in datastore
            if f.type in ("technology", "http_server_header", "service_banner")
        ]
        subdominios = [f.value for f in datastore.by_type("subdomain")][:10]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""Objetivo: {target}
Subdominios descubiertos: {subdominios if subdominios else "ninguno"}
Tecnologías detectadas: {tecnologias[:15] if tecnologias else "no identificadas"}

Genera exactamente 6 Google Dorks para este objetivo específico.
Para cada dork indica:
- La query exacta lista para copiar en Google (usando site:{target} como base)
- En una línea: qué tipo de información expuesta busca

Prioriza dorks que busquen:
1. Ficheros de configuración o credenciales (.env, config, backup)
2. Paneles de administración o login
3. Documentación técnica indexada accidentalmente
4. Páginas de error que revelen información del sistema
5. Ficheros sensibles (logs, dumps, backups)
6. Información de empleados o estructura interna""",
            },
        ]

        response = await self.provider.complete(
            messages=messages,
            temperature=0.4,
            max_tokens=600,
        )

        return AIInsight(
            type="dork_suggestion",
            title="Google Dorks Personalizados",
            content=response.content,
            confidence=0.72,
        )

    async def _calcular_risk_score(self, datastore: DataStore) -> AIInsight:
        """
        Calcula un score de riesgo global de 0 a 100.

        Pedimos JSON estructurado con temperatura muy baja (0.1)
        para maximizar la consistencia entre ejecuciones.
        El código incluye parsing robusto ante respuestas mal formateadas.
        """
        resumen  = datastore.summary()
        high     = [f.to_dict() for f in datastore.by_severity(Severity.HIGH)][:8]
        medium   = [f.to_dict() for f in datastore.by_severity(Severity.MEDIUM)][:8]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""Evalúa el nivel de riesgo de exposición basándote 
                               en estos hallazgos OSINT.

Resumen:
{json.dumps(resumen, indent=2)}

Hallazgos HIGH:
{json.dumps(high, indent=2, ensure_ascii=False)}

Hallazgos MEDIUM:
{json.dumps(medium, indent=2, ensure_ascii=False)}

Responde ÚNICAMENTE con un objeto JSON con esta estructura exacta, sin texto adicional:
{{
  "score": <número entero 0-100>,
  "nivel": "<CRÍTICO|ALTO|MEDIO|BAJO>",
  "justificacion": "<2-3 frases explicando el score>",
  "factores_principales": ["<factor1>", "<factor2>", "<factor3>"]
}}""",
            },
        ]

        response = await self.provider.complete(
            messages=messages,
            temperature=0.1,
            max_tokens=300,
        )

        # Parseamos el JSON con múltiples estrategias de fallback
        content = self._parsear_risk_score(response.content)

        return AIInsight(
            type="risk_score",
            title="Score de Riesgo Global",
            content=content,
            confidence=0.82,
        )

    def _parsear_risk_score(self, texto: str) -> str:
        """
        Parsea la respuesta JSON del risk score de forma robusta.

        Los modelos a veces añaden texto antes o después del JSON,
        o lo envuelven en bloques de código markdown. Esta función
        maneja todos esos casos sin lanzar excepciones.
        """
        # Limpiamos bloques de código markdown si los hay
        raw = texto.strip()
        if "```" in raw:
            partes = raw.split("```")
            for parte in partes:
                parte = parte.strip()
                if parte.startswith("json"):
                    parte = parte[4:]
                if parte.strip().startswith("{"):
                    raw = parte.strip()
                    break

        try:
            data = json.loads(raw)
            return (
                f"**Score de riesgo: {data['score']}/100 — {data['nivel']}**\n\n"
                f"{data['justificacion']}\n\n"
                f"Factores principales:\n"
                + "\n".join(f"- {f}" for f in data.get("factores_principales", []))
            )
        except (json.JSONDecodeError, KeyError):
            # Fallback: devolvemos el texto tal cual si el JSON falla
            return texto

    def _construir_contexto(self, datastore: DataStore, target: str) -> str:
        """
        Serializa el DataStore de forma compacta para el contexto del LLM.

        El problema: un escaneo puede producir cientos de hallazgos.
        Los modelos tienen contexto limitado (~8k tokens en modelos pequeños).
        Solución: mostramos los más relevantes por severidad y truncamos el resto.

        Regla: HIGH (todos) + MEDIUM (top 15) + LOW (top 10) + INFO (top 5)
        """
        lineas = [f"Objetivo: {target}", ""]

        limites = {
            Severity.HIGH:   None,  # todos los HIGH sin límite
            Severity.MEDIUM: 15,
            Severity.LOW:    10,
            Severity.INFO:   5,
        }

        for severidad, limite in limites.items():
            findings = datastore.by_severity(severidad)
            if not findings:
                continue

            mostrados = findings[:limite] if limite else findings
            lineas.append(f"[{severidad.upper()}] ({len(findings)} total):")

            for f in mostrados:
                linea = f"  • [{f.module}] {f.type}: {f.value}"
                # Añadimos metadatos relevantes sin saturar el contexto
                meta_interesante = {
                    k: v for k, v in f.metadata.items()
                    if k in ("port", "version", "cvss", "country", 
                             "org", "breach_count")
                }
                if meta_interesante:
                    linea += f" | {meta_interesante}"
                lineas.append(linea)

            if limite and len(findings) > limite:
                lineas.append(f"  ... y {len(findings) - limite} más")
            lineas.append("")

        return "\n".join(lineas)
import os

import pytest

from osint.ai.analyst import AIAnalyst
from osint.ai.chat import InteractiveChat
from osint.ai.providers import LLMResponse, LLMStreamChunk
from osint.core.config import Config
from osint.core.orchestrator import Orchestrator
from osint.modules.dns_module import DnsModule
from osint.modules.leaks_module import LeaksModule
from osint.modules.shodan_module import ShodanModule
from osint.modules.socials_module import SocialsModule
from osint.modules.tls_module import TlsModule
from osint.modules.whois_module import WhoisModule
from osint.reports.engine import ReportEngine

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_INTEGRATION_TESTS") != "1",
    reason="La prueba requiere acceso de red: RUN_INTEGRATION_TESTS=1",
)


@pytest.mark.asyncio
async def test_pipeline_real_con_todos_los_modulos():
    """Ejecuta todos los módulos contra un dominio público autorizado."""
    config = Config()
    config.network.timeout = 10
    config.modules.dns.bruteforce = False

    orchestrator = Orchestrator(config)
    modulos = [
        DnsModule(config),
        TlsModule(config),
        WhoisModule(config),
        ShodanModule(config),
        LeaksModule(config),
        SocialsModule(config),
    ]
    for modulo in modulos:
        orchestrator.register(modulo)

    assert {modulo.name for modulo in orchestrator._modules} == {
        "dns",
        "tls",
        "whois",
        "shodan",
        "leaks",
        "socials",
    }

    datastore = await orchestrator.run("scanme.nmap.org")

    assert len(datastore) > 0
    assert set(datastore.summary()["modules_run"]).issubset(
        {modulo.name for modulo in modulos}
    )


class StreamIntegracion:
    def __init__(self):
        self._chunks = iter([
            LLMStreamChunk("Respuesta de ", False),
            LLMStreamChunk("chat de integración.", True),
        ])

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._chunks)
        except StopIteration as error:
            raise StopAsyncIteration from error


class ProveedorIntegracion:
    """Proveedor determinista para validar las capas de IA sin una API externa."""

    model = "integration-test"

    async def health_check(self):
        return True

    async def complete(self, messages, temperature=0.3, max_tokens=1000):
        prompt = messages[-1]["content"]
        if "Responde ÚNICAMENTE con este JSON exacto" in prompt:
            content = (
                '{"score_estatico": 0, "score_contextual_ia": 10, '
                '"nivel_ia": "BAJO", "justificacion": "Prueba de integración", '
                '"factores_agravantes": []}'
            )
        else:
            content = "Respuesta de integración basada en los hallazgos disponibles."
        return LLMResponse(content, self.model, 0, 0)

    def stream(self, messages, temperature=0.3, max_tokens=1000):
        return StreamIntegracion()


@pytest.mark.asyncio
async def test_pipeline_completo_config_informes_ia_y_chat(tmp_path):
    """Valida recopilación, configuración, informes, IA y streaming de chat."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
apis: {}
network:
  timeout: 10
modules:
  dns:
    bruteforce: false
output:
  directory: reports
  formats: [json, html, csv]
ai:
  enabled: true
  provider: test
  model: integration-test
""",
        encoding="utf-8",
    )
    config = Config.from_yaml(config_path)
    orchestrator = Orchestrator(config)
    modulos = [
        DnsModule(config),
        TlsModule(config),
        WhoisModule(config),
        ShodanModule(config),
        LeaksModule(config),
        SocialsModule(config),
    ]
    for modulo in modulos:
        orchestrator.register(modulo)

    datastore = await orchestrator.run("scanme.nmap.org")
    assert len(datastore) > 0

    provider = ProveedorIntegracion()
    insights = await AIAnalyst(provider).analizar(datastore, "scanme.nmap.org")
    assert {insight.type for insight in insights} == {
        "executive_summary",
        "correlation",
        "dork_suggestion",
        "risk_score",
    }

    output_dir = tmp_path / "reports"
    archivos = ReportEngine(
        output_dir=output_dir,
        formats=config.output.formats,
        cfg=config,
    ).generate(datastore, "scanme.nmap.org", insights, cfg=config)
    assert {archivo.suffix for archivo in archivos} == {".json", ".html", ".csv"}
    assert all(archivo.exists() for archivo in archivos)

    chat = InteractiveChat(provider, datastore, "scanme.nmap.org", insights)
    chat._historial.append({"role": "user", "content": "Resume los hallazgos."})
    respuesta = await chat._generar_respuesta()
    assert respuesta == "Respuesta de chat de integración."

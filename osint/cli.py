import asyncio
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="osint-framework")
def main():
    """
    Framework modular de reconocimiento OSINT.

    Automatiza el ciclo completo de reconocimiento pasivo sobre un objetivo
    consultando múltiples fuentes públicas en paralelo y generando un informe
    con los hallazgos y análisis de inteligencia artificial.

    USO ÉTICO ÚNICAMENTE. Solo sobre sistemas con autorización explícita.
    """
    pass


@main.command()
@click.argument("target")
@click.option(
    "--config", "-c",
    default="config.yaml",
    type=Path,
    help="Ruta al fichero de configuración (por defecto: config.yaml)",
)
@click.option(
    "--modules", "-m",
    multiple=True,
    type=click.Choice(["dns", "tls", "whois", "shodan", "leaks", "socials"]),
    help="Módulos a ejecutar. Si no se especifica, se ejecutan todos los habilitados.",
)
@click.option(
    "--output", "-o",
    type=Path,
    default=None,
    help="Directorio de salida para los informes.",
)
@click.option(
    "--format", "-f",
    "formats",
    multiple=True,
    type=click.Choice(["json", "html", "pdf", "csv"]),
    help="Formatos de salida. Se pueden especificar varios.",
)
@click.option(
    "--no-ai",
    is_flag=True,
    default=False,
    help="Desactiva el análisis con IA aunque esté habilitado en config.yaml.",
)
@click.option(
    "--no-chat",
    is_flag=True,
    default=False,
    help="No abre el modo chat interactivo al finalizar el escaneo.",
)

def scan(
    target: str,
    config: Path,
    modules: tuple,
    output: Path,
    formats: tuple,
    no_ai: bool,
    no_chat: bool,
):
    """
    Lanza un reconocimiento completo sobre TARGET.

    TARGET puede ser un dominio (ejemplo.com) o una IP.

    Ejemplos:

    \b
      osint scan ejemplo.com
      osint scan ejemplo.com -m dns -m tls
      osint scan ejemplo.com -f json -f html
      osint scan ejemplo.com --no-ai
    """
    asyncio.run(
        _ejecutar_scan(target, config, modules, output, formats, no_ai, no_chat)
    )


async def _ejecutar_scan(
    target: str,
    config_path: Path,
    modules: tuple,
    output: Path | None,
    formats: tuple,
    no_ai: bool,
    no_chat: bool,
):
    """Función asíncrona principal del comando scan."""
    from osint.core.config import Config
    from osint.core.orchestrator import Orchestrator
    from osint.modules.dns_module import DnsModule
    from osint.modules.leaks_module import LeaksModule
    from osint.modules.shodan_module import ShodanModule
    from osint.modules.socials_module import SocialsModule
    from osint.modules.tls_module import TlsModule
    from osint.modules.whois_module import WhoisModule

    # Cargamos la configuración
    try:
        cfg = Config.from_yaml(config_path)
    except FileNotFoundError:
        console.print(f"[red]Error: config '{config_path}' no encontrada.[/red]")
        console.print("Copia config.example.yaml → config.yaml y rellénala.")
        return

    # Sobreescribimos la config con los parámetros CLI si se han especificado
    if output:
        cfg.output.directory = output
    if formats:
        cfg.output.formats = list(formats)

    # Registramos los módulos disponibles
    todos_los_modulos = {
        "dns":     DnsModule(cfg),
        "tls":     TlsModule(cfg),
        "whois":   WhoisModule(cfg),
        "shodan":  ShodanModule(cfg),
        "leaks":   LeaksModule(cfg),
        "socials": SocialsModule(cfg),
    }

    seleccionados = modules if modules else todos_los_modulos.keys()

    orchestrator = Orchestrator(cfg)
    for nombre in seleccionados:
        if nombre in todos_los_modulos:
            orchestrator.register(todos_los_modulos[nombre])

    # Ejecutamos el escaneo
    datastore = await orchestrator.run(target)

    if len(datastore) == 0:
        console.print("[yellow]No se encontraron hallazgos.[/yellow]")
        return

    # Capa de IA
    insights = []
    if cfg.ai.enabled and not no_ai:
        insights = await _ejecutar_analisis_ia(cfg, datastore, target)

    # Generación de informes
    from osint.reports.engine import ReportEngine

    console.print("\n[bold cyan]📄 Generando informes...[/bold cyan]")
    engine = ReportEngine(output_dir=cfg.output.directory, formats=cfg.output.formats, cfg=cfg)
    archivos = engine.generate(datastore, target, insights, cfg=cfg)

    for arch in archivos:
        console.print(f"  [green]✓[/green] Guardado: [dim]{arch}[/dim]")

    # Modo chat interactivo
    if insights and not no_chat:
        await _iniciar_chat(cfg, datastore, target, insights)


async def _ejecutar_analisis_ia(cfg, datastore, target) -> list:
    """Ejecuta el análisis con IA y devuelve los insights generados."""
    from osint.ai.analyst import AIAnalyst
    from osint.ai.providers import build_provider

    try:
        provider = build_provider(cfg)
        ok = await provider.health_check()
        if not ok:
            console.print(
                "[yellow]⚠ IA no disponible. "
                "Comprueba la API key en config.yaml.[/yellow]"
            )
            return []

        console.print("\n[bold cyan]★ Analizando con IA...[/bold cyan]")
        analyst  = AIAnalyst(provider)
        insights = await analyst.analizar(datastore, target)
        console.print(f"[green]✓ {len(insights)} análisis generados[/green]")
        return insights

    except Exception as e:
        console.print(f"[yellow]⚠ Error en análisis IA: {e}[/yellow]")
        return []


async def _iniciar_chat(cfg, datastore, target, insights):
    """Inicia el modo chat interactivo post-scan."""
    from osint.ai.chat import InteractiveChat
    from osint.ai.providers import build_provider

    try:
        provider = build_provider(cfg)
        chat = InteractiveChat(
            provider=provider,
            datastore=datastore,
            target=target,
            insights=insights,
        )
        await chat.iniciar()
    except Exception as e:
        console.print(f"[yellow]⚠ Error iniciando chat: {e}[/yellow]")


@main.command("check-config")
@click.option(
    "--config", "-c",
    default="config.yaml",
    type=Path,
    help="Ruta al fichero de configuración.",
)
def check_config(config: Path):
    """
    Verifica que config.yaml existe y muestra el estado de las API keys.

    Ejemplo:

    \b
      osint check-config
      osint check-config --config mi_config.yaml
    """
    from osint.core.config import Config

    try:
        cfg = Config.from_yaml(config)
    except FileNotFoundError:
        console.print(f"[red]Error: '{config}' no encontrada.[/red]")
        console.print("Ejecuta: cp config.example.yaml config.yaml")
        return

    console.print(f"\n[bold]Configuración:[/bold] {config}\n")

    # Estado de las API keys
    keys = {
        "shodan":         "Shodan (mapeo de infraestructura)",
        "hibp":           "HaveIBeenPwned (filtraciones)",
        "github":         "GitHub (reconocimiento en repos)",
        "twitter":        "Twitter/X (reconocimiento en RRSS)",
        "groq":           "Groq (análisis con IA)",
        "censys_id":      "Censys ID (complemento Shodan)",
        "censys_secret":  "Censys Secret",
    }

    console.print("[bold]API Keys:[/bold]")
    for key, descripcion in keys.items():
        valor = cfg.get_api_key(key)
        if valor:
            console.print(f"  [green]✓[/green] {descripcion}")
        else:
            console.print(f"  [yellow]—[/yellow] {descripcion} [dim](no configurada)[/dim]")

    # Módulos disponibles
    console.print("\n[bold]Módulos disponibles:[/bold]")
    from osint.modules.dns_module import DnsModule
    from osint.modules.leaks_module import LeaksModule
    from osint.modules.shodan_module import ShodanModule
    from osint.modules.socials_module import SocialsModule
    from osint.modules.tls_module import TlsModule
    from osint.modules.whois_module import WhoisModule

    modulos = [
        DnsModule(cfg), TlsModule(cfg), WhoisModule(cfg),
        ShodanModule(cfg), LeaksModule(cfg), SocialsModule(cfg),
    ]
    for modulo in modulos:
        if modulo.is_available():
            console.print(f"  [green]✓[/green] {modulo.name} — {modulo.description}")
        else:
            console.print(
                f"  [yellow]—[/yellow] {modulo.name} "
                f"[dim](requiere key: {modulo.requires_api_key()})[/dim]"
            )

    # Estado de la IA
    console.print("\n[bold]Inteligencia Artificial:[/bold]")
    groq_key = cfg.get_api_key("groq")
    if groq_key:
        console.print("  [green]✓[/green] Groq configurado")
    else:
        console.print("  [yellow]—[/yellow] Sin proveedor de IA configurado")

    console.print()


@main.command()
@click.argument("target")
@click.option(
    "--config", "-c",
    default="config.yaml",
    type=Path,
)
def chat(
    target: str,
    config: Path = Path("config.yaml"),
    report: Path | None = None,
    ):
        """
        Abre el modo chat interactivo sobre los hallazgos de un escaneo previo.

        Ejemplos:

        \b
        osint chat ejemplo.com
        osint chat ejemplo.com -r ./reports/ejemplo.com_report.json
        """
        asyncio.run(_ejecutar_chat_standalone(target, config, report))




async def _ejecutar_chat_standalone(target: str, config_path: Path("config.yaml"), report_path: Path | None):
    """Chat standalone sin escaneo previo — usa un DataStore vacío."""
    import json

    from osint.ai.analyst import AIInsight
    from osint.ai.chat import InteractiveChat
    from osint.ai.providers import build_provider
    from osint.core.config import Config
    from osint.core.datastore import DataStore

    try:
        cfg = Config.from_yaml(config_path)
    except FileNotFoundError:
        console.print(f"[red]Error: config '{config_path}' no encontrada.[/red]")
        return

    try:
        provider = build_provider(cfg)
    except ValueError as e:
        console.print(f"[red]Error configurando IA: {e}[/red]")
        return

    # Si el usuario no pasa una ruta explícita, se busca la ruta por defecto en la carpeta de reportes
    if not report_path:
        safe_target = target.replace("/", "_").replace(":", "_")
        report_path = cfg.output.directory / f"{safe_target}_report.json"

    datastore = DataStore()
    insights = []

    # Cargam el archivo de reporte si existe
    if report_path.exists():
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            datastore = DataStore.from_dict(data)

            # Reconstruye los objetos AIInsight cargados del JSON
            for i_data in data.get("insights", []):
                insights.append(
                    AIInsight(
                        type=i_data.get("type", ""),
                        title=i_data.get("title", ""),
                        content=i_data.get("content", ""),
                        confidence=i_data.get("confidence", 0.8),
                        severity=i_data.get("severity"),
                        related_finding_types=i_data.get("related_finding_types", []),
                    )
                )

            console.print(
                f"[green]✓ Cargado informe previo desde:[/green] {report_path} "
                f"({len(datastore)} hallazgos, {len(insights)} análisis de IA)"
            )
        except Exception as e:
            console.print(f"[yellow]⚠ No se pudo leer el informe {report_path}: {e}[/yellow]")
            console.print("[dim]Iniciando chat con contexto vacío...[/dim]")
    else:
        console.print(f"[yellow]⚠ No se encontró informe previo en {report_path}[/yellow]")
        console.print("[dim]Iniciando chat con contexto vacío...[/dim]")

    chat_session = InteractiveChat(
        provider=provider,
        datastore=datastore,
        target=target,
        insights=insights,
    )
    await chat_session.iniciar()


if __name__ == "__main__":
    main()
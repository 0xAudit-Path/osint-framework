import asyncio
import time

import structlog
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from osint.core.datastore import DataStore, Finding, Severity

# Logger estructurado: guarda los eventos con contexto (módulo, target, etc.)
log = structlog.get_logger()

# Consola de Rich: gestiona todo el output con colores y formato.
console = Console()

class BaseModule:
    """
    Clase base que deben heredar todos los módulos de recopilación.

    Define el contrato mínimo que el orquestador espera de cada módulo:
    - un nombre identificativo
    - una descripción legible
    - un método run() que recibe el objetivo y devuelve una lista de findings
    - métodos opcionales para comprobar disponibilidad y requisitos
    """

    # Cada módulo sobreescribe estos atributos con sus propios valores
    name: str = "base"
    description: str = ""

    def __init__(self, config: "Config"):
        self.config = config
        self.findings: list[Finding] = []

    async def run(self, target: str) -> list[Finding]:
        """
        Método principal del módulo. Debe ser asíncrono (async) para que
        el orquestador pueda ejecutar varios módulos a la vez con asyncio.
        Cada módulo lo sobreescribe con su lógica específica.
        """
        raise NotImplementedError(f"El módulo '{self.name}' no implementa run()")

    # Si el módulo necesita una API key, devuelve el nombre del servicio.
    def requires_api_key(self) -> str | None:
        return None

    # Comprueba si el módulo puede ejecutarse. Si requiere API key, verifica que esté configurada.
    def is_available(self) -> bool:
        key_name = self.requires_api_key()
        if key_name:
            return self.config.get_api_key(key_name) is not None
        return True

    # Atajo para crear un Finding y añadirlo a la lista del módulo.
    def add_finding(self, **kwargs) -> Finding:
        f = Finding(module=self.name, **kwargs)
        self.findings.append(f)
        return f


class Orchestrator:
    """
    Motor central del framework. Coordina la ejecución de todos los módulos
    registrados y agrega sus resultados en el DataStore.

    Funciona de la siguiente manera:
    1. Se registran los módulos que se quieren ejecutar
    2. Se llama a run() con el objetivo
    3. Todos los módulos se ejecutan en paralelo con asyncio.gather()
    4. Los findings de cada módulo se añaden al DataStore al terminar
    5. Se devuelve el DataStore con todos los hallazgos consolidados
    """

    def __init__(self, config: "Config"):  
        self.config = config
        self.datastore = DataStore()

        # Lista interna de módulos registrados y listos para ejecutar
        self._modules: list[BaseModule] = []

    # Registra un módulo para que sea ejecutado en el siguiente scan
    def register(self, module: BaseModule):
        if not module.is_available():
            key = module.requires_api_key()
            console.print(
                f"[yellow]⚠ Módulo '[bold]{module.name}[/bold]' deshabilitado: "
                f"falta API key '[italic]{key}[/italic]' en config.yaml[/yellow]"
            )
            return

        self._modules.append(module)
        log.debug("modulo_registrado", modulo=module.name)

    # Ejecuta todos los módulos registrados en paralelo contra el objetivo
    async def run(self, target: str) -> DataStore:
        if not self._modules:
            console.print("[red]No hay módulos registrados para ejecutar.[/red]")
            return self.datastore

        start = time.perf_counter()

        console.print(f"\n[bold cyan]▶ Objetivo:[/bold cyan] [bold]{target}[/bold]")
        console.print(
            f"[dim]Módulos activos: "
            f"{', '.join(m.name for m in self._modules)}[/dim]\n"
        )

        # Barra de progreso con spinner, texto y barra visual
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:

            # Creamos una tarea de progreso por cada módulo
            tasks_ui = {
                m.name: progress.add_task(
                    f"[cyan]{m.name}[/cyan]", total=None
                )
                for m in self._modules
            }

            async def ejecutar_modulo(module: BaseModule):
                """
                Función interna que ejecuta un módulo individual y gestiona
                tanto el resultado como los posibles errores.
                Se ejecuta en paralelo para cada módulo registrado.
                """
                log.info("modulo.inicio", modulo=module.name, objetivo=target)
                try:
                    findings = await module.run(target)
                    nuevos = self.datastore.add_many(findings)

                    log.info(
                        "modulo.completado",
                        modulo=module.name,
                        findings_nuevos=nuevos,
                    )

                    # Actualizamos la barra de progreso con el resultado
                    progress.update(
                        tasks_ui[module.name],
                        completed=True,
                        description=(
                            f"[green]✓ {module.name}[/green] "
                            f"[dim]({nuevos} hallazgos)[/dim]"
                        ),
                    )

                except Exception as e:
                    log.error(
                        "modulo.error",
                        modulo=module.name,
                        error=str(e),
                    )
                    progress.update(
                        tasks_ui[module.name],
                        completed=True,
                        description=f"[red]✗ {module.name}[/red] [dim]{e}[/dim]",
                    )

            # Lanzamos todos los módulos a la vez y esperamos a que terminen
            await asyncio.gather(
                *[ejecutar_modulo(m) for m in self._modules],
                return_exceptions=True,
            )

        # Mostramos el resumen final
        elapsed = time.perf_counter() - start
        summary = self.datastore.summary()

        high = summary["by_severity"].get(Severity.HIGH, 0)
        medium = summary["by_severity"].get(Severity.MEDIUM, 0)
        low = summary["by_severity"].get(Severity.LOW, 0)
        info = summary["by_severity"].get(Severity.INFO, 0)

        console.print(
            f"\n[bold green]✓ Escaneo completado en {elapsed:.1f}s[/bold green]"
        )
        console.print(
            f"[dim]Total de hallazgos: [bold]{summary['total']}[/bold] — "
            f"[red]{high} HIGH[/red] · "
            f"[yellow]{medium} MEDIUM[/yellow] · "
            f"[blue]{low} LOW[/blue] · "
            f"[dim]{info} INFO[/dim][/dim]\n"
        )

        return self.datastore
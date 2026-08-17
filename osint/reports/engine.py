from pathlib import Path

import structlog

from osint.ai.analyst import AIInsight
from osint.core.datastore import DataStore
from osint.reports.exporters.csv_exporter import CSVExporter
from osint.reports.exporters.html_exporter import HTMLExporter
from osint.reports.exporters.json_exporter import JSONExporter

log = structlog.get_logger()


class ReportEngine:
    """Orquestador central para la generación de informes en múltiples formatos."""

    def __init__(self, output_dir: Path, formats: list[str], cfg=None):
        self.output_dir = output_dir
        self.formats = [f.lower() for f in formats]
        self.cfg = cfg

    def generate(
        self,
        datastore: DataStore,
        target: str,
        insights: list[AIInsight] | None = None,
        cfg=None,
    ) -> list[Path]:
        """
        Genera los archivos de informe según los formatos especificados en la configuración.
        """
        generated_files: list[Path] = []
        safe_target = target.replace("/", "_").replace(":", "_")
        base_filename = f"{safe_target}_report"

        config_obj = cfg or self.cfg
        groq_key = config_obj.get_api_key("groq") if config_obj else None

        self.output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in self.formats:
            try:
                if fmt == "json":
                    out = self.output_dir / f"{base_filename}.json"
                    JSONExporter.export(datastore, target, out, insights)
                    generated_files.append(out)

                elif fmt == "csv":
                    out = self.output_dir / f"{base_filename}.csv"
                    CSVExporter.export(datastore, target, out)
                    generated_files.append(out)

                elif fmt in ("html", "pdf"):
                    # Generamos el HTML (si piden PDF, el HTML resultante es imprimible a PDF directamente)
                    out = self.output_dir / f"{base_filename}.html"
                    HTMLExporter.export(datastore, target, out, insights, groq_api_key=groq_key)
                    generated_files.append(out)

            except Exception as e:
                log.error("reports.export_error", format=fmt, error=str(e))
        return generated_files
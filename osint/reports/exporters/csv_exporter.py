import csv
import json
from pathlib import Path

from osint.core.datastore import DataStore


class CSVExporter:
    """Exporta la lista de hallazgos del DataStore a un archivo CSV plano."""

    @staticmethod
    def export(datastore: DataStore, target: str, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = ["module", "type", "value", "severity", "source", "metadata"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for finding in datastore:
                row = finding.to_dict()
                # Serializamos los metadatos a string para el CSV
                row["metadata"] = json.dumps(row["metadata"], ensure_ascii=False)
                writer.writerow(row)

        return output_path
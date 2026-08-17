import json
from pathlib import Path
from typing import Optional

from osint.ai.analyst import AIInsight
from osint.core.datastore import DataStore


class JSONExporter:
    """Exporta los hallazgos y los análisis de la IA a un archivo JSON estructurado."""

    @staticmethod
    def export(
        datastore: DataStore,
        target: str,
        output_path: Path,
        insights: Optional[list[AIInsight]] = None,
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "target": target,
            "summary": datastore.summary(),
            "insights": [
                {
                    "type": i.type,
                    "title": i.title,
                    "content": i.content,
                    "confidence": i.confidence,
                    "severity": i.severity,
                    "related_finding_types": i.related_finding_types,
                }
                for i in (insights or [])
            ],
            "findings": [f.to_dict() for f in datastore],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return output_path
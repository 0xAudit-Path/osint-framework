from collections import defaultdict
from typing import Iterator


# Tipos de severidad de hallazgos
class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# Clases de hallazgos
class Finding:
    def __init__(
        self,
        module: str,
        type: str,
        value: str,
        severity: str = Severity.INFO,
        source: str | None = None,
        metadata: dict | None = None,
    ):
        self.module = module
        self.type = type
        self.value = value
        self.severity = severity
        self.source = source
        self.metadata = metadata or {}

    # Método para convertir hallazgo a diccionario
    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "type": self.type,
            "value": self.value,
            "severity": self.severity,
            "source": self.source,
            "metadata": self.metadata,
        }

    # Representación en string
    def __repr__(self) -> str:
        return f"Finding(module={self.module}, type={self.type}, value={self.value}, severity={self.severity})"

# Almacén centralizado de resultados
class DataStore:
    def __init__(self):
        self._findings: list[Finding] = []
        self._seen: set[str] = set()

    # Agregar hallazgo
    def add(self, finding: Finding) -> bool:
        # Crear clave única para evitar duplicados
        key = f"{finding.module}:{finding.type}:{finding.value}"
        # Verificar si el hallazgo ya existe
        if key in self._seen:
            return False
        self._seen.add(key)
        self._findings.append(finding)
        return True

    # Agregar múltiples hallazgos
    def add_many(self, findings: list[Finding]) -> int:
        return sum(1 for f in findings if self.add(f))

    # Obtener hallazgos por módulo
    def by_module(self, module: str) -> list[Finding]:
        return [f for f in self._findings if f.module == module]

    # Obtener hallazgos por severidad
    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    # Obtener hallazgos por tipo
    def by_type(self, ftype: str) -> list[Finding]:
        return [f for f in self._findings if f.type == ftype]

    # Resumen de hallazgos
    def summary(self) -> dict:
        counts: dict[str, int] = defaultdict(int)
        for f in self._findings:
            counts[f.severity] += 1
        return {
            "total": len(self._findings),
            "by_severity": dict(counts),
            "modules_run": list({f.module for f in self._findings}),
        }

    # Convertir a diccionario
    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self._findings],
        }

    # Iterar sobre hallazgos
    def __iter__(self) -> Iterator[Finding]:
        return iter(self._findings)

    # Obtener número de hallazgos
    def __len__(self) -> int:
        return len(self._findings)

    # Método para reconstruir un DataStore a partir de un diccionario
    @classmethod
    def from_dict(cls, data: dict) -> "DataStore":
        """Reconstruye un DataStore a partir del diccionario de un reporte JSON."""
        ds = cls()
        for f_data in data.get("findings", []):
            finding = Finding(
                module=f_data.get("module", "unknown"),
                type=f_data.get("type", "unknown"),
                value=f_data.get("value", ""),
                severity=f_data.get("severity", Severity.INFO),
                source=f_data.get("source"),
                metadata=f_data.get("metadata", {}),
            )
            ds.add(finding)
        return ds

    def calculate_static_risk(self) -> dict:
        """
        Calcula un score de riesgo estático (0-100) basado en reglas fijas
        y ponderación por severidad.
        """
        pesos = {
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }

        puntuacion_raw = sum(
            len(self.by_severity(sev)) * peso 
            for sev, peso in pesos.items()
        )
        score_final = min(100, puntuacion_raw)

        if score_final >= 75:
            nivel = "CRÍTICO"
        elif score_final >= 50:
            nivel = "ALTO"
        elif score_final >= 25:
            nivel = "MEDIO"
        else:
            nivel = "BAJO"

        return {"score": score_final, "nivel": nivel}
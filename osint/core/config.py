from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator


# Configuración de la red
class NetworkConfig(BaseModel):
    timeout: int = 10
    retries: int = 3
    proxy: Optional[str] = None

# Configuración de DNS
class DnsConfig(BaseModel):
    enabled: bool = True
    bruteforce: bool = False
    wordlist: Optional[Path] = None
    resolvers: list[str] = ["8.8.8.8", "1.1.1.1"]

# Configuración de módulos
class ModulesConfig(BaseModel):
    dns: DnsConfig = Field(default_factory=DnsConfig)

# Configuración de AI
class AiConfig(BaseModel):
    enabled: bool = True
    provider: str = "groq"   
    model: str = "llama-3.3-70b-versatile"

# Configuración de salida
class OutputConfig(BaseModel):
    directory: Path = Path("./reports")
    formats: list[str] = ["json", "html", "csv"] # Formatos de salida permitidos por defecto

    @field_validator("formats")
    @classmethod
    def valid_formats(cls, v: list[str]) -> list[str]:
        allowed = {"json", "html", "pdf", "csv"}
        for fmt in v:
            if fmt not in allowed:
                raise ValueError(f"Format '{fmt}' not supported. Use: {allowed}")
        return v

# Configuración global
class Config(BaseModel):
    apis: dict[str, Optional[str]] = Field(default_factory=dict)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    ai: AiConfig = Field(default_factory=AiConfig)

    @classmethod
    # Cargar configuración desde YAML
    def from_yaml(cls, path: Path) -> "Config":
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    # Obtener API key de un servicio específico
    def get_api_key(self, service: str) -> Optional[str]:
        key = self.apis.get(service)
        return key if key else None
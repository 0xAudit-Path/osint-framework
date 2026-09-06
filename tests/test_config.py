from pathlib import Path

from osint.core.config import Config


def test_config_carga_seccion_ai(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
apis:
  groq: test-key
ai:
  enabled: false
  provider: ollama
  model: llama3.1
""",
        encoding="utf-8",
    )

    config = Config.from_yaml(config_path)

    assert config.ai.enabled is False
    assert config.ai.provider == "ollama"
    assert config.ai.model == "llama3.1"
    assert config.get_api_key("groq") == "test-key"
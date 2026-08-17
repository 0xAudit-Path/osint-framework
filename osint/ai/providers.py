import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import aiohttp


@dataclass
class LLMResponse:
    """
    Respuesta completa de uno de los modelo de lenguaje.
    Encapsula el contenido y los metadatos de uso de tokens.
    """
    content:           str
    model:             str
    prompt_tokens:     int
    completion_tokens: int


@dataclass
class LLMStreamChunk:
    """
    Fragmento de respuesta en modo streaming.
    El modelo devuelve el texto token a token en lugar de esperar
    a que esté completo, lo que hace la experiencia más fluida.
    """
    delta:    str   # texto del fragmento actual
    finished: bool  # True cuando el modelo ha terminado de generar


class BaseProvider(ABC):
    """
    Interfaz común para todos los proveedores de LLM.

    El resto del sistema nunca interactúa directamente con Groq
    u Ollama, solo habla con BaseProvider. Esto permite cambiar
    de proveedor modificando una sola línea en config.yaml.
    """

    @abstractmethod
    async def complete(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 1000,
    ) -> LLMResponse:
        """
        Genera una respuesta completa y la devuelve de golpe.
        Usar cuando no se necesita mostrar el texto mientras se genera.
        """
        ...

    @abstractmethod
    async def stream(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 1000,
    ) -> AsyncIterator[LLMStreamChunk]:
        """
        Genera la respuesta en streaming, token a token.
        Usar en el modo chat para que el usuario vea la respuesta
        aparecer progresivamente en lugar de esperar al final.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verifica que el proveedor está disponible y responde.
        Se llama antes del escaneo para avisar si la IA no está lista.
        """
        ...


class GroqProvider(BaseProvider):
    """
    Proveedor de IA usando la API de Groq.

    Groq es un servicio cloud gratuito (con cuenta) que ofrece
    inferencia de LLMs de código abierto a velocidades muy altas
    gracias a su hardware especializado (LPU).

    Modelos disponibles en el tier gratuito:
    - llama-3.1-70b-versatile  → mejor calidad, recomendado
    - llama-3.1-8b-instant     → más rápido, menor calidad
    - mixtral-8x7b-32768       → buena alternativa
    - gemma2-9b-it             → modelo de Google

    API key gratuita en: https://console.groq.com
    La API es compatible con el formato de OpenAI, lo que facilita
    la migración entre proveedores.
    """

    BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model   = model
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }

    async def complete(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 1000,
    ) -> LLMResponse:
        """
        Llama al endpoint de chat completions de Groq sin streaming.
        Espera a que el modelo termine de generar y devuelve todo.
        """
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
            "stream":      False,
        }

        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=self._headers,
                    json=payload,
                ) as r:
                    r.raise_for_status()
                    data = await r.json()

            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                model=self.model,
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
            )

        except aiohttp.ClientResponseError as e:
            raise RuntimeError(f"Error de Groq API ({e.status}): {e.message}")
        except Exception as e:
            raise RuntimeError(f"Error conectando con Groq: {e}")

    async def stream(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 1000,
    ) -> AsyncIterator[LLMStreamChunk]:
        """
        Streaming de respuesta desde Groq usando Server-Sent Events (SSE).

        Groq devuelve los tokens en formato SSE, cada línea con el prefijo
        'data: ' seguido de un JSON con el delta de texto. Cuando el modelo
        termina envía 'data: [DONE]'.

        Este formato es el estándar de OpenAI y lo siguen todos los
        proveedores compatibles, incluyendo Ollama cuando lo añadamos.
        """
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
            "stream":      True,
        }

        timeout = aiohttp.ClientTimeout(total=120)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=self._headers,
                    json=payload,
                ) as r:
                    r.raise_for_status()
                    async for line in r.content:
                        linea = line.decode("utf-8").strip()

                        # Ignoramos líneas vacías y comentarios SSE
                        if not linea or not linea.startswith("data: "):
                            continue

                        raw = linea[6:]  # quitamos el prefijo "data: "

                        # [DONE] indica que el modelo terminó de generar
                        if raw.strip() == "[DONE]":
                            yield LLMStreamChunk(delta="", finished=True)
                            return

                        try:
                            chunk = json.loads(raw)
                            delta = (
                                chunk["choices"][0]
                                .get("delta", {})
                                .get("content", "")
                            )
                            terminado = (
                                chunk["choices"][0].get("finish_reason") is not None
                            )
                            yield LLMStreamChunk(delta=delta or "", finished=terminado)
                        except (json.JSONDecodeError, KeyError):
                            continue

        except aiohttp.ClientResponseError as e:
            raise RuntimeError(f"Error de Groq API ({e.status}): {e.message}")
        except Exception as e:
            raise RuntimeError(f"Error en streaming con Groq: {e}")

    async def health_check(self) -> bool:
        """
        Verifica que la API key es válida y Groq responde.
        Llama al endpoint de modelos que es ligero y no consume créditos.
        """
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{self.BASE_URL}/models",
                    headers=self._headers,
                ) as r:
                    return r.status == 200
        except Exception:
            return False


def build_provider(config: "Config") -> BaseProvider:  # type: ignore[name-defined]
    """
    Factory que construye el proveedor correcto según config.yaml.

    El resto del código solo trabaja con BaseProvider, nunca
    con GroqProvider directamente. Esto hace que añadir Ollama
    en el futuro sea crear la clase y añadir un elif aquí.
    """
    ai_config = getattr(config, "ai", {})
    if isinstance(ai_config, dict):
        proveedor = ai_config.get("provider", "groq").lower()
        modelo    = ai_config.get("model", "llama-3.3-70b-versatile")
    else:
        proveedor = getattr(ai_config, "provider", "groq").lower()
        modelo    = getattr(ai_config, "model", "llama-3.3-70b-versatile")

    if proveedor == "groq":
        key = config.get_api_key("groq")
        if not key:
            raise ValueError(
                "Falta la key de Groq en config.yaml (apis.groq). "
                "Obtén una gratuita en https://console.groq.com"
            )
        return GroqProvider(api_key=key, model=modelo)

    raise ValueError(
        f"Proveedor '{proveedor}' no soportado. "
        f"Valores válidos: groq"
    )
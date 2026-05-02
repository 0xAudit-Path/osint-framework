import asyncio
import random
import time

# Clase para limitar la tasa de solicitudes
class RateLimiter:
    def __init__(
        self,
        calls_per_second: float = 2.0,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
    ):
        self.calls_per_second = calls_per_second
        self.min_delay = min_delay
        self.max_delay = max_delay
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    # Espera según la velocidad configurada
    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / self.calls_per_second
            elapsed = now - self._last_call
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_call = time.monotonic()

    # Espera aleatoria entre min_delay y max_delay
    async def wait_random(self):
        await self.wait()
        delay = random.uniform(self.min_delay, self.max_delay)
        await asyncio.sleep(delay)

# Lista de User-Agents
# Si se realizan peticiones HTTP sin identificarnos correctamente, muchos servidores las bloquearán directamente.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# Obtiene un User-Agent aleatorio.
# Los módulos lo usarán en las cabeceras de sus peticiones HTTP para parecer un navegador normal.
def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)
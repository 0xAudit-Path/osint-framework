import asyncio

import aiodns
import dns.exception
import dns.query
import dns.resolver
import dns.zone

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule

class DnsModule(BaseModule):
    """
    Módulo de enumeración DNS.

    Realiza tres tipos de consultas sobre el dominio objetivo:
    1. Resolución de registros estándar (A, AAAA, MX, NS, TXT, CNAME, SOA)
    2. Intento de transferencia de zona (AXFR)
    3. Fuerza bruta de subdominios con diccionario (opcional)

    Usa los servidores DNS configurados en config.yaml
    o los de Google (8.8.8.8) y Cloudflare (1.1.1.1) por defecto.
    """

    name = "dns"
    description = "Enumeración de registros DNS y descubrimiento de subdominios"

    # Tipos de registro que se consultan en cada escaneo
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    async def run(self, target: str) -> list[Finding]:
        """
        Punto de entrada del módulo. Lanza en paralelo la resolución
        de todos los tipos de registro y el intento de transferencia de zona.
        Si está habilitada la fuerza bruta en config.yaml, la lanza también.
        """
        resolver = aiodns.DNSResolver(
            nameservers=self.config.modules.dns.resolvers,
            timeout=self.config.network.timeout,
        )

        # Se crea una tarea por cada tipo de registro y se lanzan a la vez
        tareas = [
            self._consultar_registro(resolver, target, rtype)
            for rtype in self.RECORD_TYPES
        ]

        # La transferencia de zona se lanza siempre junto al resto
        tareas.append(self._intentar_transferencia_zona(target))

        # La fuerza bruta solo si está habilitada en config.yaml
        if self.config.modules.dns.bruteforce:
            tareas.append(self._fuerza_bruta_subdominios(resolver, target))

        # return_exceptions=True evita que un fallo detenga el resto de tareas
        await asyncio.gather(*tareas, return_exceptions=True)

        return self.findings

    async def _consultar_registro(
        self, resolver: aiodns.DNSResolver, dominio: str, rtype: str
    ):
        """
        Consulta un tipo de registro DNS concreto para el dominio.
        Si el registro no existe, aiodns lanza una excepción que se ignora,
        ya que es el comportamiento normal cuando el registro no está definido.
        """
        try:
            resultado = await resolver.query(dominio, rtype)

            for registro in resultado:
                valor = str(registro)
                severidad = self._clasificar_severidad(rtype, valor)

                self.add_finding(
                    type=f"dns_{rtype.lower()}",
                    value=valor,
                    severity=severidad,
                    source=f"dns/{rtype}",
                    metadata={
                        "record_type": rtype,
                        "domain": dominio,
                    },
                )

        except aiodns.error.DNSError:
            # El registro no existe para este dominio, es completamente normal
            pass

    def _clasificar_severidad(self, rtype: str, valor: str) -> str:
        """
        Asigna la severidad de un registro DNS según su tipo y contenido.

        La mayoría son informativos, pero algunos merecen más atención:
        - Los registros TXT con SPF o DMARC indican política de email
          que puede estar mal configurada
        - Los registros NS exponen los servidores autoritativos del dominio
        """
        if rtype == "TXT":
            valor_lower = valor.lower()
            if "v=spf" in valor_lower or "_dmarc" in valor_lower:
                # Política de email presente pero revisable
                return Severity.LOW
        if rtype == "NS":
            # Los NS exponen qué proveedor DNS usa el objetivo
            return Severity.LOW

        return Severity.INFO

    async def _intentar_transferencia_zona(self, dominio: str):
        """
        Intenta una transferencia de zona AXFR contra cada nameserver del dominio.

        Una transferencia de zona devuelve TODOS los registros DNS del dominio
        de golpe. Si el servidor lo permite, es una misconfiguration grave porque
        revela toda la infraestructura interna del objetivo.
        En servidores bien configurados esto está bloqueado y simplemente falla.
        """
        try:
            # Primero obtenemos los nameservers del dominio
            ns_resultado = dns.resolver.resolve(dominio, "NS")

            for ns in ns_resultado:
                ns_str = str(ns.target).rstrip(".")
                try:
                    # Intentamos la transferencia contra este nameserver
                    zona = dns.zone.from_xfr(
                        dns.query.xfr(ns_str, dominio, timeout=5)
                    )

                    # Si llegamos aquí, la transferencia funcionó: mala configuración
                    for nombre in zona.nodes:
                        self.add_finding(
                            type="zone_transfer_record",
                            value=f"{nombre}.{dominio}",
                            severity=Severity.HIGH,
                            source=f"axfr/{ns_str}",
                            metadata={
                                "nameserver": ns_str,
                                "zone": dominio,
                            },
                        )

                except Exception:
                    # La transferencia fue bloqueada, que es lo esperado
                    pass

        except Exception:
            pass

    async def _fuerza_bruta_subdominios(
        self, resolver: aiodns.DNSResolver, dominio: str
    ):
        """
        Prueba subdominios comunes usando un diccionario de palabras.
        Para cada palabra del diccionario construye un FQDN y comprueba
        si resuelve a alguna IP. Si resuelve, es un subdominio activo.

        Las consultas se lanzan en grupos de 50 a la vez para no saturar
        el resolver DNS ni generar demasiado tráfico de golpe.
        """
        wordlist = self.config.modules.dns.wordlist
        if not wordlist or not wordlist.exists():
            return

        with open(wordlist) as f:
            palabras = [line.strip() for line in f if line.strip()]

        # Procesamos en grupos de 50 para controlar la carga
        tamano_grupo = 50
        for i in range(0, len(palabras), tamano_grupo):
            grupo = palabras[i : i + tamano_grupo]
            tareas = [
                self._comprobar_subdominio(resolver, f"{palabra}.{dominio}")
                for palabra in grupo
            ]
            await asyncio.gather(*tareas, return_exceptions=True)

    async def _comprobar_subdominio(
        self, resolver: aiodns.DNSResolver, fqdn: str
    ):
        """
        Comprueba si un subdominio concreto resuelve alguna IP.
        Si resuelve, lo registra como hallazgo de severidad LOW
        porque cualquier subdominio activo amplía la superficie de ataque.
        """
        try:
            resultado = await resolver.query(fqdn, "A")
            if resultado:
                self.add_finding(
                    type="subdomain",
                    value=fqdn,
                    severity=Severity.LOW,
                    source="dns/bruteforce",
                    metadata={
                        "ips": [str(r) for r in resultado],
                    },
                )
        except Exception:
            # El subdominio no existe, se ignora
            pass
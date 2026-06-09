import asyncio
from typing import Any

import whois
from ipwhois import IPWhois

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule


class WhoisModule(BaseModule):
    """
    Módulo de reconocimiento WHOIS y ASN.

    Trabaja con dos fuentes complementarias:

    1. WHOIS de dominio — consulta los servidores WHOIS para obtener
       información de registro del dominio: registrante, fechas de
       creación y expiración, nameservers y registrar.
       Usa la librería python-whois, que no requiere API key.

    2. WHOIS de IP / ASN — para cada IP asociada al dominio consulta
       los registros de los registros regionales de Internet (ARIN,
       RIPE, LACNIC, APNIC) para obtener el bloque de red, el ASN
       y la organización propietaria.
       Usa la librería ipwhois, que tampoco requiere API key.

    Ninguna de las dos fuentes tiene límites de uso significativos 
    para un uso normal de OSINT.
    """

    name = "whois"
    description = "Consulta WHOIS de dominio e IPs para obtener información de registro y ASN"

    async def run(self, target: str) -> list[Finding]:
        """
        Lanza en paralelo el WHOIS del dominio y el WHOIS de sus IPs.
        Ambas operaciones son síncronas internamente, así que las
        ejecuta en un executor para no bloquear el event loop.
        """
        await asyncio.gather(
            self._whois_dominio(target),
            self._whois_ips(target),
            return_exceptions=True,
        )
        return self.findings

    async def _whois_dominio(self, dominio: str):
        """
        Consulta el WHOIS del dominio objetivo.

        python-whois hace la consulta de forma síncrona, así que
        la ejecuta en un executor para no bloquear asyncio.
        El resultado es un objeto con todos los campos del registro
        WHOIS parseados automáticamente.
        """
        try:
            resultado = await asyncio.get_event_loop().run_in_executor(
                None, whois.whois, dominio
            )
            if resultado:
                self._procesar_whois_dominio(resultado, dominio)
        except Exception:
            # Algunos dominios no tienen WHOIS público o el servidor
            # rechaza la consulta. No es un error crítico.
            pass

    def _procesar_whois_dominio(self, datos: Any, dominio: str):
        """
        Extrae y clasifica la información relevante del resultado WHOIS.

        Los campos más interesantes desde el punto de vista OSINT son:
        - El registrante: quién registró el dominio
        - Las fechas: cuándo se creó y cuándo expira
        - Los nameservers: dónde está la DNS autoritativa
        - El registrar: a través de qué empresa se registró
        """

        # --- Información general del dominio ---
        # Siempre registra un finding informativo con los datos básicos
        self.add_finding(
            type="whois_domain",
            value=dominio,
            severity=Severity.INFO,
            source="whois",
            metadata={
                "registrar": self._extraer_campo(datos, "registrar"),
                "creation_date": self._formatear_fecha(
                    self._extraer_campo(datos, "creation_date")
                ),
                "expiration_date": self._formatear_fecha(
                    self._extraer_campo(datos, "expiration_date")
                ),
                "updated_date": self._formatear_fecha(
                    self._extraer_campo(datos, "updated_date")
                ),
                "name_servers": self._extraer_lista(datos, "name_servers"),
                "status": self._extraer_lista(datos, "status"),
                "dnssec": self._extraer_campo(datos, "dnssec"),
            },
        )

        # --- Registrante ---
        # La información del registrante puede estar anonimizada (privacy guard)
        # o ser pública. Si es pública, es un dato de inteligencia valioso.
        registrante = self._extraer_campo(datos, "org") or self._extraer_campo(
            datos, "name"
        )
        if registrante:
            self.add_finding(
                type="whois_registrant",
                value=registrante,
                severity=Severity.INFO,
                source="whois",
                metadata={
                    "domain": dominio,
                    "email": self._extraer_campo(datos, "emails"),
                    "country": self._extraer_campo(datos, "country"),
                },
            )

        # --- Expiración del dominio ---
        # Un dominio que expira pronto podría ser secuestrado si no se renueva.
        # Es un dato relevante para el informe.
        expiracion = self._extraer_campo(datos, "expiration_date")
        if expiracion:
            self._comprobar_expiracion_dominio(expiracion, dominio)

        # --- Nameservers ---
        # Los nameservers revelan el proveedor DNS y pueden ser útiles
        # para cruzar con otros hallazgos del módulo DNS.
        nameservers = self._extraer_lista(datos, "name_servers")
        for ns in nameservers:
            if ns:
                self.add_finding(
                    type="whois_nameserver",
                    value=ns.lower(),
                    severity=Severity.INFO,
                    source="whois",
                    metadata={"domain": dominio},
                )

    def _comprobar_expiracion_dominio(self, expiracion: Any, dominio: str):
        """
        Comprueba si el dominio está próximo a expirar o ya ha expirado.
        Un dominio expirado puede ser comprado por un atacante.
        """
        from datetime import datetime, timezone, timedelta

        try:
            # expiration_date puede ser una lista o un objeto datetime
            if isinstance(expiracion, list):
                expiracion = expiracion[0]

            # python-whois devuelve datetimes sin timezone a veces
            if expiracion.tzinfo is None:
                expiracion = expiracion.replace(tzinfo=timezone.utc)

            ahora = datetime.now(timezone.utc)
            dias_restantes = (expiracion - ahora).days

            if dias_restantes < 0:
                self.add_finding(
                    type="domain_expired",
                    value=dominio,
                    severity=Severity.HIGH,
                    source="whois",
                    metadata={
                        "expired_days_ago": abs(dias_restantes),
                        "expiration_date": expiracion.isoformat(),
                    },
                )
            elif dias_restantes < 30:
                self.add_finding(
                    type="domain_expiring_soon",
                    value=dominio,
                    severity=Severity.MEDIUM,
                    source="whois",
                    metadata={
                        "days_remaining": dias_restantes,
                        "expiration_date": expiracion.isoformat(),
                    },
                )
        except Exception:
            pass

    async def _whois_ips(self, dominio: str):
        """
        Resuelve el dominio a sus IPs y consulta el WHOIS de cada una.
        Obtiene el ASN, bloque de red y organización propietaria.
        """
        import socket

        try:
            # Obtiene todas las IPs asociadas al dominio
            infos = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.getaddrinfo(dominio, None),
            )

            # Deduplica las IPs antes de consultarlas
            ips_vistas: set[str] = set()
            for info in infos:
                ip = info[4][0]
                if ip not in ips_vistas:
                    ips_vistas.add(ip)
                    await self._whois_ip(ip, dominio)

        except Exception:
            pass

    async def _whois_ip(self, ip: str, dominio: str):
        """
        Consulta el WHOIS de una IP concreta usando ipwhois.

        ipwhois consulta los registros regionales de Internet (RIR):
        - ARIN: América del Norte
        - RIPE: Europa y Oriente Medio
        - LACNIC: América Latina
        - APNIC: Asia-Pacífico
        - AFRINIC: África

        El resultado incluye el ASN (número de sistema autónomo),
        el bloque CIDR al que pertenece la IP y la organización
        que tiene asignado ese bloque.
        """
        try:
            resultado = await asyncio.get_event_loop().run_in_executor(
                None, self._consultar_ipwhois, ip
            )
            if resultado:
                self._procesar_whois_ip(resultado, ip, dominio)
        except Exception:
            pass

    def _consultar_ipwhois(self, ip: str) -> dict | None:
        """
        Ejecuta la consulta ipwhois de forma síncrona.
        Se llama desde un executor para no bloquear asyncio.
        """
        try:
            obj = IPWhois(ip)
            return obj.lookup_rdap(depth=1)
        except Exception:
            return None

    def _procesar_whois_ip(self, datos: dict, ip: str, dominio: str):
        """
        Extrae la información relevante del resultado WHOIS de una IP.
        """
        asn = datos.get("asn", "")
        asn_descripcion = datos.get("asn_description", "")
        asn_cidr = datos.get("asn_cidr", "")
        asn_pais = datos.get("asn_country_code", "")

        self.add_finding(
            type="ip_asn",
            value=ip,
            severity=Severity.INFO,
            source="ipwhois",
            metadata={
                "domain": dominio,
                "asn": asn,
                "asn_description": asn_descripcion,
                "cidr": asn_cidr,
                "country": asn_pais,
                "network_name": datos.get("network", {}).get("name", ""),
            },
        )

        # Si el ASN corresponde a un proveedor cloud conocido, lo indica,
        # porque tiene implicaciones distintas a infraestructura propia
        proveedores_cloud = {
            "amazon": "AWS",
            "google": "GCP",
            "microsoft": "Azure",
            "cloudflare": "Cloudflare",
            "digitalocean": "DigitalOcean",
            "ovh": "OVHcloud",
            "hetzner": "Hetzner",
        }
        descripcion_lower = asn_descripcion.lower()
        for keyword, nombre in proveedores_cloud.items():
            if keyword in descripcion_lower:
                self.add_finding(
                    type="cloud_provider",
                    value=f"{ip} → {nombre}",
                    severity=Severity.INFO,
                    source="ipwhois",
                    metadata={
                        "ip": ip,
                        "provider": nombre,
                        "asn": asn,
                    },
                )
                break

    # ---------------------------------------------------------------------------
    # Helpers para extraer campos del resultado WHOIS
    # ---------------------------------------------------------------------------

    def _extraer_campo(self, datos: Any, campo: str) -> str:
        """
        Extrae un campo del resultado WHOIS de forma segura.
        python-whois puede devolver el campo como string, lista o None.
        Siempre se devuelve un string para simplificar el procesado.
        """
        valor = getattr(datos, campo, None)
        if valor is None:
            return ""
        if isinstance(valor, list):
            return str(valor[0]) if valor else ""
        return str(valor)

    def _extraer_lista(self, datos: Any, campo: str) -> list[str]:
        """
        Extrae un campo del resultado WHOIS que espera que sea una lista.
        Si es un string lo envuelve en una lista para uniformidad.
        """
        valor = getattr(datos, campo, None)
        if valor is None:
            return []
        if isinstance(valor, list):
            return [str(v) for v in valor if v]
        return [str(valor)]

    def _formatear_fecha(self, fecha: str) -> str:
        """
        Normaliza las fechas al formato ISO 8601.
        python-whois puede devolver fechas en formatos distintos
        según el TLD y el registrar. Se normalizan para el informe.
        """
        if not fecha:
            return ""
        try:
            from datetime import datetime
            if isinstance(fecha, datetime):
                return fecha.isoformat()
        except Exception:
            pass
        return str(fecha)
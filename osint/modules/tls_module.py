import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from osint.core.datastore import Finding, Severity
from osint.core.orchestrator import BaseModule


class TlsModule(BaseModule):
    """
    Módulo de análisis de certificados TLS.

    Trabaja con dos fuentes complementarias:

    1. crt.sh — base de datos pública de Certificate Transparency Logs.
       Contiene todos los certificados emitidos por autoridades certificadoras
       públicas. Permite descubrir subdominios históricos que nunca aparecerían
       en una enumeración DNS normal porque pueden estar inactivos.

    2. Conexión TLS directa — se conecta al servidor del objetivo y analiza
       el certificado activo: fechas de expiración, algoritmos de firma,
       tamaño de clave, SANs (Subject Alternative Names) e información
       del emisor. Detecta certificados expirados, débiles o autofirmados.
    """

    name = "tls"
    description = "Análisis de certificados TLS y descubrimiento de subdominios via CT Logs"

    # URL de la API pública de crt.sh
    # El prefijo %25 es la codificación URL del comodín %
    # que permite buscar todos los subdominios del dominio
    CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

    async def run(self, target: str) -> list[Finding]:
        """
        Lanza en paralelo la consulta a crt.sh y el análisis
        del certificado activo del servidor.
        """
        await asyncio.gather(
            self._consultar_crt_sh(target),
            self._analizar_certificado_activo(target),
            return_exceptions=True,
        )
        return self.findings

    async def _consultar_crt_sh(self, dominio: str):
        """
        Consulta crt.sh para obtener todos los certificados emitidos
        para el dominio y sus subdominios.

        crt.sh indexa los Certificate Transparency Logs, que son registros
        públicos donde las autoridades certificadoras deben publicar cada
        certificado que emiten. Esto permite ver subdominios históricos
        aunque ya no estén activos en DNS.
        """
        url = self.CRT_SH_URL.format(domain=dominio)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers={"Accept": "application/json"},
            ) as respuesta:
                if respuesta.status != 200:
                    return
                datos = await respuesta.json(content_type=None)

        # Usa  un set para no procesar el mismo nombre dos veces
        nombres_vistos: set[str] = set()

        for entrada in datos:
            # Cada entrada puede contener varios nombres separados por saltos de línea
            nombres_raw = entrada.get("name_value", "")
            nombres = [n.strip() for n in nombres_raw.splitlines() if n.strip()]

            for nombre in nombres:
                # Elimina el comodín si lo hay (*.example.com → example.com)
                limpio = nombre.lstrip("*.")

                # Ignora duplicados y nombres que no pertenecen al dominio objetivo
                if limpio in nombres_vistos or not limpio.endswith(dominio):
                    continue
                nombres_vistos.add(limpio)

                severidad = self._severidad_por_expiracion(
                    entrada.get("not_after", "")
                )

                self.add_finding(
                    type="certificate_subdomain",
                    value=limpio,
                    severity=severidad,
                    source="crt.sh",
                    metadata={
                        "issuer": entrada.get("issuer_name", ""),
                        "not_before": entrada.get("not_before", ""),
                        "not_after": entrada.get("not_after", ""),
                        "is_wildcard": nombre.startswith("*."),
                        "crt_id": entrada.get("id"),
                    },
                )

    def _severidad_por_expiracion(self, not_after: str) -> str:
        """
        Determina la severidad de un certificado según su fecha de expiración.
        Un certificado expirado que sigue en uso es un hallazgo relevante.
        """
        if not not_after:
            return Severity.INFO

        try:
            expiracion = datetime.fromisoformat(
                not_after.replace("Z", "+00:00")
            )
            ahora = datetime.now(timezone.utc)
            dias_restantes = (expiracion - ahora).days

            if dias_restantes < 0:
                # Certificado ya expirado
                return Severity.MEDIUM
            elif dias_restantes < 30:
                # Expira pronto, hay que renovarlo
                return Severity.LOW

        except ValueError:
            pass

        return Severity.INFO

    async def _analizar_certificado_activo(self, dominio: str, puerto: int = 443):
        """
        Se conecta al servidor y extrae el certificado TLS activo.

        Usa el módulo ssl de la librería estándar de Python para la conexión
        y cryptography para parsear el certificado X.509 y extraer toda
        la información relevante: SANs, algoritmos, fechas y emisor.

        La conexión es síncrona (ssl y socket no son async), así que se
        ejecuta en un executor para no bloquear el event loop de asyncio.
        """
        try:
            cert_der = await asyncio.get_event_loop().run_in_executor(
                None, self._obtener_cert_der, dominio, puerto
            )
            if cert_der:
                await self._procesar_certificado(cert_der, dominio)
        except Exception:
            # El servidor puede no tener HTTPS, estar caído o rechazar
            # la conexión. No es un error crítico, simplemente no hay datos.
            pass

    def _obtener_cert_der(self, dominio: str, puerto: int) -> Optional[bytes]:
        """
        Establece la conexión SSL y obtiene el certificado en formato DER.

        DER (Distinguished Encoding Rules) es el formato binario estándar
        de los certificados X.509. Se necesita en este formato para
        que la librería cryptography pueda parsearlo.

        Desactiva la verificación del certificado (CERT_NONE) para poder
        analizar también certificados autofirmados o expirados sin que
        Python rechace la conexión.
        """
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE

        with socket.create_connection((dominio, puerto), timeout=10) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                return ssock.getpeercert(binary_form=True)

    async def _procesar_certificado(self, cert_der: bytes, dominio: str):
        """
        Parsea el certificado DER y extrae toda la información relevante.
        Detecta problemas de seguridad: expiración, algoritmos débiles,
        claves cortas y certificados autofirmados.
        """
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        ahora = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        dias_restantes = (not_after - ahora).days

        # --- Comprobación de expiración ---
        if dias_restantes < 0:
            self.add_finding(
                type="expired_certificate",
                value=dominio,
                severity=Severity.HIGH,
                source="tls/live",
                metadata={
                    "expired_days_ago": abs(dias_restantes),
                    "not_after": not_after.isoformat(),
                },
            )
        elif dias_restantes < 15:
            self.add_finding(
                type="expiring_certificate",
                value=dominio,
                severity=Severity.HIGH,
                source="tls/live",
                metadata={"days_remaining": dias_restantes},
            )
        elif dias_restantes < 30:
            self.add_finding(
                type="expiring_certificate",
                value=dominio,
                severity=Severity.MEDIUM,
                source="tls/live",
                metadata={"days_remaining": dias_restantes},
            )

        # --- Subject Alternative Names ---
        # Los SANs son los dominios adicionales que cubre el certificado.
        # Pueden revelar subdominios que no aparecen en DNS.
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for nombre in san_ext.value.get_values_for_type(x509.DNSName):
                self.add_finding(
                    type="san_domain",
                    value=nombre.lstrip("*."),
                    severity=Severity.INFO,
                    source="tls/san",
                    metadata={"certificate_domain": dominio},
                )
        except x509.ExtensionNotFound:
            pass

        # --- Algoritmo de firma débil ---
        # MD5 y SHA1 están rotos criptográficamente desde hace años.
        # Un certificado que los usa es un hallazgo de severidad alta.
        try:
            algo = cert.signature_hash_algorithm
            if algo and algo.name in ("md5", "sha1"):
                self.add_finding(
                    type="weak_signature_algorithm",
                    value=f"{dominio} usa {algo.name.upper()}",
                    severity=Severity.HIGH,
                    source="tls/live",
                    metadata={"algorithm": algo.name},
                )
        except Exception:
            pass

        # --- Tamaño de clave RSA insuficiente ---
        # Claves RSA menores de 2048 bits se consideran inseguras desde 2010.
        try:
            clave_publica = cert.public_key()
            if isinstance(clave_publica, rsa.RSAPublicKey):
                if clave_publica.key_size < 2048:
                    self.add_finding(
                        type="weak_rsa_key",
                        value=f"{dominio}: RSA {clave_publica.key_size} bits",
                        severity=Severity.HIGH,
                        source="tls/live",
                        metadata={"key_size": clave_publica.key_size},
                    )
        except Exception:
            pass

        # --- Certificado autofirmado ---
        # En producción un certificado autofirmado es sospechoso porque
        # cualquiera puede emitir uno para cualquier dominio.
        es_autofirmado = cert.issuer == cert.subject
        if es_autofirmado:
            self.add_finding(
                type="self_signed_certificate",
                value=dominio,
                severity=Severity.MEDIUM,
                source="tls/live",
                metadata={},
            )

        # --- Información general del certificado ---
        # Siempre registra un finding informativo con los datos básicos
        # para que aparezcan en el informe aunque no haya problemas.
        try:
            subject_cn = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except (IndexError, Exception):
            subject_cn = ""

        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except (IndexError, Exception):
            issuer_cn = ""

        self.add_finding(
            type="certificate_info",
            value=dominio,
            severity=Severity.INFO,
            source="tls/live",
            metadata={
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": dias_restantes,
                "is_self_signed": es_autofirmado,
            },
        )
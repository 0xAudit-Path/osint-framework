# osint-framework

Herramienta automatizada de reconocimiento OSINT, modular y de código abierto, escrita en Python.

**El objetivo es automatizar el ciclo completo de reconocimiento pasivo desde fuentes públicas y generar un informe que cualquier analista pueda leer y reproducir.**

---

## Aviso legal

Esta herramienta realiza únicamente reconocimiento **pasivo**. No accede a ningún sistema sin autorización, no explota vulnerabilidades y no realiza ataques de ningún tipo. Aun así, úsala **solo en**:

- Dominios e infraestructura bajo tu control
- Auditorías con consentimiento explícito y por escrito
- Entornos de laboratorio y plataformas CTF (HackTheBox, TryHackMe)
- Dominios de prueba públicos (`scanme.nmap.org`, `example.com`)

El uso de esta herramienta sobre sistemas sin autorización puede ser constitutivo de delito en virtud del artículo 197 bis del Código Penal español y legislación equivalente en otras jurisdicciones.

---

## Tabla de contenidos

1. [Quickstart](#quickstart)
2. [¿Qué es OSINT?](#qué-es-osint)
   - [El ciclo de inteligencia](#el-ciclo-de-inteligencia)
   - [Reconocimiento pasivo vs activo](#reconocimiento-pasivo-vs-activo)
   - [Fuentes de información pública](#fuentes-de-información-pública)
3. [Arquitectura del proyecto](#arquitectura-del-proyecto)
   - [Estructura de ficheros](#estructura-de-ficheros)
   - [Flujo de ejecución](#flujo-de-ejecución)
   - [El DataStore](#el-datastore)
4. [Módulos de recopilación](#módulos-de-recopilación)
   - [DNS](#dns)
   - [TLS / Certificados](#tls--certificados)
   - [WHOIS y ASN](#whois-y-asn)
   - [Shodan](#shodan)
5. [Capa de inteligencia artificial](#capa-de-inteligencia-artificial)
6. [Instalación](#instalación)
7. [Configuración](#configuración)
8. [Uso](#uso)
9. [Tests](#tests)
10. [Comparativa con herramientas existentes](#comparativa-con-herramientas-existentes)
11. [Recursos para aprender más](#recursos-para-aprender-más)

---

## Quickstart

```bash
# Clonar e instalar
git clone https://github.com/0xAudit-Path/osint-framework.git
cd osint-framework
poetry install

# Configurar API keys (solo las gratuitas son necesarias)
cp config.example.yaml config.yaml

# Configurar la IA local (opcional pero recomendado)
poetry run osint ai-setup

# Escaneo completo
poetry run osint scan ejemplo.com

# Escaneo con módulos específicos
poetry run osint scan ejemplo.com -m dns -m tls

# Escaneo con formato de salida concreto
poetry run osint scan ejemplo.com -f json -f html

# Chat interactivo sobre los resultados
poetry run osint chat ejemplo.com --results reports/ejemplo.com.json

# Verificar configuración y API keys
poetry run osint check-config
```

---

## ¿Qué es OSINT?

OSINT (*Open Source Intelligence*) es la disciplina de recopilar y analizar información de fuentes de acceso público para obtener inteligencia útil sobre un objetivo. No implica acceso no autorizado a ningún sistema: toda la información ya está disponible en Internet, la diferencia está en saber dónde buscar y cómo correlacionarla.

En ciberseguridad, OSINT es la primera fase de cualquier auditoría o test de penetración. Antes de interactuar con los sistemas objetivo, un analista dedica horas a recopilar información pasiva que después guía el resto del proceso.

### El ciclo de inteligencia

```
┌─────────────────────────────────────────────────────────────┐
│  1. PLANIFICACIÓN                                           │
│  ¿Qué queremos saber? ¿Sobre qué objetivo?                  │
├─────────────────────────────────────────────────────────────┤
│  2. RECOPILACIÓN  ← esta herramienta automatiza esta fase   │
│  DNS · TLS · Shodan · WHOIS · Filtraciones · RRSS           │
├─────────────────────────────────────────────────────────────┤
│  3. PROCESADO                                               │
│  Normalización, deduplicación y clasificación por severidad │
├─────────────────────────────────────────────────────────────┤
│  4. ANÁLISIS  ← la capa de IA automatiza esta fase          │
│  Correlaciones, risk score, resumen ejecutivo               │
├─────────────────────────────────────────────────────────────┤
│  5. DISEMINACIÓN                                            │
│  Informe en PDF, HTML, JSON y CSV                           │
└─────────────────────────────────────────────────────────────┘
```

### Reconocimiento pasivo vs activo

| Característica | Pasivo (esta herramienta) | Activo |
|---|---|---|
| Interacción con el objetivo | Ninguna directa | Directa (ping, escaneo de puertos...) |
| Detectable por el objetivo | No | Sí (aparece en logs) |
| Fuentes | Bases de datos públicas, APIs | El propio sistema objetivo |
| Legalidad sin autorización | Legal | Ilegal en la mayoría de jurisdicciones |
| Ejemplos | crt.sh, Shodan, WHOIS | nmap, nikto, dirbuster |

### Fuentes de información pública

Cada fuente revela una capa distinta de la infraestructura del objetivo:

```
DOMINIO objetivo.com
        │
        ├── DNS ──────────────── Subdominios, IPs, servidores de correo
        │                        Transferencias de zona mal configuradas
        │
        ├── TLS / CT Logs ─────── Subdominios históricos (crt.sh)
        │                        Certificados expirados o débiles
        │
        ├── WHOIS / ASN ────────── Registrante, fechas, proveedor de red
        │                        Bloque CIDR, organización propietaria
        │
        ├── Shodan / Censys ────── Puertos abiertos, banners, CVEs
        │                        Paneles de administración expuestos
        │
        ├── Filtraciones ───────── Credenciales comprometidas (HIBP)
        │                        Correos corporativos en brechas
        │
        └── RRSS / GitHub ──────── Empleados, tecnologías, secretos
                                  en repositorios públicos
```

---

## Arquitectura del proyecto

### Estructura de ficheros

```
osint-framework/
├── pyproject.toml              → dependencias y comando CLI
├── config.example.yaml         → plantilla de configuración
├── osint/
│   ├── cli.py                  → comandos de terminal (Click)
│   ├── core/
│   │   ├── config.py           → carga y validación de config.yaml (Pydantic)
│   │   ├── datastore.py        → almacén central de hallazgos
│   │   ├── orchestrator.py     → ejecución paralela de módulos (asyncio)
│   │   └── rate_limiter.py     → control de velocidad y rotación de UA
│   ├── modules/
│   │   ├── dns_module.py       → registros DNS, zona transfer, bruteforce
│   │   ├── tls_module.py       → CT Logs (crt.sh) y análisis de certificado
│   │   ├── whois_module.py     → WHOIS de dominio e IPs (ASN, CIDR)
│   │   ├── shodan_module.py    → puertos, banners, CVEs (Shodan + Censys)
│   │   ├── leaks_module.py     → credenciales filtradas (HIBP)
│   │   └── socials_module.py   → GitHub, Twitter/X, LinkedIn
│   ├── ai/
│   │   ├── providers.py        → Ollama (local) y Groq (cloud) con interfaz común
│   │   ├── analyst.py          → análisis post-scan: resumen, correlaciones, dorks
│   │   ├── chat.py             → modo conversacional interactivo con streaming
│   │   └── setup.py            → instalación asistida de Ollama
│   └── reports/
│       ├── engine.py           → generación de informes (PDF, HTML, JSON, CSV)
│       └── templates/          → plantillas Jinja2
└── tests/
    ├── test_dns_module.py
    ├── test_tls_module.py
    └── test_whois_module.py
```

### Flujo de ejecución

```
Usuario: osint scan ejemplo.com
              │
              ▼
          cli.py
          Valida argumentos y carga config.yaml
              │
              ▼
       Orchestrator
       Registra módulos disponibles según config y API keys
              │
              ▼
    ┌─────────────────────────────────────────────────┐
    │  asyncio.gather() — ejecución paralela          │
    │                                                 │
    │  DnsModule    TlsModule    WhoisModule  ...     │
    │      │            │            │                │
    │      └────────────┴────────────┘                │
    │                   │                             │
    │               findings[]                        │
    └───────────────────┼─────────────────────────────┘
                        │
                        ▼
                    DataStore
              Normaliza y deduplica
                        │
                        ▼
                   AI Analyst  (opcional)
              Resumen · Correlaciones · Risk score
                        │
                        ▼
                  ReportEngine
              PDF · HTML · JSON · CSV
                        │
                        ▼
                  Chat interactivo  (opcional)
              Preguntas en lenguaje natural sobre los resultados
```

### El DataStore

El `DataStore` es el objeto central que recorre todo el pipeline. Cada módulo produce una lista de `Finding` que se añade al DataStore al terminar. Un `Finding` tiene la siguiente estructura:

```python
Finding(
    module   = "dns",           # qué módulo lo encontró
    type     = "subdomain",     # tipo de hallazgo
    value    = "dev.ejemplo.com", # el dato en sí
    severity = "low",           # info | low | medium | high
    source   = "dns/bruteforce",# fuente concreta
    metadata = {"ips": ["1.2.3.4"]}  # datos adicionales
)
```

El DataStore deduplica automáticamente: si dos módulos distintos descubren el mismo subdominio, solo se registra una vez.

**Niveles de severidad:**

| Nivel | Ejemplos |
|---|---|
| `HIGH` | CVE con CVSS ≥ 7, certificado expirado, transferencia de zona permitida, RDP/MongoDB expuesto |
| `MEDIUM` | Certificado autofirmado, dominio próximo a expirar, SMTP expuesto |
| `LOW` | Subdominio descubierto, SSH expuesto, política SPF revisable |
| `INFO` | Registros DNS estándar, información WHOIS, geolocalización |

---

## Módulos de recopilación

### DNS

Realiza tres tipos de consultas de forma paralela usando `aiodns` (asíncrono):

**1. Resolución de registros estándar**

Consulta todos los tipos relevantes: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`. Los lanza todos a la vez con `asyncio.gather()`, por lo que el tiempo total es el del registro más lento, no la suma de todos.

**2. Transferencia de zona (AXFR)**

```
Servidor bien configurado:
  cliente → AXFR → servidor → REFUSED ✓

Servidor mal configurado:
  cliente → AXFR → servidor → [todos los registros DNS] ← HIGH
```

Si el servidor lo permite, devuelve toda la infraestructura DNS de golpe. Es una misconfiguration grave que marca todos los registros obtenidos como `HIGH`.

**3. Fuerza bruta de subdominios**

Prueba palabras de un diccionario (configurable) construyendo FQDNs y comprobando si resuelven. Se lanza en grupos de 50 peticiones simultáneas para controlar la carga.

### TLS / Certificados

Dos fuentes complementarias en paralelo:

**crt.sh (CT Logs)**

Los Certificate Transparency Logs son registros públicos donde las autoridades certificadoras deben publicar cada certificado que emiten. crt.sh los indexa todos. Buscando `%.ejemplo.com` obtenemos todos los subdominios para los que se ha emitido algún certificado, incluyendo históricos que ya no están en DNS.

```
crt.sh query: %.ejemplo.com
     │
     ├── ejemplo.com          (certificado vigente)
     ├── www.ejemplo.com      (certificado vigente)
     ├── dev.ejemplo.com      (certificado expirado hace 8 meses) ← interesante
     ├── staging.ejemplo.com  (certificado expirado hace 2 años)  ← interesante
     └── api.ejemplo.com      (certificado vigente)
```

**Conexión TLS directa**

Se conecta al servidor con `ssl.CERT_NONE` (para analizar también certificados inválidos) y parsea el certificado X.509 con la librería `cryptography`:

- Fechas de validez y días restantes
- Subject Alternative Names (SANs) → subdominios adicionales
- Algoritmo de firma (MD5/SHA1 → `HIGH`)
- Tamaño de clave RSA (< 2048 bits → `HIGH`)
- Certificado autofirmado (`MEDIUM`)

### WHOIS y ASN

**WHOIS de dominio** (`python-whois`)

Consulta los servidores WHOIS para obtener el registrante, las fechas de creación y expiración, los nameservers y el registrar. Un dominio próximo a expirar es `MEDIUM` porque podría ser comprado por un atacante para ataques de phishing o intercepción de correo.

**WHOIS de IP / ASN** (`ipwhois`)

Para cada IP del dominio consulta los registros regionales de Internet (ARIN, RIPE, LACNIC, APNIC) usando el protocolo RDAP:

```
IP: 93.184.216.34
     │
     └── ASN: AS15133
         Organización: Edgecast Inc.
         CIDR: 93.184.216.0/24
         País: US
         Proveedor cloud detectado: Cloudflare  ← cruzado con lista de proveedores
```

### Shodan

Tres fuentes en cascada, de mayor a menor detalle:

| Fuente | Datos | API key | Límite |
|---|---|---|---|
| Shodan | Puertos, banners, CVEs, OS, geolocalización | Sí (gratis con email académico) | 100 queries/mes (free) |
| Censys | Servicios, protocolos, TLS por IP | Opcional | Free tier disponible |
| ipinfo.io | ASN, organización, país | No | 50.000 req/mes |

El módulo clasifica automáticamente los puertos por severidad real, no solo por presencia:

```
Puerto 22  (SSH)       → LOW    (normal, pero revisar versión)
Puerto 445 (SMB)       → HIGH   (EternalBlue, PrintNightmare)
Puerto 3306 (MySQL)    → HIGH   (base de datos expuesta a Internet)
Puerto 6379 (Redis)    → HIGH   (sin autenticación por defecto)
Puerto 9200 (Elastic)  → HIGH   (sin autenticación por defecto)
```

También detecta paneles de administración expuestos analizando los títulos HTTP de Shodan (Grafana, Jenkins, phpMyAdmin, Kibana...) y cruza los servicios detectados con la base de datos de CVEs que Shodan ya proporciona.

---

## Capa de inteligencia artificial

Tras el escaneo, el `AIAnalyst` procesa el DataStore completo y genera cuatro productos en paralelo:

**1. Resumen ejecutivo**

Texto de ~250 palabras en lenguaje natural dirigido a un responsable técnico. Destaca los 3 hallazgos más críticos y sugiere prioridades de acción.

**2. Correlaciones entre módulos**

El análisis más valioso. Detecta relaciones entre hallazgos de distintos módulos que un humano podría pasar por alto:

```
Ejemplo de correlación detectada:

  [dns/bruteforce]  → dev.ejemplo.com resuelve a 1.2.3.4
  [tls/crt.sh]      → certificado de dev.ejemplo.com expiró hace 8 meses
  [shodan]          → 1.2.3.4 tiene el puerto 8080 abierto con panel de admin
  [leaks/hibp]      → 3 credenciales filtradas del dominio ejemplo.com

  → Correlación: entorno de desarrollo expuesto accidentalmente en producción
    con credenciales comprometidas. Severidad: ALTA.
```

**3. Google Dorks personalizados**

Genera 6 dorks específicos basados en la tecnología detectada en el escaneo. Mucho más efectivos que un diccionario estático porque se adaptan a lo que realmente usa el objetivo.

**4. Risk score**

Puntuación de 0 a 100 con nivel (CRÍTICO / ALTO / MEDIO / BAJO) y justificación. Aparece en la portada del informe.

**Modo chat interactivo**

Tras el escaneo el usuario puede hacer preguntas en lenguaje natural sobre los resultados:

```
▶ Objetivo: ejemplo.com
✓ Completado en 34.2s — 187 hallazgos (3 HIGH · 12 MEDIUM · 45 LOW)

   Modo análisis interactivo

> ¿Cuáles son los tres hallazgos más urgentes?
  1. MySQL expuesto en 93.184.216.34:3306 con credenciales filtradas
     asociadas al dominio. Riesgo de acceso directo a la base de datos.
  2. Transferencia de zona permitida en ns2.ejemplo.com — expone toda
     la infraestructura DNS interna.
  3. Certificado de dev.ejemplo.com expirado hace 8 meses con panel
     de administración accesible en el puerto 8080.

> ¿Hay subdominios que parezcan entornos de desarrollo?
  Sí: dev.ejemplo.com, staging.ejemplo.com y test.ejemplo.com.
  Los tres tienen certificados expirados y apuntan a IPs distintas
  a la infraestructura principal.
```

**Proveedores de IA soportados:**

| Proveedor | Modelo | Coste | Requiere |
|---|---|---|---|
| Ollama | llama3.1:8b, mistral:7b | Gratis | Instalación local |
| Groq | llama-3.1-70b-versatile | Gratis | API key (sin tarjeta) |

---

## Instalación

**Requisitos:**
- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- [Ollama](https://ollama.com/download) (opcional, para análisis con IA)

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/osint-framework.git
cd osint-framework

# 2. Instalar dependencias
poetry install

# 3. Configurar Ollama (opcional)
poetry run osint ai-setup
# Descarga llama3.1:8b (~4.7 GB) y verifica que funciona
```

---

## Configuración

```bash
cp config.example.yaml config.yaml
```

```yaml
apis:
  shodan: ""        # gratis con email académico → https://account.shodan.io
  hibp: ""          # gratis con cuenta → https://haveibeenpwned.com/API/Key
  github: ""        # gratis → https://github.com/settings/tokens
  groq: ""          # gratis → https://console.groq.com (para IA en cloud)

network:
  timeout: 10       # segundos por petición
  retries: 3

modules:
  dns:
    enabled: true
    bruteforce: false         # true para activar fuerza bruta de subdominios
    wordlist: null            # ruta a tu wordlist, ej: wordlists/top1m.txt
    resolvers: ["8.8.8.8", "1.1.1.1"]
  tls:
    enabled: true
  whois:
    enabled: true
  shodan:
    enabled: true             # funciona sin key con Censys + ipinfo como fallback

ai:
  enabled: true
  provider: "ollama"          # ollama | groq
  model: "llama3.1:8b"
  features:
    executive_summary: true
    correlations: true
    dork_generation: true
    chat: true

output:
  directory: "./reports"
  formats: ["json", "html", "pdf"]
```

Las API keys marcadas como gratuitas no requieren tarjeta de crédito. Si no configuras ninguna, los módulos que no las necesitan (DNS, TLS, WHOIS) siguen funcionando con normalidad.

---

## Uso

```bash
# Escaneo completo con todos los módulos
poetry run osint scan ejemplo.com

# Solo módulos específicos
poetry run osint scan ejemplo.com -m dns -m tls -m whois

# Elegir formatos de salida
poetry run osint scan ejemplo.com -f json -f html

# Directorio de salida personalizado
poetry run osint scan ejemplo.com -o ./mis-informes

# Chat sobre resultados de un scan previo
poetry run osint chat ejemplo.com --results reports/ejemplo.com_20250524.json

# Configurar Ollama (solo la primera vez)
poetry run osint ai-setup --model llama3.1:8b

# Verificar API keys configuradas
poetry run osint check-config
```

---

## Tests

```bash
# Ejecutar todos los tests
poetry run pytest tests/ -v

# Un módulo concreto
poetry run pytest tests/test_dns_module.py -v

# Con cobertura
poetry run pytest tests/ -v --cov=osint --cov-report=term-missing

# Con reporte HTML de cobertura
poetry run pytest tests/ --cov=osint --cov-report=html
# Abre htmlcov/index.html en el navegador
```

**Estrategia de tests:**

Los tests no hacen peticiones reales a Internet. Cada dependencia externa (aiodns, aiohttp, socket) se mockea para que los tests sean rápidos, deterministas y funcionen sin conexión.

Excepción: el módulo TLS genera certificados X.509 reales usando la librería `cryptography` porque esta opera sobre bytes reales y no acepta mocks.

**Cobertura actual por módulo:**

| Módulo | Cobertura |
|---|---|
| `dns_module.py` | 96% |
| `tls_module.py` | 83% |
| `whois_module.py` | — (en progreso) |

---

## Comparativa con herramientas existentes

| Característica | osint-framework | theHarvester | Recon-ng | Maltego |
|---|---|---|---|---|
| Licencia | MIT (gratis) | MIT (gratis) | BSD (gratis) | Comercial |
| Módulos mantenidos | ✓ | Parcial | Parcial | ✓ |
| Ejecución paralela | ✓ (asyncio) | ✗ | Parcial | ✓ |
| Informe PDF/HTML | ✓ | ✗ | ✗ | ✓ (de pago) |
| Análisis con IA | ✓ (local/gratis) | ✗ | ✗ | ✗ |
| Chat sobre resultados | ✓ | ✗ | ✗ | ✗ |
| Sin API keys obligatorias | ✓ | ✓ | ✓ | ✗ |
| Configuración | YAML | CLI flags | Consola interactiva | GUI |

---

## Recursos para aprender más

- **"Open Source Intelligence Techniques"** — Michael Bazzell. La referencia práctica de OSINT.
- **MITRE ATT&CK TA0043** — Táctica de reconocimiento con técnicas y subtécnicas documentadas. https://attack.mitre.org/tactics/TA0043/
- **PTES** — Penetration Testing Execution Standard. Marco metodológico donde se encuadra el reconocimiento. http://www.pentest-standard.org/
- **crt.sh** — Interfaz web de CT Logs para explorar certificados manualmente. https://crt.sh
- **Shodan** — Motor de búsqueda de dispositivos conectados. https://www.shodan.io
- **HaveIBeenPwned** — Base de datos de filtraciones de credenciales. https://haveibeenpwned.com
- **dnspython** — Documentación de la librería DNS usada en este proyecto. https://dnspython.readthedocs.io
- **cryptography** — Librería Python para operaciones criptográficas. https://cryptography.io

---

*Proyecto de Trabajo de Fin de Grado — Ingeniería Informática, mención en Tecnologías de la Información. Uso exclusivamente ético y con autorización.*
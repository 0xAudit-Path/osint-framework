import html
import re
from pathlib import Path

from osint.core.datastore import DataStore, Severity


class HTMLExporter:
    """
    Genera un informe HTML técnico de nivel ejecutivo: dashboard estático
    con KPIs, gráficos de severidad/módulo, score de riesgo y tabla de
    evidencias filtrable.

    Es completamente autocontenido y offline (sin llamadas a APIs externas
    ni CDNs), por lo que es seguro entregarlo a un cliente sin que dependa
    de ninguna key ni conexión.

    El chat interactivo con IA vive únicamente en la CLI (`osint chat`),
    donde la clave de API nunca sale de la máquina del auditor.
    """

    # Colores usados en los gráficos SVG, alineados con las variables CSS
    # de severidad para que el dashboard sea visualmente consistente.
    COLOR_SEVERIDAD = {
        Severity.HIGH:   "#ef4444",
        Severity.MEDIUM: "#f59e0b",
        Severity.LOW:    "#3b82f6",
        Severity.INFO:   "#94a3b8",
    }

    ORDEN_SEVERIDAD = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    @staticmethod
    def _limpiar_valor(valor: str) -> str:
        """Sanea representaciones crudas de objetos Python."""
        if "AresQuery" in valor:
            match_host = re.search(r"host=['\"]([^'\"]+)['\"]", valor)
            if match_host:
                return match_host.group(1)
            match_text = re.search(r"text=['\"]([^'\"]+)['\"]", valor)
            if match_text:
                return match_text.group(1)
        return valor

    @staticmethod
    def _esc(valor) -> str:
        """
        Escapa cualquier valor antes de insertarlo en el HTML.

        Los hallazgos (títulos HTTP, banners, nombres de dominio...) vienen
        de la infraestructura del objetivo auditado, no del auditor, así que
        deben tratarse como no confiables antes de insertarlos en el informe.
        """
        return html.escape(str(valor), quote=True)

    @classmethod
    def _texto_insight_a_html(cls, contenido: str) -> str:
        """
        Convierte un subconjunto útil de Markdown a HTML seguro sin depender
        de una librería externa. El contenido se escapa antes de añadir las
        etiquetas generadas por el parser.
        """
        lineas = contenido.replace("\r\n", "\n").split("\n")
        resultado = []
        lista = None
        parrafo = []

        def cerrar_parrafo():
            if parrafo:
                resultado.append(f'<p>{cls._markdown_inline(" ".join(parrafo))}</p>')
                parrafo.clear()

        def cerrar_lista():
            nonlocal lista
            if lista:
                resultado.append(f"</{lista}>")
                lista = None

        for linea in lineas:
            texto = linea.strip()
            if not texto:
                cerrar_parrafo()
                cerrar_lista()
                continue

            encabezado = re.match(r"^(#{1,3})\s+(.+)$", texto)
            if encabezado:
                cerrar_parrafo()
                cerrar_lista()
                nivel = len(encabezado.group(1)) + 2
                resultado.append(
                    f'<h{nivel}>{cls._markdown_inline(encabezado.group(2))}</h{nivel}>'
                )
                continue

            item = re.match(r"^[-*+]\s+(.+)$", texto)
            item_ordenado = re.match(r"^\d+[.)]\s+(.+)$", texto)
            if item or item_ordenado:
                cerrar_parrafo()
                tipo = "ul" if item else "ol"
                if lista != tipo:
                    cerrar_lista()
                    resultado.append(f"<{tipo}>")
                    lista = tipo
                contenido_item = (item or item_ordenado).group(1)
                resultado.append(f'<li>{cls._markdown_inline(contenido_item)}</li>')
                continue

            if texto.startswith("> "):
                cerrar_parrafo()
                cerrar_lista()
                resultado.append(
                    f'<blockquote>{cls._markdown_inline(texto[2:])}</blockquote>'
                )
                continue

            cerrar_lista()
            parrafo.append(texto)

        cerrar_parrafo()
        cerrar_lista()
        return "\n".join(resultado)

    @classmethod
    def _markdown_inline(cls, contenido: str) -> str:
        """Escapa inline Markdown y permite únicamente enlaces http(s)."""
        escapado = cls._esc(contenido)
        protegidos = []

        def proteger(valor: str) -> str:
            protegidos.append(valor)
            return f"\x00{len(protegidos) - 1}\x00"

        escapado = re.sub(
            r"`([^`]+)`",
            lambda m: proteger(f"<code>{m.group(1)}</code>"),
            escapado,
        )
        escapado = re.sub(
            r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
            lambda m: proteger(
                f'<a href="{m.group(2)}" target="_blank" rel="noopener noreferrer">'
                f"{m.group(1)}</a>"
            ),
            escapado,
        )

        def reemplazar_negrita(match):
            return f"<strong>{match.group(1) or match.group(2)}</strong>"

        def reemplazar_cursiva(match):
            return f"<em>{match.group(1) or match.group(2)}</em>"

        escapado = re.sub(
            r"\*\*(.+?)\*\*|__(.+?)__",
            reemplazar_negrita,
            escapado,
        )
        escapado = re.sub(
            r"(?<!\*)\*([^*]+)\*(?!\*)|(?<!_)_([^_]+)_(?!_)",
            reemplazar_cursiva,
            escapado,
        )
        escapado = re.sub(r"~~(.+?)~~", r"<del>\1</del>", escapado)
        for indice, valor in enumerate(protegidos):
            escapado = escapado.replace(f"\x00{indice}\x00", valor)
        return escapado

    @classmethod
    def _parsear_risk_score(cls, contenido: str):
        """
        Intenta extraer score (0-100) y nivel del texto del insight de riesgo.
        Devuelve None si el formato no coincide, para poder hacer fallback
        a mostrarlo como un insight normal sin perder información.
        """
        m = re.search(
            r"\*{0,2}Score Contextual \(IA\):\*{0,2}\s*(\d+)\s*/\s*100\s*[—-]\s*\*{0,2}"
            r"([A-ZÁÉÍÓÚ]+)\*{0,2}",
            contenido,
        )
        if not m:
            return None
        return int(m.group(1)), m.group(2)

    @classmethod
    def _contar_por_modulo(cls, datastore: DataStore) -> list[tuple[str, int]]:
        """Cuenta hallazgos por módulo, ordenados de mayor a menor."""
        conteo: dict[str, int] = {}
        for f in datastore:
            conteo[f.module] = conteo.get(f.module, 0) + 1
        return sorted(conteo.items(), key=lambda x: x[1], reverse=True)

    @classmethod
    def _grafico_donut_severidad(cls, by_sev: dict) -> str:
        """
        Genera un donut chart en SVG puro con la distribución por severidad.
        Sin JS ni librerías externas: se calcula todo en Python.
        """
        total = sum(by_sev.get(s, 0) for s in cls.ORDEN_SEVERIDAD)
        if total == 0:
            return '<div class="chart-empty">Sin hallazgos que representar.</div>'

        radio = 54
        circunferencia = 2 * 3.14159265 * radio
        offset_acumulado = 0.0
        segmentos = ""
        leyenda = ""

        for sev in cls.ORDEN_SEVERIDAD:
            cantidad = by_sev.get(sev, 0)
            if cantidad == 0:
                continue
            color = cls.COLOR_SEVERIDAD[sev]
            largo_segmento = circunferencia * (cantidad / total)
            segmentos += (
                f'<circle cx="65" cy="65" r="{radio}" fill="none" '
                f'stroke="{color}" stroke-width="18" '
                f'stroke-dasharray="{largo_segmento:.2f} {circunferencia - largo_segmento:.2f}" '
                f'stroke-dashoffset="{-offset_acumulado:.2f}" />'
            )
            offset_acumulado += largo_segmento

            porcentaje = round(100 * cantidad / total)
            leyenda += f"""
                <div class="legend-item">
                    <span class="legend-dot" style="background:{color};"></span>
                    <span class="legend-label">{sev.upper()}</span>
                    <span class="legend-value">{cantidad} ({porcentaje}%)</span>
                </div>"""

        return f"""
        <div class="donut-wrapper">
            <svg viewBox="0 0 130 130" class="donut-svg">
                <g transform="rotate(-90 65 65)">
                    <circle cx="65" cy="65" r="{radio}" fill="none" stroke="#e2e8f0" stroke-width="18" />
                    {segmentos}
                </g>
                <text x="65" y="61" text-anchor="middle" class="donut-total">{total}</text>
                <text x="65" y="78" text-anchor="middle" class="donut-label">hallazgos</text>
            </svg>
            <div class="donut-legend">{leyenda}</div>
        </div>
        """

    @classmethod
    def _grafico_barras_modulo(cls, datastore: DataStore) -> str:
        """Genera un gráfico de barras horizontal (HTML/CSS puro) por módulo."""
        conteos = cls._contar_por_modulo(datastore)
        if not conteos:
            return '<div class="chart-empty">Sin hallazgos que representar.</div>'

        maximo = max(c for _, c in conteos)
        filas = ""
        for modulo, cantidad in conteos:
            pct = round(100 * cantidad / maximo) if maximo else 0
            filas += f"""
                <div class="bar-row">
                    <span class="bar-label">{cls._esc(modulo)}</span>
                    <div class="bar-track">
                        <div class="bar-fill" style="width:{pct}%;"></div>
                    </div>
                    <span class="bar-value">{cantidad}</span>
                </div>"""
        return f'<div class="bar-chart">{filas}</div>'

    @classmethod
    def _panel_risk_score(cls, score: int, nivel: str, contenido_completo: str) -> str:
        """Panel destacado del score de riesgo global, con gauge circular."""
        if score >= 70:
            color = "#ef4444"
        elif score >= 40:
            color = "#f59e0b"
        else:
            color = "#16a34a"

        # El resto del texto (justificación y factores) se muestra debajo del gauge,
        # reutilizando el mismo conversor seguro de markdown ligero.
        cuerpo_html = cls._texto_insight_a_html(contenido_completo)
        radio = 52
        circunferencia = 2 * 3.14159265 * radio
        offset = circunferencia * (1 - score / 100)

        return f"""
        <div class="risk-panel">
            <figure class="risk-figure" aria-label="Score de riesgo: {score} sobre 100">
                <svg viewBox="0 0 140 140" class="risk-gauge-svg" role="img">
                    <circle cx="70" cy="70" r="{radio}" class="risk-gauge-track" />
                    <circle cx="70" cy="70" r="{radio}" class="risk-gauge-fill"
                        stroke="{color}" stroke-dasharray="{circunferencia:.2f}"
                        stroke-dashoffset="{offset:.2f}" />
                </svg>
                <div class="risk-gauge-numbers">
                    <span class="risk-score-big" style="color:{color};">{score}</span>
                    <span class="risk-score-max">/100</span>
                </div>
                <figcaption class="risk-nivel-badge" style="background:{color};">{cls._esc(nivel)}</figcaption>
            </figure>
            <div class="risk-detail">{cuerpo_html}</div>
        </div>
        """

    @classmethod
    def export(
        cls,
        datastore: DataStore,
        target: str,
        output_path: Path,
        insights: list | None = None,
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = datastore.summary()
        by_sev = summary.get("by_severity", {})
        target_esc = cls._esc(target)

        # Separamos el insight de risk_score (si existe y se puede parsear)
        # del resto, porque se muestra en un panel destacado aparte.
        insights = insights or []
        risk_insight = None
        risk_parseado = None
        otros_insights = []
        for insight in insights:
            if insight.type == "risk_score" and risk_parseado is None:
                parseo = cls._parsear_risk_score(insight.content)
                if parseo:
                    risk_insight = insight
                    risk_parseado = parseo
                    continue
            otros_insights.append(insight)

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe de Auditoría OSINT - {target_esc}</title>
    <style>
        :root {{
            --primary: #172554;
            --primary-light: #1e3a8a;
            --accent: #00cfff;
            --accent-secondary: #a855f7;
            --accent-soft: #e6faff;
            --border: #dbeafe;
            --bg-body: #ffffff;
            --bg-card: #ffffff;
            --text-dark: #172554;
            --text-muted: #64748b;

            --sev-high-bg: #fef2f2;
            --sev-high-text: #991b1b;
            --sev-high-border: #fecaca;

            --sev-med-bg: #fffbe3;
            --sev-med-text: #92400e;
            --sev-med-border: #fef08a;

            --sev-low-bg: #eff6ff;
            --sev-low-text: #1e40af;
            --sev-low-border: #bfdbfe;

            --sev-info-bg: #f1f5f9;
            --sev-info-text: #475569;
            --sev-info-border: #cbd5e1;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            font-family: Georgia, "Times New Roman", serif;
            background: #ffffff;
            color: var(--text-dark);
            margin: 0;
            padding: 3rem 1rem;
            line-height: 1.55;
        }}

        .report-paper {{
            max-width: 1150px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: 0 10px 30px rgba(23, 37, 84, 0.08);
            padding: 3.25rem;
        }}

        /* Header oficial */
        .header-bar {{
            position: relative;
            display: flex;
            justify-content: center;
            align-items: center;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 1.75rem;
            margin-bottom: 1.75rem;
            text-align: center;
            z-index: 1;
        }}

        .brand-title {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
        }}

        .brand-logo {{
            position: absolute;
            top: 0;
            left: 0;
            width: 86px;
            height: 86px;
            object-fit: contain;
        }}

        .header-title h1 {{
            margin: 0;
            font-size: 1.5rem;
            color: var(--primary);
            letter-spacing: 0;
            font-weight: 700;
        }}

        .header-title {{
            width: calc(100% - 220px);
            max-width: 760px;
            margin: 0 auto;
        }}

        .header-title .subtitle {{
            margin-top: 0.2rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .header-actions {{
            position: absolute;
            top: 0;
            right: 0;
            display: flex;
            flex-direction: column;
            align-items: stretch;
            gap: 0.5rem;
            width: 200px;
        }}

        .confidential-tag {{
            background-color: var(--accent-secondary);
            color: #ffffff;
            font-size: 0.62rem;
            font-weight: 800;
            padding: 0.24rem 0.35rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            text-align: center;
            white-space: nowrap;
        }}

        .btn-print {{
            background: #ffffff;
            border: 1px solid var(--accent);
            color: var(--text-dark);
            width: 100%;
            padding: 0.34rem 0.55rem;
            font-size: 0.78rem;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }}

        .btn-print:hover {{
            background: var(--accent-soft);
            border-color: var(--primary-light);
        }}

        /* Nota del chat CLI */
        .cli-note {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: var(--accent-soft);
            border: 1px solid #a5f3fc;
            color: var(--primary-light);
            border-radius: 8px;
            padding: 0.7rem 1rem;
            font-size: 0.85rem;
            margin-bottom: 2rem;
        }}

        .cli-note code {{
            background: rgba(30, 64, 175, 0.1);
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-weight: 700;
        }}

        /* Tarjetas Métricas KPI */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}

        .kpi-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}

        .kpi-card .label {{
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .kpi-card .val {{
            font-size: 2rem;
            font-weight: 800;
            margin-top: 0.2rem;
            color: var(--primary);
        }}

        /* Secciones */
        .section-title {{
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--primary);
            margin: 2.5rem 0 1.2rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            letter-spacing: 0.02em;
        }}

        /* Panel de Risk Score */
        .risk-panel {{
            display: grid;
            grid-template-columns: 220px 1fr;
            gap: 2rem;
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem 1.75rem;
            margin-bottom: 2.5rem;
            align-items: center;
        }}

        .risk-figure {{
            position: relative;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0;
            min-height: 220px;
        }}

        .risk-gauge-svg {{
            width: 160px;
            height: 160px;
            transform: rotate(-90deg);
        }}

        .risk-gauge-track, .risk-gauge-fill {{
            fill: none;
            stroke-width: 14;
        }}

        .risk-gauge-track {{
            stroke: #e5e7eb;
        }}

        .risk-gauge-fill {{
            stroke-linecap: round;
            transition: stroke-dashoffset 0.4s ease;
        }}

        .risk-gauge-numbers {{
            position: absolute;
            top: 78px;
            left: 0;
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: baseline;
            gap: 0.25rem;
            min-height: 2.6rem;
        }}

        .risk-score-big {{
            font-size: 2.4rem;
            font-weight: 800;
            line-height: 1;
        }}

        .risk-score-max {{
            font-size: 1rem;
            color: var(--text-muted);
            font-weight: 600;
        }}

        .risk-figure .risk-nivel-badge {{
            margin-top: 0.75rem;
            z-index: 1;
        }}

        .risk-nivel-badge {{
            color: white;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            letter-spacing: 0.05em;
        }}

        .risk-detail {{
            font-size: 0.92rem;
            color: #334155;
            line-height: 1.6;
            border-left: 1px solid var(--border);
            padding-left: 1.75rem;
        }}

        /* Gráficos: donut de severidad y barras por módulo */
        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .chart-card {{
            background: #fbfdfc;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
        }}

        .chart-card h4 {{
            margin: 0 0 1rem 0;
            font-size: 0.85rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}

        .chart-empty {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-style: italic;
        }}

        .donut-wrapper {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }}

        .donut-svg {{
            width: 130px;
            height: 130px;
            flex-shrink: 0;
        }}

        .donut-total {{
            font-size: 1.6rem;
            font-weight: 800;
            fill: var(--primary);
        }}

        .donut-label {{
            font-size: 0.6rem;
            fill: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .donut-legend {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            min-width: 150px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            font-size: 0.8rem;
        }}

        .legend-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-right: 0.5rem;
        }}

        .legend-label {{
            font-weight: 700;
            color: var(--text-dark);
        }}

        .legend-value {{
            color: var(--text-muted);
            margin-left: 0.75rem;
        }}

        .bar-chart {{
            display: flex;
            flex-direction: column;
            gap: 0.7rem;
        }}

        .bar-row {{
            display: grid;
            grid-template-columns: 90px 1fr 34px;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.8rem;
        }}

        .bar-label {{
            font-weight: 700;
            color: var(--text-dark);
            text-transform: capitalize;
        }}

        .bar-track {{
            background: #e2e8f0;
            border-radius: 4px;
            height: 10px;
            overflow: hidden;
        }}

        .bar-fill {{
            background: var(--accent);
            height: 100%;
            border-radius: 4px;
        }}

        .bar-value {{
            text-align: right;
            color: var(--text-muted);
            font-weight: 700;
        }}

        .insight-card {{
            background: #fbfdfc;
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent);
            border-radius: 4px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.2rem;
        }}

        .insight-card h3 {{
            margin: 0 0 0.6rem 0;
            font-size: 1rem;
            color: var(--primary);
        }}

        .insight-card .content {{
            font-size: 0.92rem;
            color: #334155;
            line-height: 1.6;
        }}

        .content p, .risk-detail p {{ margin: 0 0 0.8rem; }}
        .content p:last-child, .risk-detail p:last-child {{ margin-bottom: 0; }}
        .content h3, .content h4, .risk-detail h3, .risk-detail h4 {{
            color: var(--primary);
            margin: 1rem 0 0.45rem;
            font-family: "Trebuchet MS", sans-serif;
        }}
        .content h3, .risk-detail h3 {{ font-size: 1.05rem; }}
        .content h4, .risk-detail h4 {{ font-size: 0.95rem; }}
        .content ul, .content ol, .risk-detail ul, .risk-detail ol {{
            margin: 0.45rem 0 0.9rem;
            padding-left: 1.35rem;
        }}
        .content li, .risk-detail li {{ margin: 0.25rem 0; }}
        .content blockquote, .risk-detail blockquote {{
            border-left: 3px solid var(--accent);
            color: var(--text-muted);
            margin: 0.7rem 0;
            padding-left: 0.9rem;
        }}
        .content code, .risk-detail code {{
            background: var(--accent-soft);
            color: #115e59;
        }}
        .content a, .risk-detail a {{ color: var(--accent); font-weight: 700; }}

        /* Controles de Filtro */
        .filter-container {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            align-items: center;
        }}

        .filter-container input, .filter-container select {{
            padding: 0.45rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
        }}

        .filter-container input {{ flex: 1; }}

        /* Tabla de Evidencias */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}

        th {{
            background-color: var(--bg-body);
            color: var(--text-muted);
            font-weight: 700;
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 0.725rem;
            letter-spacing: 0.05em;
        }}

        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            color: var(--text-dark);
            vertical-align: top;
        }}

        tr:nth-child(even) td {{
            background-color: #fafafa;
        }}

        .badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.725rem;
            font-weight: 800;
            text-transform: uppercase;
            border: 1px solid transparent;
        }}

        .badge-high {{ background: var(--sev-high-bg); color: var(--sev-high-text); border-color: var(--sev-high-border); }}
        .badge-medium {{ background: var(--sev-med-bg); color: var(--sev-med-text); border-color: var(--sev-med-border); }}
        .badge-low {{ background: var(--sev-low-bg); color: var(--sev-low-text); border-color: var(--sev-low-border); }}
        .badge-info {{ background: var(--sev-info-bg); color: var(--sev-info-text); border-color: var(--sev-info-border); }}

        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f1f5f9;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.825rem;
            color: #0f172a;
            word-break: break-all;
        }}

        /* Ocultar elementos en la impresión a PDF */
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .report-paper {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
            .btn-print, .filter-container, .cli-note {{ display: none !important; }}
            .section-title {{ page-break-after: avoid; }}
            .risk-panel, .chart-card {{ page-break-inside: avoid; }}
            tr {{ page-break-inside: avoid; }}
        }}

        @media (max-width: 760px) {{
            body {{ padding: 1rem 0.5rem; }}
            .report-paper {{ padding: 1.25rem; border-radius: 8px; }}
            .header-bar {{ flex-direction: column; gap: 1rem; padding-top: 3.5rem; }}
            .brand-title {{ flex-direction: column; }}
            .header-title {{ width: 100%; max-width: none; }}
            .header-actions {{ top: 0; right: 0; align-items: flex-end; }}
            .kpi-grid, .charts-grid, .risk-panel {{ grid-template-columns: 1fr; }}
            .risk-detail {{ border-left: 0; border-top: 1px solid var(--border); padding: 1rem 0 0; }}
            .filter-container {{ flex-direction: column; align-items: stretch; }}
            table {{ display: block; overflow-x: auto; white-space: nowrap; }}
        }}
    </style>
</head>
<body>

    <div class="report-paper">
        <!-- Encabezado Oficial -->
        <div class="header-bar">
            <div class="header-title">
                <div class="brand-title">
                    <img class="brand-logo" src="assets/argosmind-logo.png" alt="ArgosMind">
                    <h1>Informe Técnico de Reconocimiento OSINT</h1>
                </div>
                <div class="subtitle">Objetivo auditado: <strong>{target_esc}</strong></div>
            </div>
            <div class="header-actions">
                <span class="confidential-tag">Confidencial / Uso Interno</span>
                <button class="btn-print" onclick="window.print()">Imprimir / Guardar a PDF</button>
            </div>
        </div>

        <div class="cli-note">
            ¿Quieres explorar estos hallazgos de forma conversacional?
            Ejecuta <code>poetry run osint chat {target_esc}</code> en tu terminal.
        </div>

        <!-- Tarjetas KPI -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="label">Total Hallazgos</div>
                <div class="val">{summary.get("total", 0)}</div>
            </div>
            <div class="kpi-card" style="border-top: 3px solid var(--sev-high-text);">
                <div class="label">Riesgo Alto</div>
                <div class="val" style="color: var(--sev-high-text);">{by_sev.get(Severity.HIGH, 0)}</div>
            </div>
            <div class="kpi-card" style="border-top: 3px solid var(--sev-med-text);">
                <div class="label">Riesgo Medio</div>
                <div class="val" style="color: var(--sev-med-text);">{by_sev.get(Severity.MEDIUM, 0)}</div>
            </div>
            <div class="kpi-card" style="border-top: 3px solid var(--sev-low-text);">
                <div class="label">Bajo / Info</div>
                <div class="val" style="color: var(--sev-low-text);">{by_sev.get(Severity.LOW, 0) + by_sev.get(Severity.INFO, 0)}</div>
            </div>
        </div>
"""

        # Panel destacado de Risk Score (si la IA lo generó y se pudo parsear)
        if risk_insight and risk_parseado:
            score, nivel = risk_parseado
            html_content += '<div class="section-title">Score de Riesgo Global</div>'
            html_content += cls._panel_risk_score(score, nivel, risk_insight.content)

        # Gráficos: distribución por severidad y por módulo
        html_content += f"""
        <div class="section-title">Resumen Visual</div>
        <div class="charts-grid">
            <div class="chart-card">
                <h4>Distribución por Severidad</h4>
                {cls._grafico_donut_severidad(by_sev)}
            </div>
            <div class="chart-card">
                <h4>Hallazgos por Módulo</h4>
                {cls._grafico_barras_modulo(datastore)}
            </div>
        </div>
        """

        # Resto de insights de IA (resumen ejecutivo, correlaciones, dorks...)
        if otros_insights:
            html_content += '<div class="section-title">Análisis de Inteligencia Asistida (IA)</div>'
            for insight in otros_insights:
                html_content += f"""
                <div class="insight-card">
                    <h3>{cls._esc(insight.title)}</h3>
                    <div class="content">{cls._texto_insight_a_html(insight.content)}</div>
                </div>
                """

        # Tabla de Hallazgos
        html_content += f"""
        <div class="section-title">Evidencias e Infraestructura Identificada</div>

        <div class="filter-container">
            <input type="text" id="searchInput" onkeyup="filtrarTabla()" placeholder="Buscar por valor o dominio...">
            <select id="sevFilter" onchange="filtrarTabla()">
                <option value="">Todas las Severidades</option>
                <option value="high">HIGH</option>
                <option value="medium">MEDIUM</option>
                <option value="low">LOW</option>
                <option value="info">INFO</option>
            </select>
        </div>

        <table id="findingsTable">
            <thead>
                <tr>
                    <th style="width: 10%;">Severidad</th>
                    <th style="width: 12%;">Módulo</th>
                    <th style="width: 20%;">Categoría</th>
                    <th>Valor / Recurso Expuesto</th>
                    <th style="width: 15%;">Fuente</th>
                </tr>
            </thead>
            <tbody>
        """

        for f in datastore:
            valor_limpio = cls._esc(cls._limpiar_valor(f.value))
            sev_class = f"badge-{f.severity}"
            html_content += f"""
                <tr data-sev="{cls._esc(f.severity)}">
                    <td><span class="badge {sev_class}">{cls._esc(f.severity)}</span></td>
                    <td><strong>{cls._esc(f.module)}</strong></td>
                    <td>{cls._esc(f.type)}</td>
                    <td><code>{valor_limpio}</code></td>
                    <td style="color: var(--text-muted); font-size: 0.8rem;">{cls._esc(f.source or '-')}</td>
                </tr>
            """

        html_content += """
            </tbody>
        </table>
    </div>

    <script>
        // Filtros de la tabla de evidencias
        function filtrarTabla() {
            const search = document.getElementById("searchInput").value.toLowerCase();
            const sev = document.getElementById("sevFilter").value.toLowerCase();
            const rows = document.querySelectorAll("#findingsTable tbody tr");

            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                const rowSev = row.getAttribute("data-sev");
                const matchText = text.includes(search);
                const matchSev = !sev || rowSev === sev;

                row.style.display = (matchText && matchSev) ? "" : "none";
            });
        }
    </script>
</body>
</html>
        """

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
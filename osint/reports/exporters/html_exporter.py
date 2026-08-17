import json
import re
from pathlib import Path

from osint.core.datastore import DataStore, Severity


class HTMLExporter:
    """
    Genera un informe HTML técnico de nivel ejecutivo con un Widget de IA 
    interactivo embebido para consultar los hallazgos en el navegador.
    """

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

    @classmethod
    def export(
        cls,
        datastore: DataStore,
        target: str,
        output_path: Path,
        insights: list | None = None,
        groq_api_key: str | None = None,
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = datastore.summary()
        by_sev = summary.get("by_severity", {})

        # Serializamos los hallazgos e insights a JSON para el widget de IA en JS
        findings_raw = [
            {
                "module": f.module,
                "type": f.type,
                "value": cls._limpiar_valor(f.value),
                "severity": f.severity,
                "source": f.source or "-",
            }
            for f in datastore
        ]
        
        insights_raw = [
            {
                "title": i.title,
                "content": i.content,
                "severity": i.severity,
            }
            for i in (insights or [])
        ]

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe de Auditoría OSINT - {target}</title>
    <style>
        :root {{
            --primary: #0f172a;
            --primary-light: #1e293b;
            --accent: #2563eb;
            --border: #e2e8f0;
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-dark: #0f172a;
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
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-dark);
            margin: 0;
            padding: 2.5rem 1rem;
            line-height: 1.5;
        }}

        .report-paper {{
            max-width: 1150px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05);
            padding: 3rem;
        }}

        /* Header oficial */
        .header-bar {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        .brand-title {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .brand-logo {{
            background: var(--primary);
            color: white;
            font-weight: 800;
            font-size: 1.25rem;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            letter-spacing: 0.05em;
        }}

        .header-title h1 {{
            margin: 0;
            font-size: 1.6rem;
            color: var(--primary);
            letter-spacing: -0.02em;
        }}

        .header-title .subtitle {{
            margin-top: 0.2rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .header-actions {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.5rem;
        }}

        .confidential-tag {{
            background-color: #ef4444;
            color: #ffffff;
            font-size: 0.7rem;
            font-weight: 800;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .btn-print {{
            background: #ffffff;
            border: 1px solid var(--border);
            color: var(--text-dark);
            padding: 0.4rem 0.9rem;
            font-size: 0.85rem;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .btn-print:hover {{
            background: var(--bg-body);
            border-color: var(--text-muted);
        }}

        /* Tarjetas Métricas KPI */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}

        .kpi-card {{
            background: var(--bg-body);
            border: 1px solid var(--border);
            border-radius: 6px;
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
        }}

        .insight-card {{
            background: var(--bg-body);
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
            white-space: pre-line;
            line-height: 1.6;
        }}

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

        /* =======================================================
           WIDGET DE CHAT IA FLOTANTE EMBEBIDO EN NAVEGADOR
           ======================================================= */
        #ai-chat-widget {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 9999;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}

        #ai-chat-toggle {{
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 30px;
            padding: 0.8rem 1.4rem;
            font-weight: 700;
            font-size: 0.9rem;
            cursor: pointer;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.25);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: transform 0.2s;
        }}

        #ai-chat-toggle:hover {{
            transform: translateY(-2px);
            background: var(--primary-light);
        }}

        #ai-chat-box {{
            display: none;
            width: 380px;
            height: 520px;
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
            flex-direction: column;
            overflow: hidden;
            position: absolute;
            bottom: 60px;
            right: 0;
        }}

        .chat-header {{
            background: var(--primary);
            color: white;
            padding: 0.8rem 1rem;
            font-weight: 700;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .chat-header button {{
            background: transparent;
            border: none;
            color: white;
            font-size: 1.1rem;
            cursor: pointer;
        }}

        .chat-config {{
            background: var(--bg-body);
            padding: 0.5rem 0.8rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            gap: 0.5rem;
            font-size: 0.75rem;
        }}

        .chat-config select, .chat-config input {{
            font-size: 0.75rem;
            padding: 0.2rem 0.4rem;
            border: 1px solid var(--border);
            border-radius: 4px;
        }}

        .chat-messages {{
            flex: 1;
            padding: 0.8rem;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
            font-size: 0.85rem;
            background: #fafafa;
        }}

        .chat-msg {{
            padding: 0.6rem 0.8rem;
            border-radius: 8px;
            max-width: 85%;
            line-height: 1.4;
            white-space: pre-wrap;
        }}

        .chat-msg.user {{
            background: var(--accent);
            color: white;
            align-self: flex-end;
            border-bottom-right-radius: 2px;
        }}

        .chat-msg.assistant {{
            background: #ffffff;
            color: var(--text-dark);
            border: 1px solid var(--border);
            align-self: flex-start;
            border-bottom-left-radius: 2px;
        }}

        .chat-input-area {{
            padding: 0.6rem;
            border-top: 1px solid var(--border);
            background: white;
            display: flex;
            gap: 0.4rem;
        }}

        .chat-input-area input {{
            flex: 1;
            padding: 0.5rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
        }}

        .chat-input-area button {{
            background: var(--primary);
            color: white;
            border: none;
            padding: 0.5rem 0.8rem;
            border-radius: 6px;
            font-weight: 700;
            cursor: pointer;
        }}

        /* Ocultar elementos en la impresión a PDF */
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .report-paper {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
            .btn-print, #ai-chat-widget, .filter-container {{ display: none !important; }}
            .section-title {{ page-break-after: avoid; }}
            tr {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>

    <div class="report-paper">
        <!-- Encabezado Oficial -->
        <div class="header-bar">
            <div>
                <div class="brand-title">
                    <span class="brand-logo">ARGOSMIND</span>
                    <h1>Informe Técnico de Reconocimiento OSINT</h1>
                </div>
                <div class="subtitle">Objetivo auditado: <strong>{target}</strong></div>
            </div>
            <div class="header-actions">
                <span class="confidential-tag">Confidencial / Uso Interno</span>
                <button class="btn-print" onclick="window.print()">Imprimir / Guardar a PDF</button>
            </div>
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

        # Añadimos los Insights de la IA si existen
        if insights:
            html_content += '<div class="section-title">Análisis de Inteligencia Asistida (IA)</div>'
            for insight in insights:
                html_content += f"""
                <div class="insight-card">
                    <h3>{insight.title}</h3>
                    <div class="content">{insight.content}</div>
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
            valor_limpio = cls._limpiar_valor(f.value)
            sev_class = f"badge-{f.severity}"
            html_content += f"""
                <tr data-sev="{f.severity}">
                    <td><span class="badge {sev_class}">{f.severity}</span></td>
                    <td><strong>{f.module}</strong></td>
                    <td>{f.type}</td>
                    <td><code>{valor_limpio}</code></td>
                    <td style="color: var(--text-muted); font-size: 0.8rem;">{f.source or '-'}</td>
                </tr>
            """

        html_content += f"""
            </tbody>
        </table>
    </div>

    <!-- WIDGET DE CHAT IA EMBEBIDO -->
    <div id="ai-chat-widget">
        <button id="ai-chat-toggle" onclick="toggleChat()">
            🤖 Consultar Asistente IA
        </button>
        <div id="ai-chat-box">
            <div class="chat-header">
                <span>ArgosMind Assistant</span>
                <button onclick="toggleChat()">✕</button>
            </div>
            <div class="chat-config">
                <select id="providerSelect" onchange="actualizarProveedor()">
                    <option value="ollama">Ollama (Local)</option>
                    <option value="groq">Groq Cloud (API)</option>
                </select>
                <input type="password" id="apiKeyInput" placeholder="Groq API Key (opcional)" style="display:none; flex:1;">
            </div>
            <div class="chat-messages" id="chatMessages">
                <div class="chat-msg assistant">¡Hola! Soy la IA de ArgosMind. Puedes hacerme cualquier pregunta técnica sobre los datos recopilados en este informe de {target}.</div>
            </div>
            <div class="chat-input-area">
                <input type="text" id="chatInput" placeholder="Escribe tu consulta..." onkeypress="handleKeyPress(event)">
                <button onclick="enviarMensaje()">Enviar</button>
            </div>
        </div>
    </div>

    <script>
        // Datos e integración IA
        const TARGET = "{target}";
        const GROQ_KEY_CONFIG = "{groq_api_key or ''}";        
        const FINDINGS_DATA = {json.dumps(findings_raw, ensure_ascii=False)};
        const INSIGHTS_DATA = {json.dumps(insights_raw, ensure_ascii=False)};

        // Filtros de la tabla
        function filtrarTabla() {{
            const search = document.getElementById("searchInput").value.toLowerCase();
            const sev = document.getElementById("sevFilter").value.toLowerCase();
            const rows = document.querySelectorAll("#findingsTable tbody tr");

            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                const rowSev = row.getAttribute("data-sev");
                const matchText = text.includes(search);
                const matchSev = !sev || rowSev === sev;

                row.style.display = (matchText && matchSev) ? "" : "none";
            }});
        }}

        // Inicialización del Widget de Chat IA
        window.addEventListener("DOMContentLoaded", () => {{
            const provSelect = document.getElementById("providerSelect");
            
            if (GROQ_KEY_CONFIG && GROQ_KEY_CONFIG.trim() !== "") {{
                provSelect.value = "groq";
            }}
            actualizarProveedor();
        }});

        // Lógica del Chat IA
        function toggleChat() {{
            const box = document.getElementById("ai-chat-box");
            box.style.display = (box.style.display === "flex") ? "none" : "flex";
        }}

        function actualizarProveedor() {{
            const prov = document.getElementById("providerSelect").value;
            const keyInput = document.getElementById("apiKeyInput");

            // Si eligen Groq y NO tenemos clave cargada desde el YAML, mostramos la casilla
            if (prov === "groq" && (!GROQ_KEY_CONFIG || GROQ_KEY_CONFIG.trim() === "")) {{
                keyInput.style.display = "block";
            }} else {{
                keyInput.style.display = "none";
            }}
        }}

        function handleKeyPress(e) {{
            if (e.key === "Enter") enviarMensaje();
        }}

        async function enviarMensaje() {{
            const input = document.getElementById("chatInput");
            const text = input.value.trim();
            if (!text) return;

            const msgContainer = document.getElementById("chatMessages");

            // Mensaje del usuario
            const userDiv = document.createElement("div");
            userDiv.className = "chat-msg user";
            userDiv.innerText = text;
            msgContainer.appendChild(userDiv);
            input.value = "";
            msgContainer.scrollTop = msgContainer.scrollHeight;

            // Placeholder de respuesta
            const astDiv = document.createElement("div");
            astDiv.className = "chat-msg assistant";
            astDiv.innerText = "Pensando...";
            msgContainer.appendChild(astDiv);
            msgContainer.scrollTop = msgContainer.scrollHeight;

            const provider = document.getElementById("providerSelect").value;
            const manualKey = document.getElementById("apiKeyInput").value.trim();
            const apiKey = GROQ_KEY_CONFIG || manualKey;

            const systemPrompt = `Eres el asistente de ciberseguridad de ArgosMind.
            REGLAS STRICTAS Y BARRERAS DE SEGURIDAD:
            1. Responde ÚNICAMENTE a preguntas sobre el informe OSINT del objetivo '${target}'.
            2. Datos de hallazgos disponibles: ${{JSON.stringify(FINDINGS_DATA)}}
            3. Si el usuario pregunta algo no relacionado con este informe, rechaza responder con esta frase exacta: "Esta consulta no está relacionada con el informe OSINT analizado."`;

            try {{
                if (provider === "ollama") {{
                    const res = await fetch("http://localhost:11434/api/generate", {{
                        method: "POST",
                        headers: {{ "Content-Type": "application/json" }},
                        body: JSON.stringify({{
                            model: "llama3.1",
                            prompt: `${{systemPrompt}}\n\nPregunta: ${{text}}`,
                            stream: false
                        }})
                    }});
                    const data = await res.json();
                    astDiv.innerText = data.response || "No se obtuvo respuesta de Ollama.";
                }} else {{
                    if (!apiKey) {{
                        astDiv.innerText = "No se ha encontrado ninguna API Key de Groq en config.yaml ni introducida manualmente.";
                        return;
                    }}
                    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {{
                        method: "POST",
                        mode: "cors",
                        headers: {{
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${{apiKey}}`
                        }},
                        body: JSON.stringify({{
                            model: "llama-3.3-70b-versatile",
                            messages: [
                                {{ role: "system", content: systemPrompt }},
                                {{ role: "user", content: text }}
                            ]
                        }})
                    }});
                    const data = await res.json();
                    if (data.choices && data.choices[0]) {{
                        astDiv.innerText = data.choices[0].message.content;
                    }} else {{
                        astDiv.innerText = "Error en respuesta de Groq: " + (data.error?.message || "Consulta rechazada.");
                    }}
                }}
            }} catch (err) {{
                astDiv.innerText = "Error de conexión al procesar la solicitud: " + err.message;
            }}

            msgContainer.scrollTop = msgContainer.scrollHeight;
        }}
    </script>
</body>
</html>
        """

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
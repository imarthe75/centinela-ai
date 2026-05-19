import streamlit as st
import psycopg2
import pandas as pd
import os
import plotly.express as px

# --- Configuración de Autenticación y Marca ---
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

def login():
    st.session_state.authenticated = True

def logout():
    st.session_state.authenticated = False
    # Redirección global para cerrar sesión en Authentik también
    st.markdown(f'<meta http-equiv="refresh" content="0; url=https://arquitectura.casmart.internal/application/o/centinela-ai/end-session/?post_logout_redirect_uri=https://arquitectura.casmart.internal/centinela/">', unsafe_allow_html=True)
    st.stop()

# Configuración de Base de Datos
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "casmarts-core-db-primary"),
    "database": os.getenv("DB_NAME", "casmarts_security"),
    "user": os.getenv("DB_USER", "admin"),
    "password": os.getenv("DB_PASSWORD", "casmarts_secure_db_pwd_2026")
}

BRAND_COLORS = {
    "metallic_blue": "#002A4C",
    "silver": "#E2E8F0",
    "white": "#FFFFFF"
}

def get_data(query):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Error al obtener datos: {e}")
        return pd.DataFrame()

# Estilos Premium CASMARTS (Estilo ConsultaRPP)
st.set_page_config(page_title="Centinela-AI Dashboard", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&family=Open+Sans:wght@400;600&display=swap');
    
    .stApp {
        background: radial-gradient(circle at center, #003a66 0%, #002A4C 100%);
        font-family: 'Open Sans', sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: white;
        border-right: 1px solid #e2e8f0;
    }
    .login-card {
        background: white;
        padding: 3.5rem;
        border-radius: 40px;
        width: 100%;
        max-width: 448px;
        margin: 5rem auto;
        text-align: center;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }
    h1, h2, h3 {
        font-family: 'Montserrat', sans-serif !important;
    }
    .stButton > button {
        background-color: #002A4C !important;
        color: white !important;
        border-radius: 12px !important;
        padding: 0.75rem 1.5rem !important;
        font-weight: 700 !important;
        border: none !important;
        box-shadow: 0 10px 15px -3px rgba(0, 42, 76, 0.3) !important;
    }
    </style>
    """, unsafe_allow_html=True)

if not st.session_state.authenticated:
    st.markdown(f"""
        <div class="login-card">
            <div style="display: flex; justify-content: center; margin-bottom: 1.5rem;">
                <div style="position: relative;">
                    <img src="https://arquitectura.casmart.internal/static/dist/assets/icons/apple-touch-icon.png" width="96" style="filter: drop-shadow(0 4px 6px rgba(0,0,0,0.1));">
                    <div style="position: absolute; top: -8px; left: -8px; right: -8px; bottom: -8px; border: 1px solid rgba(96, 165, 250, 0.3); border-radius: 50%; pointer-events: none;"></div>
                </div>
            </div>
            <h1 style="color:#002A4C; font-size: 1.875rem; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: -0.025em;">Centinela-AI</h1>
            <p style="color:#BDC3C7; font-weight:700; text-transform:uppercase; letter-spacing:0.4em; font-size:0.75rem; margin-bottom: 2.5rem;">Centro de Mando de Seguridad</p>
        </div>
    """, unsafe_allow_html=True)
    
    col_l1, col_l2, col_l3 = st.columns([1,2,1])
    with col_l2:
        # Botón estilizado mediante el estilo definido arriba
        if st.button("🛡️ INICIAR SESIÓN CON CASMARTS ID", use_container_width=True, type="primary"):
            login()
            st.rerun()
        
        st.markdown("""
            <div style="text-align:center; margin-top:1.5rem">
                <a href="https://arquitectura.casmart.internal/if/flow/password-recovery/" style="color:rgba(0,42,76,0.6); text-decoration:none; font-size:0.75rem; font-weight:500">
                    ¿Olvidaste tu contraseña?
                </a>
            </div>
            <div style="margin-top: 3rem; text-align: center; border-top: 1px solid rgba(226, 232, 240, 0.5); pt: 1.5rem;">
                <p style="font-size: 9px; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4em; padding-top: 1.5rem;">
                    Powered by Casmarts AI Core
                </p>
            </div>
        """, unsafe_allow_html=True)
    st.stop()

# --- Dashboard Principal (Solo si está autenticado) ---
with st.sidebar:
    st.image("https://arquitectura.casmart.internal/static/dist/assets/icons/apple-touch-icon.png", width=100)
    st.markdown("### Usuario: Admin")
    if st.button("Cerrar Sesión"):
        logout()

st.divider()

# --- Sección de Métricas ---
col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)

total_vulns = get_data("SELECT COUNT(*) FROM public.vulnerability_log")
total_count = total_vulns.iloc[0,0] if not total_vulns.empty else 0

pending_rem = get_data("SELECT COUNT(*) FROM public.remediation_history WHERE approval_token = 'PENDING_APPROVAL'")
pending_count = pending_rem.iloc[0,0] if not pending_rem.empty else 0

pending_analysis = get_data("""
    SELECT COUNT(*) 
    FROM public.vulnerability_log v 
    LEFT JOIN public.remediation_history r ON v.id = r.vuln_id 
    WHERE r.id IS NULL
""")
analysis_count = pending_analysis.iloc[0,0] if not pending_analysis.empty else 0

critical_vulns = get_data("SELECT COUNT(*) FROM public.vulnerability_log WHERE severity = 'CRITICAL'")
critical_count = critical_vulns.iloc[0,0] if not critical_vulns.empty else 0

high_vulns = get_data("SELECT COUNT(*) FROM public.vulnerability_log WHERE severity = 'HIGH'")
high_count = high_vulns.iloc[0,0] if not high_vulns.empty else 0

col_m1.metric("Hallazgos Totales", total_count)
col_m2.metric("Cola de IA 🤖", analysis_count)
col_m3.metric("Riesgos Críticos 🚨", critical_count)
col_m4.metric("Riesgos Altos ⚠️", high_count)
col_m5.metric("Listos para Aprobar", pending_count)

st.divider()

# --- Sección de Gráficos y Análisis ---
col_g1, col_g2 = st.columns(2)

with col_g1:
    st.subheader("📊 Distribución de Riesgos")
    df_sev = get_data("SELECT severity, COUNT(*) as total FROM public.vulnerability_log GROUP BY severity")
    if not df_sev.empty:
        fig = px.pie(df_sev, values='total', names='severity', hole=.3,
                     color='severity', color_discrete_map={'CRITICAL':'#C53030', 'HIGH':'#DD6B20', 'MEDIUM':'#D69E2E', 'LOW':'#3182CE'})
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True)

with col_g2:
    st.subheader("📈 Tendencia de Detecciones")
    df_trend = get_data("SELECT detected_at::date as fecha, COUNT(*) as total FROM public.vulnerability_log GROUP BY fecha ORDER BY fecha ASC")
    if not df_trend.empty:
        st.line_chart(df_trend.set_index('fecha'), color=BRAND_COLORS['metallic_blue'])

st.divider()

# Barra lateral para Registro de Activos
with st.sidebar:
    st.header("➕ Registrar Nuevo Activo")
    asset_name = st.text_input("Nombre del Activo (ej: Servidor Producción)")
    asset_type = st.selectbox("Tipo", ["IP", "URL", "Repository", "Container", "Database (SQL)", "NoSQL", "Cache/Memory"])
    endpoint = st.text_input("Endpoint (IP, URL o Ruta de Repo)")
    
    if st.button("Registrar Activo"):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, %s, %s)",
                (asset_name, asset_type, endpoint)
            )
            conn.commit()
            cur.close()
            conn.close()
            st.success(f"Activo {asset_name} registrado correctamente.")
        except Exception as e:
            st.error(f"Error al registrar: {e}")

col1, col2 = st.columns(2)

with col1:
    st.subheader("📦 Inventario de Infraestructura")
    df_infra = get_data("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory")
    st.dataframe(df_infra, use_container_width=True)

with col2:
    st.subheader("🚨 Últimas Vulnerabilidades")
    
    # Filtros Combinados
    f_col1, f_col2 = st.columns(2)
    
    with f_col1:
        sev_filter = st.selectbox("Filtrar por Severidad", ["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    
    with f_col2:
        asset_list = ["Todos"] + df_infra['asset_name'].tolist() if not df_infra.empty else ["Todos"]
        asset_filter = st.selectbox("Filtrar por Activo", asset_list)
    
    query_vulns = """
        SELECT i.asset_name, v.cve_id, v.severity, v.detected_at 
        FROM public.vulnerability_log v 
        JOIN public.infra_inventory i ON v.asset_id = i.id 
    """
    where_clauses = []
    if sev_filter != "Todas":
        where_clauses.append(f"v.severity = '{sev_filter}'")
    if asset_filter != "Todos":
        where_clauses.append(f"i.asset_name = '{asset_filter}'")
        
    if where_clauses:
        query_vulns += " WHERE " + " AND ".join(where_clauses)
        
    query_vulns += " ORDER BY v.detected_at DESC LIMIT 50"
    
    df_vulns = get_data(query_vulns)
    st.dataframe(df_vulns, use_container_width=True)

st.divider()

col3, col4 = st.columns([1, 2])

with col3:
    st.subheader("⚔️ Ataques en Tiempo Real (Falco)")
    df_falco = get_data("""
        SELECT priority as Prioridad, rule_name as Regla, detected_at as Detectado_En 
        FROM public.runtime_alerts 
        ORDER BY detected_at DESC 
        LIMIT 20
    """)
    st.dataframe(df_falco, use_container_width=True)

with col4:
    st.subheader("🛠️ Cola de Remediación (Pendiente de Aprobación)")
df_rem = get_data("""
    SELECT r.id, i.asset_name, i.endpoint, v.cve_id, r.script_path, r.approval_token, r.can_automate,
           v.executive_summary, v.business_impact, v.developer_steps
    FROM public.remediation_history r
    JOIN public.vulnerability_log v ON r.vuln_id = v.id
    JOIN public.infra_inventory i ON v.asset_id = i.id
    WHERE r.approval_token = 'PENDING_APPROVAL'
""")

if not df_rem.empty:
    for index, row in df_rem.iterrows():
        with st.expander(f"Solución para {row['cve_id']} en {row['asset_name']}"):
            st.markdown(f"**📍 Ubicación del Activo:** `{row['endpoint']}`")
            
            if not row['can_automate']:
                st.error("⚠️ **Remediación Manual Requerida:** Este activo se encuentra en un entorno que no permite ejecución automática (ej: IP externa o servidor remoto).")
            
            st.markdown("### 👔 Reporte de Auditoría Senior")
            
            # Intentamos extraer el formato estructurado si existe
            summary = row['executive_summary']
            if "**Riesgo:**" in summary and "**Evidencia:**" in summary:
                # Ya viene formateado desde centinela.py
                st.info(summary)
            else:
                st.info(f"**Riesgo Detectado:** {summary}")
            
            st.markdown("### ⚠️ Impacto en el Negocio")
            st.warning(row['business_impact'])
            
            st.markdown("### 👨‍💻 Acción de Remediación")
            st.success(row['developer_steps'])
            
            st.divider()
            st.markdown("### 📜 Script de Remediación")
            try:
                with open(row['script_path'], 'r') as f:
                    script_content = f.read()
                st.code(script_content, language="bash")
            except Exception as e:
                st.error(f"No se pudo leer el script: {e}")
            
            if row['can_automate']:
                if st.button(f"🚀 Aprobar y Ejecutar {row['id']}"):
                    try:
                        conn = psycopg2.connect(**DB_CONFIG)
                        cur = conn.cursor()
                        cur.execute("UPDATE public.remediation_history SET approval_token = 'APPROVED' WHERE id = %s", (row['id'],))
                        conn.commit()
                        cur.close()
                        conn.close()
                        st.success(f"Remediación {row['id']} aprobada para ejecución automática.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error al aprobar: {e}")
            else:
                if st.button(f"✅ Marcar como Corregido (Manual) {row['id']}"):
                    try:
                        conn = psycopg2.connect(**DB_CONFIG)
                        cur = conn.cursor()
                        cur.execute("UPDATE public.remediation_history SET approval_token = 'COMPLETED', executed_bool = True, executed_at = NOW() WHERE id = %s", (row['id'],))
                        cur.execute("UPDATE public.vulnerability_log SET status = 'RESOLVED' WHERE id = (SELECT vuln_id FROM public.remediation_history WHERE id = %s)", (row['id'],))
                        conn.commit()
                        cur.close()
                        conn.close()
                        st.success(f"Vulnerabilidad {row['id']} marcada como corregida.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error al actualizar: {e}")
else:
    st.info("No hay remediaciones pendientes. El sistema está seguro.")

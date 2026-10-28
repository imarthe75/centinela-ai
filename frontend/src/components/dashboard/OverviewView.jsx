// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, CheckCircle2, Code2, Gauge, Globe, Info, Server, ShieldAlert, ShieldCheck, Target, Users, Zap } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, RadialBar, RadialBarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import MapChart from '../MapChart'
import { useDashboard } from './DashboardContext'
import { MetricCard, SEV_BADGE_CLS, SEV_LABEL_ES, normSev } from './shared'

export default function OverviewView() {
  const { cmmiReport, dailyDetections, dashboardCharts, filteredAlerts, handleInvestigate, mapData, riskData, roiStats, setCurrentView, setSeverityFilter, setSoarAssetCategoryFilter, setSoarCategoryFilter, severityByCategory, severityFilter, stats, tops, vulnStats } = useDashboard()
  return (
<>
              {/* Global KPIs -- métricas que no se dividen por infra/código (identidades, alertas
                  de runtime, cumplimiento fleet-wide, cola de remediación). Reorganizado
                  2026-08-14 a petición del usuario: las métricas de vulnerabilidades ahora viven
                  en 2 grupos claramente etiquetados (Infraestructura / Código) más abajo, en vez
                  de mezcladas en una sola fila sin distinción. */}
              <div className="grid grid-cols-2 lg:grid-cols-6 gap-4 mb-4">
                <MetricCard
                    label="Usuarios Activos"
                    value={stats?.users || 0}
                    icon={<Users size={20} />}
                    color="text-[#06B6D4]"
                    sub="Sincronizado CDMX"
                    onClick={() => setCurrentView('itdr')}
                    title="Ver gestión de identidades y telemetría ITDR (Haz clic para ir)"
                />
                <MetricCard 
                    label="Activos / Endpoints" 
                    value={stats?.endpoints || 0} 
                    icon={<Server size={20} />} 
                    color="text-emerald-400" 
                    sub={`${stats?.online_endpoints || 0} En línea • ${stats?.offline_endpoints || 0} Offline`}
                    onClick={() => setCurrentView('inventory')}
                    title={`Total de Activos: ${stats?.endpoints || 0}. Haz clic para ir.`}
                />
                <MetricCard
                    label="Cumplimiento ISO 27001"
                    value={vulnStats?.iso_compliance_percentage != null ? `${vulnStats.iso_compliance_percentage}%` : '—'}
                    icon={<ShieldCheck size={20} />}
                    color="text-emerald-400"
                    sub="ISO 27001 / ISO 25010"
                    onClick={() => setCurrentView('inventory')}
                    title="Porcentaje real de controles ISO 27001/25010 sin violaciones activas en toda la flota"
                />
                <MetricCard
                    label="Benchmark CMMI v3.0"
                    value={cmmiReport.overall_cmmi_compliance_rate != null ? `${cmmiReport.overall_cmmi_compliance_rate}%` : '—'}
                    icon={<CheckCircle2 size={20} />}
                    color="text-indigo-400"
                    sub={`${cmmiReport.total_assets_audited || 0} activos auditados en vivo`}
                    onClick={() => setCurrentView('inventory')}
                    title="Promedio real de cumplimiento CMMI v3.0 (CAR/PQA/CM/MC/VV -- las 5 áreas que este escáner puede evidenciar de código/historial de escaneo) sobre todos los activos auditados"
                />
                <MetricCard 
                    label="Alertas en Tiempo Real" 
                    value={stats?.alerts || 0} 
                    icon={<AlertTriangle size={20} />} 
                    color="text-red-400" 
                    sub={`${vulnStats?.critical || 0} Críticas activas`}
                    highlight
                    onClick={() => setCurrentView('threat-hunting')}
                    title="Ver búsqueda de amenazas y log maestro en tiempo real (Haz clic para ir)"
                />
                <MetricCard
                    label="Remediación con IA"
                    value={vulnStats?.pending_ia || 0}
                    icon={<Zap size={20} />}
                    color="text-[#06B6D4]"
                    sub="En cola de análisis"
                    onClick={() => setCurrentView('soar')}
                    title="Ver parches automáticos e IA SOAR (Haz clic para ir)"
                />
              </div>

              {/* Vulnerabilidades por categoría -- reorganizado 2026-08-14 a petición del usuario
                  en 2 grupos claramente etiquetados (Infraestructura / Código), cada uno con su
                  par Real/Informativo, en vez de una sola fila mixta sin distinción visual. */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
                <div className="bg-[#1E293B]/50 border border-slate-800 rounded-[24px] p-4">
                  <p className="text-[11px] font-black text-orange-400 uppercase tracking-widest mb-3 flex items-center gap-1.5"><Server size={12} /> Infraestructura</p>
                  <div className="grid grid-cols-2 gap-4">
                    <MetricCard
                        label="Vulnerabilidades"
                        value={vulnStats?.infra_vulnerabilities || 0}
                        icon={<ShieldAlert size={20} />}
                        color="text-orange-400"
                        sub="Hallazgos reales"
                        onClick={() => { setSoarCategoryFilter('VULNERABILITY'); setSoarAssetCategoryFilter('INFRA'); setCurrentView('soar') }}
                        title="Vulnerabilidades de seguridad reales sobre infraestructura (servidores, bases de datos). Haz clic para ver filtrado."
                    />
                    <MetricCard
                        label="Informativos"
                        value={vulnStats?.infra_informational || 0}
                        icon={<Info size={20} />}
                        color="text-slate-400"
                        sub="Auditorías / marcadores"
                        onClick={() => { setSoarCategoryFilter('INFORMATIONAL'); setSoarAssetCategoryFilter('INFRA'); setCurrentView('soar') }}
                        title="Hallazgos informativos sobre infraestructura: marcadores de auditoría (CIS Benchmarks, escaneos completados) -- no son vulnerabilidades de seguridad. Haz clic para ver filtrado."
                    />
                  </div>
                </div>
                <div className="bg-[#1E293B]/50 border border-slate-800 rounded-[24px] p-4">
                  <p className="text-[11px] font-black text-amber-400 uppercase tracking-widest mb-3 flex items-center gap-1.5"><Code2 size={12} /> Código</p>
                  <div className="grid grid-cols-2 gap-4">
                    <MetricCard
                        label="Vulnerabilidades"
                        value={vulnStats?.code_vulnerabilities || 0}
                        icon={<ShieldAlert size={20} />}
                        color="text-amber-400"
                        sub="Hallazgos reales"
                        onClick={() => { setSoarCategoryFilter('VULNERABILITY'); setSoarAssetCategoryFilter('CODE'); setCurrentView('soar') }}
                        title="Vulnerabilidades de seguridad reales sobre código fuente (SAST/SCA/DAST de repos GitLab). Haz clic para ver filtrado."
                    />
                    <MetricCard
                        label="Informativos"
                        value={vulnStats?.code_informational || 0}
                        icon={<Info size={20} />}
                        color="text-slate-400"
                        sub="Calidad de código"
                        onClick={() => { setSoarCategoryFilter('INFORMATIONAL'); setSoarAssetCategoryFilter('CODE'); setCurrentView('soar') }}
                        title="Hallazgos informativos sobre código: SonarQube code smells, métricas ISO 25010 (longitud de método), CMMI (deuda técnica) -- no son vulnerabilidades de seguridad. Haz clic para ver filtrado."
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-8 space-y-8">
                  {/* Map Section */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 relative overflow-hidden group" title="Ubicación geográfica real de los activos con coordenadas registradas en el inventario">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                          <Globe className="text-[#06B6D4]" size={20} />
                          Despliegue de Infraestructura Nacional
                        </h3>
                        <p className="text-[12px] text-slate-500 font-bold uppercase tracking-widest">Activos Detectados y Monitoreados por Nuclei</p>
                      </div>
                    </div>
                    <div className="h-[400px] w-full bg-[#0F172A]/50 rounded-2xl border border-white/5 flex items-center justify-center overflow-hidden">
                      <MapChart markers={mapData} />
                    </div>
                  </div>

                  {/* Alerts Table */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Últimas 5 alertas de runtime (Falco/Zeek) detectadas en vivo -- distinto de las vulnerabilidades de escaneo mostradas en otras secciones">
                    <div className="flex items-center justify-between mb-8">
                      <h3 className="text-white font-bold text-xl flex items-center gap-2">
                        <Activity className="text-[#06B6D4]" size={20} />
                        {severityFilter ? `Alertas ${severityFilter}` : 'Alertas Recientes en Tiempo Real'}
                      </h3>
                      {severityFilter && (
                        <button onClick={() => setSeverityFilter(null)} className="text-slate-500 text-[12px] font-black uppercase tracking-widest hover:text-white">Limpiar Filtro</button>
                      )}
                      <button onClick={() => setCurrentView('threat-hunting')} className="text-[#06B6D4] text-[12px] font-black uppercase tracking-widest hover:underline">Ver Todo el Registro</button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left">
                        <thead>
                          <tr className="text-slate-500 text-[12px] font-black uppercase tracking-widest border-b border-slate-800">
                            <th className="pb-4">Severidad</th>
                            <th className="pb-4">Fecha</th>
                            <th className="pb-4">Entidad</th>
                            <th className="pb-4">Mensaje</th>
                            <th className="pb-4" title="Nivel de severidad de la alerta (CRÍTICA, ALTA, MEDIA, INFO)">Severidad</th>
                            <th className="pb-4" title="Fecha y hora exacta en que se detectó la alerta">Fecha</th>
                            <th className="pb-4" title="Activo o equipo donde se originó la alerta">Activo / Entidad</th>
                            <th className="pb-4" title="Regla o firma de detección que disparó la alerta">Regla / Mensaje</th>
                            <th className="pb-4 text-right" title="Acciones disponibles sobre la alerta">Acción</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {filteredAlerts.length > 0 ? (
                            filteredAlerts.slice(0, 5).map((alert) => (
                                <tr key={alert.id} className="group hover:bg-white/5 transition-all">
                                  <td className="py-4">
                                    <span
                                      title={{ CRITICAL: 'CRÍTICA: Requiere acción inmediata, impacto severo', HIGH: 'ALTA: Acción urgente requerida en menos de 4 horas', MEDIUM: 'MEDIA: Gestionar en las próximas 24 horas', LOW: 'BAJA: Sin impacto crítico, requiere monitoreo', INFO: 'INFORMATIVA: Sin impacto de seguridad, sólo visibilidad' }[normSev(alert.priority)]}
                                      className={`px-2 py-1 rounded text-[11px] font-black ${SEV_BADGE_CLS[normSev(alert.priority)]}`}>
                                      {SEV_LABEL_ES[normSev(alert.priority)]}
                                    </span>
                                  </td>
                                  <td className="py-4 text-[12px] font-bold text-slate-500">{new Date(alert.detected_at).toLocaleString()}</td>
                                  <td className="py-4 text-[12px] font-bold text-white" title={`Ver alertas del activo: ${alert.asset_name || 'Sistema'}`}>{alert.asset_name || "Sistema"}</td>
                                  <td className="py-4 text-[12px] text-slate-400" title={alert.rule_name}>{alert.rule_name}</td>
                                  <td className="py-4 text-right">
                                    <button 
                                        onClick={() => handleInvestigate(alert.id)}
                                        title="Abrir panel de investigación forense de esta alerta"
                                        className="px-3 py-1.5 rounded-lg bg-[#06B6D4]/10 text-[#06B6D4] text-[12px] font-black uppercase tracking-widest hover:bg-[#06B6D4] hover:text-[#0F172A] transition-all"
                                    >
                                      Investigar
                                    </button>
                                  </td>
                                </tr>
                              ))
                          ) : (
                              <tr>
                                  <td colSpan="5" className="py-8 text-center text-slate-600 text-xs font-bold uppercase tracking-widest italic">
                                      No se detectaron amenazas en runtime actualmente.
                                  </td>
                              </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Daily Detections Chart */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 mt-8" title="Cantidad de nuevos hallazgos (todos los motores, infra y código) detectados por día">
                    <div>
                      <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                        <Activity className="text-[#06B6D4]" size={20} />
                        Detecciones Diarias de Vulnerabilidades
                      </h3>
                      <p className="text-[12px] text-slate-500 font-bold uppercase tracking-widest mb-6">Tendencia de hallazgos identificados por día</p>
                    </div>
                    <div className="h-[250px] w-full bg-[#0F172A]/50 rounded-2xl border border-white/5 p-4">
                      {dailyDetections.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={dailyDetections}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                            <XAxis dataKey="date" stroke="#64748B" fontSize={10} tickLine={false} />
                            <YAxis stroke="#64748B" fontSize={10} tickLine={false} />
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px' }}
                              labelStyle={{ color: '#fff', fontWeight: 'bold' }}
                            />
                            <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="flex h-full items-center justify-center text-slate-500 font-bold text-xs uppercase">No hay suficientes datos de tendencia</div>
                      )}
                    </div>
                  </div>

                  {/* Tops Section */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
                    {/* Top 5 Recent Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Últimos activos registrados en el inventario de infraestructura">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <Server className="text-[#06B6D4]" size={16} />
                        Activos Recientes
                      </h4>
                      <ul className="space-y-3">
                        {tops.recent_assets?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`Activo: ${a.asset_name}, Tipo: ${a.asset_type}`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-[12px] text-slate-500 font-mono">{a.asset_type}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Top 5 Most Vulnerable Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Activos con mayor número de vulnerabilidades CVE pendientes de remediar">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <ShieldAlert className="text-orange-400" size={16} />
                        Más Vulnerables
                      </h4>
                      <ul className="space-y-3">
                        {tops.most_vulnerable?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`${a.asset_name}: ${a.count} vulnerabilidades pendientes`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-xs font-black text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded" title={`${a.count} CVEs sin remediar`}>{a.count} vulns</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Top 5 Most Remediated Assets */}
                    <div className="bg-[#1E293B] rounded-[24px] border border-slate-800 p-6" title="Activos donde el motor SOAR/IA ha ejecutado más remediaciones exitosas">
                      <h4 className="text-white font-bold text-sm mb-4 flex items-center gap-2 uppercase tracking-wide">
                        <CheckCircle2 className="text-emerald-400" size={16} />
                        Más Remediados
                      </h4>
                      <ul className="space-y-3">
                        {tops.most_remediated?.map((a, i) => (
                          <li key={i} className="flex justify-between items-center text-xs bg-slate-900/40 p-2.5 rounded-xl border border-white/5" title={`${a.asset_name}: ${a.count} vulnerabilidades resueltas`}>
                            <span className="font-bold text-slate-300 truncate max-w-[120px]">{a.asset_name}</span>
                            <span className="text-xs font-black text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded" title={`${a.count} CVEs resueltos`}>{a.count} ✓</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* SOAR ROI Metrics Section */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 mt-8" title="Impacto medido del motor de remediación automática frente a la remediación manual, sobre datos reales de remediation_history">
                    <div>
                      <h3 className="text-white font-bold text-xl mb-1 flex items-center gap-2">
                        <Zap className="text-[#06B6D4]" size={20} />
                        Métricas de Retorno de Inversión (ROI) SOAR & IA
                      </h3>
                      <p className="text-[12px] text-slate-500 font-bold uppercase tracking-widest mb-6">Impacto y eficiencia en remediación de incidentes</p>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl flex flex-col justify-center" title="Tiempo promedio que tarda Centinela-AI en detectar y aplicar un parche desde el momento en que se identifica la vulnerabilidad">
                        <p className="text-[12px] text-slate-500 font-black uppercase tracking-wider mb-2">Tiempo Promedio de Remediación</p>
                        <h4 className="text-[#06B6D4] font-black text-4xl">{roiStats.avg_remediation_time_minutes} min</h4>
                        <p className="text-[12px] text-slate-400 mt-2">vs ~48 hrs en mitigación manual promedio</p>
                      </div>
                      
                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl flex flex-col justify-center" title="Porcentaje de remediaciones ejecutadas exitosamente por el motor SOAR/IA sin necesidad de intervención humana manual">
                        <p className="text-[12px] text-slate-500 font-black uppercase tracking-wider mb-2">Tasa de Efectividad IA</p>
                        <h4 className="text-emerald-400 font-black text-4xl">{roiStats.effectiveness_rate_percentage}%</h4>
                        <p className="text-[12px] text-slate-400 mt-2">Ejecución exitosa sin intervención humana</p>
                      </div>

                      <div className="bg-[#0F172A]/50 border border-slate-800 p-6 rounded-2xl">
                        <p className="text-[12px] text-slate-500 font-black uppercase tracking-wider mb-4">Resoluciones IA vs Manuales</p>
                        <div className="flex items-center justify-between text-xs font-bold mb-2">
                          <span className="text-slate-300">Resuelto por IA ({roiStats.comparison?.ai_resolved})</span>
                          <span className="text-slate-500">Manual ({roiStats.comparison?.manual_resolved})</span>
                        </div>
                        <div className="w-full bg-slate-800 h-3.5 rounded-full overflow-hidden flex border border-white/5">
                          <div 
                            style={{ width: `${(roiStats.comparison?.ai_resolved / (roiStats.comparison?.ai_resolved + roiStats.comparison?.manual_resolved || 1)) * 100}%` }} 
                            className="bg-[#06B6D4] h-full"
                          />
                          <div 
                            style={{ width: `${(roiStats.comparison?.manual_resolved / (roiStats.comparison?.ai_resolved + roiStats.comparison?.manual_resolved || 1)) * 100}%` }} 
                            className="bg-slate-700 h-full"
                          />
                        </div>
                        <div className="flex gap-4 mt-3 text-[11px] font-bold uppercase tracking-wider">
                          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-[#06B6D4]" /> IA</div>
                          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-slate-700" /> Manual</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                {/* Right Sidebar */}
                <div className="lg:col-span-4 space-y-8">
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Conteo de TODAS las alertas de runtime (Falco/Zeek) agrupadas por severidad -- no confundir con las vulnerabilidades de Infra/Código de las tarjetas superiores, que son hallazgos de escaneo, no alertas en vivo">
                    <h3 className="text-white font-bold text-lg mb-6">Distribución de Riesgo</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={Array.isArray(riskData) ? riskData : []}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                            nameKey="severity"
                            onClick={(data) => {
                                if (data && data.severity) {
                                    if (severityFilter === data.severity) {
                                        setSeverityFilter(null);
                                    } else {
                                        setSeverityFilter(data.severity);
                                        window.scrollTo({ top: 1000, behavior: 'smooth' });
                                    }
                                }
                            }}
                            className="cursor-pointer"
                          >
                            {(Array.isArray(riskData) ? riskData : []).map((entry, index) => (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={
                                    entry.severity === 'CRITICAL' ? '#EF4444' : 
                                    entry.severity === 'HIGH' ? '#F97316' : 
                                    entry.severity === 'MEDIUM' ? '#EAB308' : '#10B981'
                                } 
                              />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }}
                            itemStyle={{ color: '#fff' }}
                          />
                          <Legend 
                            verticalAlign="bottom" 
                            height={36} 
                            iconType="circle"
                            formatter={(value, entry) => {
                              const payload = entry.payload;
                              return <span className="text-[12px] font-bold text-slate-300 uppercase">{payload.severity}: {payload.value}</span>
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="text-[12px] text-slate-500 font-bold text-center uppercase tracking-widest mt-4">Haz clic en un segmento para filtrar alertas</p>
                  </div>

                  {/* Severidad por Infra/Código -- agregado 2026-08-14 a petición del usuario, tras
                      la separación de vulnerabilidades reales vs informativas: antes solo existía
                      un total fleet-wide sin distinguir de dónde viene cada severidad. Excluye
                      hallazgos INFORMATIONAL (SonarQube code smells, ISO 25010, CMMI) a propósito --
                      ver /api/stats/severity-by-category. */}
                  {[
                    { key: 'infra', label: 'Severidad — Infraestructura', icon: <Server size={16} className="text-orange-400" />, tip: 'Vulnerabilidades reales (excluye hallazgos informativos/de calidad) en servidores, bases de datos y activos de red, agrupadas por severidad.' },
                    { key: 'code', label: 'Severidad — Código', icon: <ShieldAlert size={16} className="text-amber-400" />, tip: 'Vulnerabilidades reales (excluye SonarQube code smells, ISO 25010, CMMI) en repositorios GitLab (SAST/SCA), agrupadas por severidad.' },
                  ].map(({ key, label, icon, tip }) => {
                    const dist = severityByCategory[key] || {}
                    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                    const colors = { CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#EAB308', LOW: '#10B981', INFO: '#64748B' }
                    const chartData = order.filter(s => (dist[s] || 0) > 0).map(s => ({ severity: s, value: dist[s] }))
                    const total = order.reduce((sum, s) => sum + (dist[s] || 0), 0)
                    return (
                      <div key={key} className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title={tip}>
                        <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">{icon} {label}</h3>
                        <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">{total} hallazgos reales</p>
                        <div className="h-40">
                          {chartData.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16 }}>
                                <XAxis type="number" hide />
                                <YAxis type="category" dataKey="severity" stroke="#64748B" fontSize={10} tickLine={false} width={60} />
                                <Tooltip
                                  contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '12px', fontSize: '11px' }}
                                  itemStyle={{ color: '#fff', fontWeight: 'bold' }}
                                  formatter={(value) => [`${value} hallazgos`, '']}
                                />
                                <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                                  {chartData.map((entry, idx) => (
                                    <Cell key={idx} fill={colors[entry.severity]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer>
                          ) : (
                            <div className="flex h-full items-center justify-center text-slate-500 font-bold text-xs uppercase">Sin hallazgos reales registrados</div>
                          )}
                        </div>
                      </div>
                    )
                  })}

                  <div className="bg-gradient-to-br from-[#06B6D4]/20 to-blue-900/20 rounded-[32px] border border-[#06B6D4]/20 p-8">
                    <div className="flex items-center gap-3 mb-4">
                      <Zap className="text-[#06B6D4]" size={24} />
                      <h3 className="text-white font-bold text-lg" title="Análisis y remediación asistidos por IA (cascada de proveedores con respaldo determinístico)">Remediación con IA</h3>
                    </div>
                    <p className="text-xs text-slate-400 mb-6 leading-relaxed font-medium">
                      El motor de IA (cascada de proveedores) está analizando <strong>{vulnStats.pending_ia}</strong> hallazgos detectados recientemente.
                    </p>
                    <button
                      onClick={() => setCurrentView('soar')}
                      title="Ir al panel SOAR para revisar, aprobar y gestionar los parches generados por IA"
                      className="w-full py-4 bg-[#06B6D4] text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-white transition-all active:scale-95"
                    >
                      Gestionar Remediaciones
                    </button>
                  </div>
                </div>
              </div>

              {/* Sección de Gráficos Analíticos -- todos los valores vienen de agregados reales
                  (backend: /api/stats/dashboard-charts; CMMI radar: computado en cliente sobre
                  cmmiReport.assets_audit, ya real y ya fetched). Ningún valor aquí es estimado. */}
              <div className="space-y-8 mt-8">
                <div>
                  <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                    <Gauge className="text-[#06B6D4]" size={22} /> Indicadores de Cumplimiento
                  </h3>
                  <p className="text-xs text-slate-500 font-bold uppercase tracking-widest mb-6">Medidores en vivo, calculados sobre hallazgos y auditorías reales</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {[
                      { label: 'ISO 27001 / 25010', value: vulnStats?.iso_compliance_percentage, sub: 'Controles sin violaciones activas', tip: 'Porcentaje real del universo fijo de controles ISO 27001/25010 sin ninguna violación activa en toda la flota (excluye activos nunca auditados).' },
                      { label: 'CMMI v3.0', value: cmmiReport.overall_cmmi_compliance_rate, sub: `${cmmiReport.total_assets_audited || 0} activos auditados`, tip: 'Promedio real de cumplimiento CMMI v3.0 (5 áreas de práctica evaluables por código: CAR/PQA/CM/MC/VV, de las 19 del modelo tailored de la organización), solo sobre activos genuinamente verificados por algún motor -- excluye activos nunca alcanzados.' },
                      { label: 'Cumplimiento SLA', value: dashboardCharts.sla_compliance_percentage, sub: `${dashboardCharts.sla_within || 0} dentro de plazo · ${dashboardCharts.sla_breached || 0} vencidos`, tip: 'Porcentaje de hallazgos abiertos que aún están dentro de su plazo SLA (24h Crítico / 7d Alto / 30d Medio / 90d Bajo) según severidad.' },
                    ].map((g, idx) => {
                      const pct = g.value ?? 0
                      const color = pct >= 75 ? '#10B981' : pct >= 50 ? '#06B6D4' : pct >= 25 ? '#F59E0B' : '#EF4444'
                      return (
                        <div key={idx} className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-6 flex flex-col items-center" title={g.tip}>
                          <div className="h-36 w-full relative">
                            <ResponsiveContainer width="100%" height="100%">
                              <RadialBarChart innerRadius="70%" outerRadius="100%" data={[{ value: pct }]} startAngle={90} endAngle={-270}>
                                <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                                <RadialBar dataKey="value" cornerRadius={10} fill={color} background={{ fill: '#0F172A' }} />
                              </RadialBarChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                              <span className="text-3xl font-black text-white">{g.value != null ? `${g.value}%` : '—'}</span>
                            </div>
                          </div>
                          <span className="text-[12px] font-black text-slate-300 uppercase tracking-widest mt-2">{g.label}</span>
                          <span className="text-[10px] text-slate-500 font-bold text-center mt-1">{g.sub}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Radar CMMI 5 áreas -- agregado en cliente: % de activos que pasan cada área
                      real (CAR/PQA/CM/MC/VV), sobre datos ya reales de cmmiReport. Realineado 2026-08-25
                      contra el modelo CMMI V3.0 tailored de 19 áreas (SAM/MSR retirados: no son
                      áreas reales de ese modelo) -- ver compliance_mapper.py. */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Radar de las 5 áreas de práctica CMMI v3.0 evaluables por código (CAR/PQA/CM/MC/VV): cada eje muestra el % de activos que aprueban esa área específica, a nivel flota">
                    <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                      <Target className="text-indigo-400" size={20} /> CMMI v3.0 — 7 Áreas de Práctica
                    </h3>
                    <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">% de activos que cumplen cada área, a nivel flota</p>
                    <div className="h-72">
                      <ResponsiveContainer width="100%" height="100%">
                        {(() => {
                          const areaMap = {}
                          ;(cmmiReport.assets_audit || []).forEach(asset => {
                            (asset.practice_areas_breakdown || []).forEach(pa => {
                              const code = (pa.area.match(/^([A-Z]+)/) || [])[1] || pa.area
                              if (!areaMap[code]) areaMap[code] = { pass: 0, total: 0 }
                              areaMap[code].total += 1
                              if (pa.passed) areaMap[code].pass += 1
                            })
                          })
                          const radarData = Object.entries(areaMap).map(([code, v]) => ({
                            area: code,
                            value: v.total > 0 ? Math.round((v.pass / v.total) * 100) : 0
                          }))
                          return (
                            <RadarChart data={radarData}>
                              <PolarGrid stroke="#334155" />
                              <PolarAngleAxis dataKey="area" tick={{ fill: '#94A3B8', fontSize: 11, fontWeight: 'bold' }} />
                              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 9 }} />
                              <Radar name="Cumplimiento" dataKey="value" stroke="#818CF8" fill="#818CF8" fillOpacity={0.4} />
                              <Tooltip contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }} itemStyle={{ color: '#fff' }} />
                            </RadarChart>
                          )
                        })()}
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Distribución CIS Benchmark -- grade real por activo (auditors/auditor_cis_benchmarks.py),
                      distingue honestamente 'Sin Conexión' (verificado, inalcanzable) de 'No Evaluado'
                      (nunca corrido) en vez de mezclarlos con un grade fabricado. */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Grade real (A-F) de hardening CIS Level 1 por activo. 'Sin Conexión' = auditoría intentada pero el host no respondió por SSH; 'No Evaluado' = nunca se ha corrido la auditoría; 'N/A' = repos de código, donde CIS no aplica">
                    <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                      <ShieldCheck className="text-cyan-400" size={20} /> Distribución CIS Benchmarks
                    </h3>
                    <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">Hardening Level 1, por grade real de la flota</p>
                    <div className="h-72">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={dashboardCharts.cis_grade_distribution || []}
                            cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={4}
                            dataKey="count" nameKey="grade"
                          >
                            {(dashboardCharts.cis_grade_distribution || []).map((entry, index) => (
                              <Cell key={`cis-cell-${index}`} fill={
                                entry.grade === 'A' ? '#10B981' :
                                entry.grade === 'B' ? '#06B6D4' :
                                entry.grade === 'C' ? '#F59E0B' :
                                entry.grade === 'F' ? '#EF4444' :
                                entry.grade === 'SIN_CONEXION' ? '#64748B' :
                                entry.grade === 'N_A' ? '#1E293B' : '#334155'
                              } />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }} itemStyle={{ color: '#fff' }} />
                          <Legend verticalAlign="bottom" height={36} iconType="circle" formatter={(v, entry) => {
                            const p = entry.payload
                            const label = p.grade === 'SIN_CONEXION' ? 'Sin Conexión' : p.grade === 'NO_EVALUADO' ? 'No Evaluado' : p.grade === 'N_A' ? 'N/A (Código)' : `Grade ${p.grade}`
                            return <span className="text-[11px] font-bold text-slate-300">{label}: {p.count}</span>
                          }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Remediación IA vs Manual -- dato real ya calculado en /api/stats/soar-roi,
                      graficado aquí como pie en vez de solo la barra numérica existente arriba. */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Cuántas remediaciones ya ejecutadas (remediation_history) fueron aplicadas automáticamente por el motor SOAR/IA frente a las aplicadas manualmente por un analista">
                    <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                      <Zap className="text-[#06B6D4]" size={20} /> Remediación: IA vs Manual
                    </h3>
                    <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">Remediaciones reales ejecutadas, por origen</p>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={[
                              { name: 'IA', value: roiStats.comparison?.ai_resolved || 0 },
                              { name: 'Manual', value: roiStats.comparison?.manual_resolved || 0 },
                            ]}
                            cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={4}
                            dataKey="value" nameKey="name"
                          >
                            <Cell fill="#06B6D4" />
                            <Cell fill="#475569" />
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }} itemStyle={{ color: '#fff' }} />
                          <Legend verticalAlign="bottom" height={36} iconType="circle" formatter={(v, entry) => (
                            <span className="text-[11px] font-bold text-slate-300">{entry.payload.name}: {entry.payload.value}</span>
                          )} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Distribución Centinela Risk Score -- histograma real (calculate_centinela_risk_score,
                      combina CVSS+EPSS+CISA KEV+criticidad del activo) sobre hallazgos abiertos. */}
                  <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Histograma del Centinela Risk Score (0-100) sobre hallazgos abiertos: combina severidad tipo-CVSS + probabilidad real de explotación (EPSS) + presencia en el catálogo CISA KEV + criticidad del activo">
                    <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                      <Activity className="text-orange-400" size={20} /> Distribución Centinela Risk Score
                    </h3>
                    <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">CVSS + EPSS + CISA KEV + Criticidad del Activo (0-100)</p>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={dashboardCharts.crs_distribution || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                          <XAxis dataKey="bucket" tick={{ fill: '#64748B', fontSize: 10, fontWeight: 'bold' }} axisLine={false} tickLine={false} />
                          <YAxis tick={{ fill: '#64748B', fontSize: 10 }} axisLine={false} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }} itemStyle={{ color: '#fff' }} cursor={{ fill: '#334155', opacity: 0.3 }} />
                          <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                            {(dashboardCharts.crs_distribution || []).map((entry, index) => (
                              <Cell key={`crs-cell-${index}`} fill={
                                entry.bucket === '80-100' ? '#EF4444' :
                                entry.bucket === '60-80' ? '#F97316' :
                                entry.bucket === '40-60' ? '#F59E0B' :
                                entry.bucket === '20-40' ? '#06B6D4' : '#10B981'
                              } />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>

                {/* Top MITRE ATT&CK -- técnicas reales detectadas y mapeadas por core/mitre_attack.py
                    sobre hallazgos abiertos, no una lista genérica del framework. */}
                <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8" title="Técnicas MITRE ATT&CK reales, mapeadas automáticamente desde los hallazgos abiertos de la flota (no una lista genérica del framework) -- ver core/mitre_attack.py">
                  <h3 className="text-white font-bold text-lg mb-1 flex items-center gap-2">
                    <ShieldAlert className="text-red-400" size={20} /> Top Técnicas MITRE ATT&CK Detectadas
                  </h3>
                  <p className="text-[11px] text-slate-500 font-bold uppercase tracking-widest mb-4">Técnicas reales mapeadas sobre hallazgos abiertos de la flota</p>
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={dashboardCharts.top_mitre_techniques || []} layout="vertical" margin={{ left: 20 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                        <XAxis type="number" tick={{ fill: '#64748B', fontSize: 10 }} axisLine={false} tickLine={false} />
                        <YAxis
                          type="category"
                          dataKey="technique_id"
                          width={90}
                          tick={{ fill: '#94A3B8', fontSize: 10, fontWeight: 'bold' }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1E293B', border: '1px solid #334155', borderRadius: '12px', fontSize: '10px', fontWeight: 'bold' }}
                          itemStyle={{ color: '#fff' }}
                          cursor={{ fill: '#334155', opacity: 0.3 }}
                          formatter={(value, name, props) => [value, props.payload.technique_name]}
                        />
                        <Bar dataKey="count" radius={[0, 8, 8, 0]} fill="#EF4444" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            </>
  )
}

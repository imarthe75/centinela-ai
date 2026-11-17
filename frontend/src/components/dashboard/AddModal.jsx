// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, CheckCircle2, ChevronDown, Download, Globe, KeyRound, Lock, PlusCircle, Radio, Shield, Upload, Users, X } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function AddModal() {
  const { connTest, handleAddAsset, handleTestConnection, isRootUser, newAsset, setAgentModalAsset, setAgentModalTab, setConnTest, setNewAsset, setNewAssetZip, setShowAddModal, setShowAgentModal } = useDashboard()
  return (
<div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0F172A]/80 backdrop-blur-sm animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-lg rounded-[40px] border border-white/10 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-300 max-h-[90vh] overflow-y-auto">
                    <div className="p-8 border-b border-white/5 flex items-center justify-between sticky top-0 bg-[#1E293B] z-10">
                        <h3 className="text-white font-bold text-xl flex items-center gap-3">
                            <PlusCircle className="text-[#06B6D4]" />
                            Registrar Nuevo Activo
                        </h3>
                        <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-white transition-all" title="Cerrar">
                            <X size={24} />
                        </button>
                    </div>
                    <form onSubmit={handleAddAsset} className="p-8 space-y-6">
                        <div className="space-y-4">

                            {/* ── Nombre ── */}
                            <div>
                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">Nombre del Activo <span className="text-red-400">*</span></label>
                                <input
                                    type="text"
                                    required
                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                    placeholder="ej. Laptop-Dev-Juan o Servidor-Prod-01"
                                    value={newAsset.asset_name}
                                    onChange={(e) => setNewAsset({...newAsset, asset_name: e.target.value})}
                                />
                            </div>

                            {/* ── Tipo de Activo ── */}
                            <div>
                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">Tipo de Activo <span className="text-red-400">*</span></label>
                                <div className="relative">
                                    <select
                                        required
                                        className={`w-full bg-[#0F172A] border rounded-2xl p-4 pr-10 font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer transition-all ${
                                            newAsset.asset_type ? 'border-slate-800 text-white' : 'border-amber-500/50 text-slate-500'
                                        }`}
                                        value={newAsset.asset_type}
                                        onChange={(e) => setNewAsset({...newAsset, asset_type: e.target.value, vault_ansible_user: '', vault_sudo_token: '', ssh_private_key: '', gitlab_user: '', gitlab_token: '', auth_type: 'PASSWORD'})}
                                    >
                                        <option value="" disabled>— Seleccione tipo de activo —</option>
                                        <optgroup label="Servidores y Equipos">
                                            <option value="WORKSTATION">Estación de Trabajo / Equipo Institucional</option>
                                            <option value="SERVER_LINUX">Servidor Linux</option>
                                            <option value="SERVER_WINDOWS">Servidor Windows</option>
                                        </optgroup>
                                        <optgroup label="Infraestructura de Red">
                                            <option value="CISCO_NETWORK">Switch / Router Cisco (SNMP / SSH)</option>
                                            <option value="VMWARE_ESXI">Hipervisor VMware ESXi (vSphere API / SSH)</option>
                                        </optgroup>
                                        <optgroup label="Cloud y Contenedores">
                                            <option value="CONTAINER">Docker Container</option>
                                            <option value="KUBERNETES">Kubernetes Cluster</option>
                                            <option value="CLOUD">Recurso Cloud (AWS/GCP)</option>
                                        </optgroup>
                                        <optgroup label="Repositorios y Servicios">
                                            <option value="GITLAB">GitLab / Gitea Repository</option>
                                            <option value="SOURCE_ZIP">Código fuente (subir ZIP)</option>
                                            <option value="IP">Dirección IP / Puerto</option>
                                            <option value="URL">URL / Aplicación Web</option>
                                            <option value="DATABASE">Base de Datos</option>
                                        </optgroup>
                                    </select>
                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                </div>
                                {!newAsset.asset_type && (
                                    <p className="text-[11px] text-amber-400 mt-1.5 flex items-center gap-1 font-medium">
                                        <AlertTriangle size={10} /> Selecciona un tipo para continuar configurando el activo
                                    </p>
                                )}
                            </div>

                            {/* ── Campos que sólo aparecen cuando hay tipo seleccionado ── */}
                            {newAsset.asset_type && (
                                <>
                                    {/* Criticidad */}
                                    <div>
                                        <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2" title="Nivel de criticidad del activo según NIST SP 800-60 y CSF 2.0">Criticidad (NIST SP 800-60 / CSF 2.0)</label>
                                        <div className="relative">
                                            <select
                                                className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 pr-10 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                value={newAsset.criticality}
                                                onChange={(e) => setNewAsset({...newAsset, criticality: e.target.value})}
                                            >
                                                <option value="CRITICAL">Muy Alta / Crítica — Impacto Severo (SLA: 1 hora)</option>
                                                <option value="HIGH">Alta — Impacto Alto (SLA: 4 horas)</option>
                                                <option value="MEDIUM">Moderada / Media — Impacto Moderado (SLA: 24 horas)</option>
                                                <option value="LOW">Baja — Impacto Bajo (SLA: 72 horas)</option>
                                                <option value="INFORMATIONAL">Informativa — Monitoreo (SLA: 7 días)</option>
                                            </select>
                                            <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                        </div>
                                        <p className="text-[11px] text-slate-500 mt-1.5 font-medium leading-relaxed">
                                            Qué tan grave sería para la organización que este activo falle o sea comprometido (¿se detiene un servicio importante? ¿hay datos sensibles?).
                                            Centinela la usa para <span className="text-slate-300">priorizar</span>: pesa en el puntaje de riesgo de cada hallazgo y fija el plazo de atención (SLA).
                                            Si dudas, elige <span className="text-slate-300">Moderada</span>; se puede cambiar después.
                                        </p>
                                    </div>

                                    {newAsset.asset_type === 'SOURCE_ZIP' && (
                                        <div>
                                            <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                <Upload size={12} className="text-[#06B6D4]" />
                                                Archivo ZIP con el código <span className="text-red-400">*</span>
                                            </label>
                                            <input
                                                type="file"
                                                accept=".zip,application/zip"
                                                required
                                                onChange={(e) => setNewAssetZip(e.target.files?.[0] || null)}
                                                className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-slate-300 text-sm file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:bg-[#06B6D4]/20 file:text-[#06B6D4] file:font-black file:uppercase file:text-[11px] cursor-pointer"
                                            />
                                            <p className="text-[11px] text-slate-500 mt-1.5 font-medium leading-relaxed">
                                                Máx. 300 MB. Se extrae en una carpeta interna protegida y se analiza con SAST, dependencias (SCA), estándares, IaC, accesibilidad, Semgrep y SonarQube. El análisis corre en segundo plano y tarda varios minutos. Si subes otro ZIP con el mismo nombre, reemplaza el código anterior. Se registra como <span className="text-[#06B6D4]">Local/&lt;nombre&gt;</span>.
                                            </p>
                                        </div>
                                    )}

                                    {newAsset.asset_type !== 'SOURCE_ZIP' && (<>
                                    {/* Endpoint / Dirección */}
                                    <div>
                                        <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                            {newAsset.asset_type === 'GITLAB' ? 'URL del Repositorio GitLab / Gitea' : 'Dirección / Endpoint (IPv4, IPv6 o FQDN)'}
                                        </label>
                                        <input
                                            type="text"
                                            required
                                            className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                            placeholder={
                                                newAsset.asset_type === 'GITLAB'
                                                    ? 'ej. http://192.0.2.14 o https://gitlab.example.internal'
                                                    : newAsset.asset_type === 'WORKSTATION'
                                                    ? 'ej. 192.0.2.30, 2001:db8::1 o mi-laptop.local'
                                                    : newAsset.asset_type === 'CISCO_NETWORK'
                                                    ? 'ej. 192.0.2.29 o [2001:db8::1] (IP del Switch)'
                                                    : newAsset.asset_type === 'VMWARE_ESXI'
                                                    ? 'ej. 192.0.2.9 o 2001:db8::10 (IP del host ESXi)'
                                                    : 'ej. 192.0.2.31, [2001:db8::1], postgres://db..., https://api...'
                                            }
                                            value={newAsset.endpoint}
                                            onChange={(e) => setNewAsset({...newAsset, endpoint: e.target.value})}
                                        />
                                        <p className="text-[11px] text-slate-500 mt-1.5 flex items-center gap-2 font-medium">
                                            <Globe size={10} className="text-[#06B6D4]" />
                                            Soporta <span className="text-[#06B6D4]">IPv4</span> (192.0.2.29), <span className="text-[#06B6D4]">IPv6</span> (2001:db8::1 o [::1]) y <span className="text-[#06B6D4]">FQDN</span> (servidor.local)
                                        </p>
                                    </div>

                                    {/* ── Credenciales según tipo ── */}
                                    {newAsset.asset_type === 'GITLAB' ? (
                                        <>
                                            <div>
                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Users size={12} className="text-[#06B6D4]" />
                                                    Usuario de GitLab / Gitea
                                                </label>
                                                <input
                                                    type="text"
                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 mb-4"
                                                    placeholder="ej. root o gitlab-admin"
                                                    value={newAsset.gitlab_user || ''}
                                                    onChange={(e) => setNewAsset({...newAsset, gitlab_user: e.target.value})}
                                                />
                                            </div>
                                            <div>
                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Lock size={12} className="text-[#06B6D4]" />
                                                    Personal Access Token (PAT) <span className="text-slate-600 font-medium">(Opcional)</span>
                                                </label>
                                                <div className="relative">
                                                    <input
                                                        type="password"
                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                        placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                                                        value={newAsset.gitlab_token || ''}
                                                        onChange={(e) => setNewAsset({...newAsset, gitlab_token: e.target.value})}
                                                    />
                                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                        <Shield size={16} />
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                    <CheckCircle2 size={10} />
                                                    El Token PAT permite auditar repositorios y generar Merge Requests automáticos. Se encripta en Vault.
                                                </p>
                                            </div>
                                        </>
                                    ) : ['SERVER_LINUX', 'SERVER_WINDOWS', 'WORKSTATION'].includes(newAsset.asset_type) ? (
                                        <>
                                            {/* ── Modo de Monitoreo: AGENT vs PING_ONLY ── */}
                                            <div>
                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-3">
                                                    Modo de Monitoreo
                                                </label>
                                                <div className="grid grid-cols-2 gap-3 mb-2">
                                                    <button
                                                        type="button"
                                                        onClick={() => setNewAsset({...newAsset, agent_mode: 'AGENT'})}
                                                        className={`flex flex-col items-center gap-2 p-4 rounded-2xl border-2 text-xs font-bold transition-all ${
                                                            (newAsset.agent_mode || 'AGENT') === 'AGENT'
                                                                ? 'bg-[#06B6D4]/10 border-[#06B6D4] text-[#06B6D4]'
                                                                : 'bg-[#0F172A] border-slate-800 text-slate-500 hover:border-slate-600'
                                                        }`}
                                                    >
                                                        <Shield size={20} />
                                                        <span>Con Agente Wazuh</span>
                                                        <span className="text-[11px] font-medium opacity-70">EDR + Telemetría completa</span>
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => setNewAsset({...newAsset, agent_mode: 'PING_ONLY', vault_sudo_token: '', vault_ansible_user: '', ssh_private_key: ''})}
                                                        className={`flex flex-col items-center gap-2 p-4 rounded-2xl border-2 text-xs font-bold transition-all ${
                                                            newAsset.agent_mode === 'PING_ONLY'
                                                                ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400'
                                                                : 'bg-[#0F172A] border-slate-800 text-slate-500 hover:border-slate-600'
                                                        }`}
                                                    >
                                                        <Radio size={20} />
                                                        <span>Solo Ping / En Línea</span>
                                                        <span className="text-[11px] font-medium opacity-70">Sin credenciales</span>
                                                    </button>
                                                </div>
                                                {newAsset.agent_mode === 'PING_ONLY' && (
                                                    <div className="flex items-start gap-3 p-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl mt-2">
                                                        <CheckCircle2 size={14} className="text-emerald-400 mt-0.5 shrink-0" />
                                                        <p className="text-[11px] text-emerald-300/80 font-medium leading-relaxed">
                                                            El activo se registra sin credenciales. Centinela solo verificará su conectividad (ping TCP). Podrás instalar el agente más tarde desde el panel del activo.
                                                        </p>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Credenciales solo si modo AGENT */}
                                            {(newAsset.agent_mode || 'AGENT') === 'AGENT' && (
                                                <>
                                                    {/* Usuario de conexión */}
                                                    <div>
                                                        <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Usuario con privilegios para instalar el agente Wazuh o ejecutar comandos Ansible">
                                                            <Users size={12} className="text-[#06B6D4]" />
                                                            Usuario de Conexión SSH / Ansible
                                                            <span className="text-slate-600 font-medium text-[11px]">(Opcional)</span>
                                                        </label>
                                                        <input
                                                            type="text"
                                                            className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700"
                                                            placeholder="ej. ubuntu o centinela (usuario con sudo, NO root)"
                                                            value={newAsset.vault_ansible_user || ''}
                                                            onChange={(e) => { setNewAsset({...newAsset, vault_ansible_user: e.target.value}); setConnTest(null) }}
                                                        />
                                                        {isRootUser(newAsset.vault_ansible_user) && (
                                                            <p className="text-[11px] text-red-400 mt-1.5 font-bold flex items-center gap-1">
                                                                <AlertTriangle size={11} /> No se permite root. Usa un usuario normal con sudo.
                                                            </p>
                                                        )}
                                                        <p className="text-[11px] text-slate-500 mt-1.5 font-medium">
                                                            Credencial almacenada de forma encriptada en OpenBao. Nunca se guarda en texto plano.
                                                        </p>
                                                    </div>

                                                    {/* Método de autenticación */}
                                                    <div className="space-y-4">
                                                        <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2" title="Selecciona cómo Ansible autenticará la conexión SSH al servidor">
                                                            Método de Autenticación SSH <span className="text-slate-600 font-medium text-[11px]">(Opcional)</span>
                                                        </label>
                                                        <div className="flex gap-3 mb-4">
                                                            <button
                                                                type="button"
                                                                title="Usar contraseña sudo para autenticación"
                                                                onClick={() => setNewAsset({...newAsset, auth_type: 'PASSWORD'})}
                                                                className={`flex-1 py-3 px-4 rounded-xl text-xs font-bold transition-all border ${newAsset.auth_type !== 'SSH_KEY' ? 'bg-[#06B6D4]/20 border-[#06B6D4] text-[#06B6D4]' : 'bg-[#0F172A] border-slate-800 text-slate-400'}`}
                                                            >
                                                                🔑 Contraseña Sudo
                                                            </button>
                                                            <button
                                                                type="button"
                                                                title="Usar llave privada SSH (.pem / RSA) para autenticación sin contraseña"
                                                                onClick={() => setNewAsset({...newAsset, auth_type: 'SSH_KEY'})}
                                                                className={`flex-1 py-3 px-4 rounded-xl text-xs font-bold transition-all border ${newAsset.auth_type === 'SSH_KEY' ? 'bg-[#06B6D4]/20 border-[#06B6D4] text-[#06B6D4]' : 'bg-[#0F172A] border-slate-800 text-slate-400'}`}
                                                            >
                                                                📜 Llave SSH (.pem / RSA)
                                                            </button>
                                                        </div>

                                                        {newAsset.auth_type === 'SSH_KEY' ? (
                                                            <div>
                                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                                    <KeyRound size={12} className="text-[#06B6D4]" />
                                                                    Llave Privada SSH (RSA / OpenSSH / PEM)
                                                                </label>
                                                                <textarea
                                                                    rows={4}
                                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-mono text-xs focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700 resize-none"
                                                                    placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEowIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
                                                                    value={newAsset.ssh_private_key || ''}
                                                                    onChange={(e) => setNewAsset({...newAsset, ssh_private_key: e.target.value})}
                                                                />
                                                                <p className="text-[11px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                                    <CheckCircle2 size={10} />
                                                                    La llave privada se cifra con AES-256 y se almacena exclusivamente en OpenBao.
                                                                </p>
                                                            </div>
                                                        ) : (
                                                            <div>
                                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Contraseña de superusuario (sudo) del servidor Linux/Windows">
                                                                    <Lock size={12} className="text-[#06B6D4]" />
                                                                    Contraseña Sudo del Servidor <span className="text-slate-600 font-medium text-[11px]">(Opcional)</span>
                                                                </label>
                                                                <div className="relative">
                                                                    <input
                                                                        type="password"
                                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                                        placeholder="••••••••••••  (dejar vacío para instalar agente manualmente)"
                                                                        value={newAsset.vault_sudo_token || ''}
                                                                        onChange={(e) => setNewAsset({...newAsset, vault_sudo_token: e.target.value})}
                                                                    />
                                                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                                        <Shield size={16} />
                                                                    </div>
                                                                </div>
                                                                <p className="text-[11px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                                    <CheckCircle2 size={10} />
                                                                    Almacenada encriptada en Vault. No se expone al frontend ni se guarda en la BD.
                                                                </p>
                                                            </div>
                                                        )}
                                                    </div>
                                                </>
                                            )}

                                            {/* Guía de instalación de agente */}
                                            <div className="flex items-start gap-3 p-4 bg-indigo-500/5 border border-indigo-500/20 rounded-2xl">
                                                <Download size={16} className="text-indigo-400 mt-0.5 shrink-0" />
                                                <div className="flex-1">
                                                    <p className="text-[12px] font-black text-indigo-400 uppercase tracking-widest mb-1">Instalación Manual del Agente</p>
                                                    <p className="text-[11px] text-slate-400 font-medium leading-relaxed mb-2">
                                                        Puedes descargar el script de instalación del Agente Wazuh para instalarlo manualmente sin credenciales SSH.
                                                    </p>
                                                    {newAsset.asset_name && (
                                                        <button
                                                            type="button"
                                                            onClick={() => {
                                                                if (newAsset.asset_name) {
                                                                    setAgentModalAsset({ name: newAsset.asset_name, type: newAsset.asset_type, endpoint: newAsset.endpoint })
                                                                    setAgentModalTab('guide')
                                                                    setShowAgentModal(true)
                                                                } else {
                                                                    alert('Introduce el nombre del activo primero.')
                                                                }
                                                            }}
                                                            className="text-[11px] font-black text-indigo-300 flex items-center gap-1.5 hover:text-white transition-colors"
                                                        >
                                                            <Download size={10} /> Ver guía y descargar script de instalación
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        </>
                                    ) : ['CISCO_NETWORK', 'VMWARE_ESXI'].includes(newAsset.asset_type) ? (
                                        <>
                                            {/* Usuario de conexión Cisco/VMware */}
                                            <div>
                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Usuario con privilegios para instalar el agente Wazuh o ejecutar comandos Ansible">
                                                    <Users size={12} className="text-[#06B6D4]" />
                                                    {newAsset.asset_type === 'CISCO_NETWORK' ? 'Usuario SNMP / SSH del Dispositivo' : 'Usuario Administrador vSphere / SSH'}
                                                    <span className="text-slate-600 font-medium text-[11px]">(Opcional)</span>
                                                </label>
                                                <input
                                                    type="text"
                                                    className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none placeholder-slate-700"
                                                    placeholder={newAsset.asset_type === 'CISCO_NETWORK' ? 'ej. admin o cisco-ro' : 'ej. administrator@example.local (no root)'}
                                                    value={newAsset.vault_ansible_user || ''}
                                                    onChange={(e) => setNewAsset({...newAsset, vault_ansible_user: e.target.value})}
                                                />
                                            </div>
                                            {/* Para Cisco/VMware: contraseña/token */}
                                            <div>
                                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2" title="Contraseña o token API del dispositivo de red">
                                                    <Lock size={12} className="text-[#06B6D4]" />
                                                    {newAsset.asset_type === 'CISCO_NETWORK' ? 'Contraseña SSH / Comunidad SNMP' : 'Contraseña / Token API vSphere'}
                                                    <span className="text-slate-600 font-medium text-[11px]">(Opcional)</span>
                                                </label>
                                                <div className="relative">
                                                    <input
                                                        type="password"
                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/30 rounded-2xl p-4 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none pr-12 placeholder-slate-700"
                                                        placeholder="••••••••••••"
                                                        value={newAsset.vault_sudo_token || ''}
                                                        onChange={(e) => setNewAsset({...newAsset, vault_sudo_token: e.target.value})}
                                                    />
                                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2 text-[#06B6D4]/50">
                                                        <Shield size={16} />
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#06B6D4]/70 mt-2 flex items-center gap-1 font-medium">
                                                    <CheckCircle2 size={10} />
                                                    Credencial cifrada en Vault. Las sondas de red no requieren instalar agente en el dispositivo.
                                                </p>
                                            </div>
                                        </>
                                    ) : (
                                        /* Para tipos sin agente (URL, IP, DB, Cloud, Container, K8s) */
                                        <div className="flex items-start gap-3 p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl">
                                            <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
                                            <div>
                                                <p className="text-[12px] font-black text-emerald-400 uppercase tracking-widest mb-1">Monitoreo Agentless</p>
                                                <p className="text-[11px] text-slate-400 font-medium leading-relaxed">
                                                    Este tipo de activo se monitorea mediante sondas de red externas (Nuclei, Zeek, SNMP) sin necesidad de instalar software en el destino.
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                    </>)}
                                </>
                            )}
                        </div>

                        {newAsset.asset_type && newAsset.asset_type !== 'SOURCE_ZIP' && (
                            <div className="space-y-3">
                                <button
                                    type="button"
                                    onClick={handleTestConnection}
                                    disabled={!newAsset.endpoint || connTest?.loading}
                                    title="Verifica que la IP responda y, si capturaste usuario y contraseña/llave, que el login SSH y sudo funcionen. No guarda nada."
                                    className="w-full py-3 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-[#06B6D4] border border-[#06B6D4]/30 font-black uppercase text-[11px] tracking-widest rounded-2xl transition-all flex items-center justify-center gap-2"
                                >
                                    <Activity size={14} className={connTest?.loading ? 'animate-spin' : ''} />
                                    {connTest?.loading ? 'Probando conexión…' : 'Probar conexión (ping, usuario y contraseña)'}
                                </button>
                                {connTest && !connTest.loading && (
                                    <div className={`p-4 rounded-2xl border text-xs space-y-2 ${connTest.ok ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/10'}`}>
                                        <p className={`font-black uppercase tracking-widest text-[11px] ${connTest.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                                            {connTest.ok ? '✅ Todo correcto' : '⚠️ Hay problemas'}
                                        </p>
                                        {(connTest.steps || []).map((st) => (
                                            <div key={st.id} className="flex gap-2">
                                                <span>{st.status === 'ok' ? '✅' : st.status === 'fail' ? '❌' : '➖'}</span>
                                                <div>
                                                    <p className="text-white font-bold">{st.label}</p>
                                                    <p className="text-slate-400 leading-relaxed">{st.detail}</p>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        <div className="pt-2">
                            <button
                                type="submit"
                                disabled={!newAsset.asset_type}
                                title={!newAsset.asset_type ? 'Selecciona un tipo de activo para continuar' : 'Registrar el activo y activar monitoreo'}
                                className={`w-full py-4 font-black uppercase text-[12px] tracking-widest rounded-2xl transition-all shadow-lg ${
                                    newAsset.asset_type
                                        ? 'bg-[#06B6D4] text-[#0F172A] hover:bg-white shadow-[#06B6D4]/10 cursor-pointer'
                                        : 'bg-slate-800 text-slate-600 cursor-not-allowed shadow-none'
                                }`}
                            >
                                {newAsset.asset_type ? 'Registrar y Activar Monitoreo' : '— Seleccione tipo de activo —'}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
  )
}

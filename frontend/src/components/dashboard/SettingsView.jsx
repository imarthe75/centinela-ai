// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, ChevronDown, Cpu, ShieldCheck, Zap } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function SettingsView() {
  const { availableModels, configLoading, configSaving, fetchModelsForProvider, fetchSystemConfig, handleSaveConfig, loadingModels, setSystemConfig, systemConfig } = useDashboard()
  return (
<div className="space-y-8 animate-in fade-in duration-300">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Cpu className="text-[#06B6D4]" size={28} />
                            Configuración del Sistema & Agentes
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                            Administración centralizada de API Keys, Endpoints de Agentes, Integraciones y Políticas
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button 
                            onClick={fetchSystemConfig} 
                            className="bg-[#0F172A] border border-slate-800 text-slate-300 hover:text-white px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2"
                        >
                            <Activity size={14} className={configLoading ? "animate-spin text-[#06B6D4]" : ""} />
                            Recargar
                        </button>
                        <button 
                            onClick={handleSaveConfig} 
                            disabled={configSaving}
                            className="bg-[#06B6D4] text-[#0F172A] hover:bg-white px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider transition-all shadow-lg shadow-[#06B6D4]/20 flex items-center gap-2"
                        >
                            <ShieldCheck size={16} />
                            {configSaving ? 'Guardando...' : 'Guardar Cambios'}
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-6">
                    {['LLM_AGENTS', 'SECURITY_AGENTS', 'INTEGRATIONS', 'POLICY_RULES'].map((cat, cIdx) => {
                        const items = systemConfig.filter(s => s.category === cat)
                        const categoryTitles = {
                            LLM_AGENTS: '🧠 Agentes de Inteligencia Artificial (LLM & Inference)',
                            SECURITY_AGENTS: '🛡️ Agentes de Seguridad (Wazuh EDR, Zeek NIDS, Falco)',
                            INTEGRATIONS: '🔌 Integraciones Externas (Authentik, GitLab, HashiCorp Vault)',
                            POLICY_RULES: '⚙️ Políticas de Autonomía & SLAs de Seguridad'
                        }
                        if (items.length === 0) return null
                        return (
                            <div key={cIdx} className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8 space-y-6">
                                <h3 className="text-white font-bold text-lg border-b border-slate-800 pb-4">
                                    {categoryTitles[cat] || cat}
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    {items.map((item, idx) => (
                                        <div key={idx} className="space-y-2">
                                            <div className="flex justify-between items-center">
                                                <label className="text-[12px] font-black text-slate-400 uppercase tracking-widest block flex items-center gap-2">
                                                    {item.key}
                                                </label>
                                                {item.key === 'AI_MODEL' && (
                                                    <button 
                                                        type="button" 
                                                        onClick={() => {
                                                            const currentProv = systemConfig.find(s => s.key === 'AI_PROVIDER')?.value || 'nvidia_nim'
                                                            fetchModelsForProvider(currentProv)
                                                        }}
                                                        className="text-[11px] font-black text-[#06B6D4] hover:underline uppercase tracking-wider flex items-center gap-1"
                                                    >
                                                        <Zap size={10} />
                                                        {loadingModels ? 'Cargando...' : 'Cargar Modelos Disponibles'}
                                                    </button>
                                                )}
                                            </div>

                                            {item.key === 'AI_PROVIDER' ? (
                                                <div className="relative">
                                                    <select 
                                                        className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 pr-12 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                        value={item.value || 'nvidia_nim'}
                                                        onChange={(e) => {
                                                            const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                            setSystemConfig(updated)
                                                            fetchModelsForProvider(e.target.value)
                                                        }}
                                                        title="Seleccionar proveedor de LLM para el motor de análisis SOAR e IA"
                                                    >
                                                        <option value="smart_router">Smart Router Global (Automático con Fallback)</option>
                                                        <option value="nvidia_nim">NVIDIA NIM Cloud / Inference</option>
                                                        <option value="google_genai">Google AI Studio (Gemini)</option>
                                                        <option value="groq">Groq Cloud (Llama / Mixtral)</option>
                                                        <option value="openai">OpenAI (GPT-4o / GPT-4)</option>
                                                        <option value="anthropic">Anthropic (Claude 3.5)</option>
                                                        <option value="ollama">Ollama / Servidor Local / On-Premise</option>
                                                    </select>
                                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                                </div>
                                            ) : item.key === 'AI_MODEL' && availableModels.length > 0 ? (
                                                <div className="relative">
                                                    <select 
                                                        className="w-full bg-[#0F172A] border border-[#06B6D4]/50 rounded-2xl p-4 pr-12 text-[#06B6D4] font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                        value={item.value || ''}
                                                        onChange={(e) => {
                                                            const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                            setSystemConfig(updated)
                                                        }}
                                                        title="Seleccionar modelo específico del proveedor de IA"
                                                    >
                                                        {availableModels.map((m, mIdx) => (
                                                            <option key={mIdx} value={m}>{m}</option>
                                                        ))}
                                                    </select>
                                                    <ChevronDown size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-[#06B6D4]/50 pointer-events-none" />
                                                </div>
                                            ) : (
                                                <input 
                                                    type={item.key.includes('KEY') || item.key.includes('SECRET') || item.key.includes('TOKEN') ? 'password' : 'text'} 
                                                    className="w-full bg-[#0F172A] border border-slate-800 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-[#06B6D4] outline-none"
                                                    value={item.value || ''}
                                                    onChange={(e) => {
                                                        const updated = systemConfig.map(s => s.key === item.key ? { ...s, value: e.target.value } : s)
                                                        setSystemConfig(updated)
                                                    }}
                                                />
                                            )}
                                            <p className="text-[11px] text-slate-500 font-medium">{item.description}</p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )
                    })}
                </div>
            </div>
  )
}

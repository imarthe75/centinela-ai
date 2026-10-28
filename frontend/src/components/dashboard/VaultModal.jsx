// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, AlertTriangle, CheckCircle2, KeyRound, Lock, Shield, XCircle } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function VaultModal() {
  const { handleSaveVaultSecret, setShowVaultModal, setVaultAuthType, setVaultPassword, setVaultSshKey, setVaultUser, vaultAuthType, vaultPassword, vaultResult, vaultSaving, vaultSshKey, vaultTarget, vaultUser } = useDashboard()
  return (
<div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-[#0F172A]/90 backdrop-blur-md animate-in fade-in duration-300">
                <div className="bg-[#1E293B] w-full max-w-lg rounded-[48px] border border-slate-800 shadow-2xl overflow-hidden animate-in zoom-in-95 duration-500">
                    <div className="p-8 border-b border-slate-800 bg-gradient-to-br from-amber-400/10 to-transparent flex justify-between items-center">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-amber-400/10 border border-amber-400/20 flex items-center justify-center text-amber-400">
                                <Lock size={24} />
                            </div>
                            <div>
                                <h3 className="text-white font-bold text-xl tracking-tighter">Credencial Sudo — Vault</h3>
                                <p className="text-[12px] text-amber-400/70 font-black uppercase tracking-widest mt-0.5">
                                    {vaultTarget}
                                </p>
                            </div>
                        </div>
                        <button onClick={() => setShowVaultModal(false)} className="text-slate-500 hover:text-white transition-all">
                            <XCircle size={28} />
                        </button>
                    </div>

                    <form onSubmit={handleSaveVaultSecret} className="p-8 space-y-5">
                        <div>
                            <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Usuario SSH / Ansible
                            </label>
                            <input
                                type="text"
                                className="w-full bg-[#0F172A] border border-slate-700 rounded-2xl p-4 text-white font-bold text-sm focus:ring-2 focus:ring-amber-400 outline-none placeholder-slate-600"
                                placeholder="ej. ia, root, ansible_user"
                                value={vaultUser}
                                onChange={(e) => setVaultUser(e.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                Método de Credencial
                            </label>
                            <div className="flex gap-3 mb-4">
                                <button
                                    type="button"
                                    onClick={() => setVaultAuthType('PASSWORD')}
                                    className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all border ${vaultAuthType === 'PASSWORD' ? 'bg-amber-400/20 border-amber-400 text-amber-300' : 'bg-[#0F172A] border-slate-700 text-slate-400'}`}
                                >
                                    🔑 Contraseña Sudo
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setVaultAuthType('SSH_KEY')}
                                    className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all border ${vaultAuthType === 'SSH_KEY' ? 'bg-amber-400/20 border-amber-400 text-amber-300' : 'bg-[#0F172A] border-slate-700 text-slate-400'}`}
                                >
                                    📜 Llave Privada SSH (.pem / RSA)
                                </button>
                            </div>
                        </div>

                        {vaultAuthType === 'SSH_KEY' ? (
                            <div>
                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                    Llave Privada SSH (PEM / RSA / OpenSSH) *
                                </label>
                                <textarea
                                    rows={5}
                                    required
                                    className="w-full bg-[#0F172A] border border-amber-400/30 rounded-2xl p-4 text-amber-300 font-mono text-xs focus:ring-2 focus:ring-amber-400 outline-none placeholder-slate-700 resize-none"
                                    placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEowIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
                                    value={vaultSshKey}
                                    onChange={(e) => setVaultSshKey(e.target.value)}
                                    autoFocus
                                />
                                <p className="text-[11px] text-amber-400/60 mt-2 flex items-center gap-1 font-medium">
                                    <CheckCircle2 size={10} />
                                    Cifrado AES-256 en HashiCorp Vault. La llave privada se guarda de forma totalmente confidencial.
                                </p>
                            </div>
                        ) : (
                            <div>
                                <label className="text-[12px] font-black text-slate-500 uppercase tracking-widest block mb-2">
                                    Contraseña Sudo *
                                </label>
                                <div className="relative">
                                    <input
                                        type="password"
                                        required
                                        className="w-full bg-[#0F172A] border border-amber-400/30 rounded-2xl p-4 text-amber-300 font-bold text-sm focus:ring-2 focus:ring-amber-400 outline-none pr-12 placeholder-slate-700"
                                        placeholder="••••••••••••"
                                        value={vaultPassword}
                                        onChange={(e) => setVaultPassword(e.target.value)}
                                        autoFocus
                                    />
                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 text-amber-400/40">
                                        <Shield size={16} />
                                    </div>
                                </div>
                                <p className="text-[11px] text-amber-400/60 mt-2 flex items-center gap-1 font-medium">
                                    <CheckCircle2 size={10} />
                                    Cifrado AES-256 en HashiCorp Vault. No se almacena en la BD ni en el frontend.
                                </p>
                            </div>
                        )}

                        {vaultResult && (
                            <div className={`p-4 rounded-2xl text-xs font-bold flex items-center gap-2 ${vaultResult.ok ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                                {vaultResult.ok ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                                {vaultResult.msg}
                            </div>
                        )}

                        <div className="pt-2 flex gap-3">
                            <button
                                type="submit"
                                disabled={vaultSaving || (vaultAuthType === 'PASSWORD' ? !vaultPassword : !vaultSshKey)}
                                className="flex-1 py-4 bg-amber-500 text-[#0F172A] font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-amber-400 transition-all shadow-lg shadow-amber-500/20 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {vaultSaving ? (
                                    <><Activity size={14} className="animate-spin" /> Guardando...</>
                                ) : (
                                    <><KeyRound size={14} /> Guardar en Vault</>
                                )}
                            </button>
                            <button
                                type="button"
                                onClick={() => setShowVaultModal(false)}
                                className="px-6 py-4 bg-slate-800 text-white font-black uppercase text-[12px] tracking-widest rounded-2xl hover:bg-slate-700 transition-all"
                            >
                                Cancelar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
  )
}

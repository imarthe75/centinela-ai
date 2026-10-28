// Generated from Dashboard.jsx by scratch/extract_dashboard.mjs (ADR-0008 #2): code moved verbatim; state comes from DashboardContext.
import { Activity, ChevronDown, Users } from 'lucide-react'
import { useDashboard } from './DashboardContext'

export default function UsersView() {
  const { currentUserRole, fetchUsers, handleUpdateUserRole, usersList, usersLoading } = useDashboard()
  return (
<div className="space-y-8 animate-in fade-in duration-300">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-white font-bold text-2xl mb-1 flex items-center gap-3">
                            <Users className="text-[#06B6D4]" size={28} />
                            Gestión de Usuarios y Roles (Authentik IDP)
                        </h2>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">
                            Control de Acceso Basado en Roles (RBAC) sincronizado con Authentik Central
                        </p>
                    </div>
                    <button 
                        onClick={fetchUsers} 
                        className="bg-[#0F172A] border border-slate-800 text-slate-300 hover:text-white px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2"
                    >
                        <Activity size={14} className={usersLoading ? "animate-spin text-[#06B6D4]" : ""} />
                        Refrescar desde Authentik
                    </button>
                </div>

                <div className="bg-[#1E293B] rounded-[32px] border border-slate-800 p-8">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="border-b border-slate-800 text-[12px] font-black text-slate-500 uppercase tracking-widest">
                                    <th className="pb-4">Usuario</th>
                                    <th className="pb-4">Nombre Completo</th>
                                    <th className="pb-4">Correo Electrónico</th>
                                    <th className="pb-4">Rol en Centinela</th>
                                    <th className="pb-4 text-right">Acción / Permisos</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                                {usersList.map((usr, idx) => (
                                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                                        <td className="py-4 text-sm font-bold text-white flex items-center gap-3">
                                            <div className="w-8 h-8 rounded-lg bg-[#06B6D4]/10 border border-[#06B6D4]/30 flex items-center justify-center text-[#06B6D4] font-black text-xs">
                                                {usr.username?.[0]?.toUpperCase()}
                                            </div>
                                            {usr.username}
                                        </td>
                                        <td className="py-4 text-xs font-bold text-slate-300">{usr.name ||usr.username}</td>
                                        <td className="py-4 text-xs font-bold text-slate-400">{usr.email || 'N/A'}</td>
                                        <td className="py-4">
                                             <span className={`px-3 py-1 rounded-lg text-[12px] font-black uppercase tracking-wider ${
                                                 usr.role === 'Admin' ? 'bg-[#06B6D4]/20 text-[#06B6D4] border border-[#06B6D4]/30' :
                                                 usr.role === 'Analyst' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' :
                                                 usr.role === 'Auditor' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                                 usr.role === 'Disabled' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                                                 'bg-slate-800 text-slate-400 border border-slate-700'
                                             }`}>
                                                 {usr.role === 'Admin' ? '🛡️ Administrador' :
                                                  usr.role === 'Analyst' ? '⚡ Analista SOC' :
                                                  usr.role === 'Auditor' ? '📋 Auditor Seg' :
                                                  usr.role === 'Disabled' ? '⛔ Deshabilitado' : '👁️ Visualizador'}
                                             </span>
                                         </td>
                                         <td className="py-4 text-right">
                                             {currentUserRole === 'Admin' ? (
                                                 <div className="relative inline-block">
                                                     <select 
                                                         value={usr.role}
                                                         onChange={(e) => handleUpdateUserRole(usr.username, e.target.value)}
                                                         className="bg-[#0F172A] border border-slate-700 text-white font-bold text-xs rounded-xl px-3 py-2 pr-8 focus:ring-2 focus:ring-[#06B6D4] outline-none appearance-none cursor-pointer"
                                                     >
                                                         <option value="Admin">🛡️ Administrador (Acceso Total)</option>
                                                         <option value="Analyst">⚡ Analista SOC (Operación / Remediar)</option>
                                                         <option value="Auditor">📋 Auditor (Auditoría / Reportes)</option>
                                                         <option value="Viewer">👁️ Visualizador (Sólo Lectura)</option>
                                                        <option value="Disabled">⛔ Deshabilitado (Sin acceso)</option>
                                                     </select>
                                                     <ChevronDown size={14} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                                 </div>
                                             ) : (
                                                 <span className="text-[12px] font-bold text-slate-600 uppercase">Sin Privilegios</span>
                                             )}
                                         </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
  )
}

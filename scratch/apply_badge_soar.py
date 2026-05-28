filepath = '/home/ia/ecosistema-casmarts/centinela-ai/frontend/src/components/Dashboard.jsx'
with open(filepath, 'r') as f:
    content = f.read()

target = """                                                <td className="p-6">
                                                    <div className="flex items-center gap-2">
                                                        {log.cve_id === 'SCAN-AUDIT' ? (
                                                            <span className="text-[9px] font-black text-blue-400 uppercase tracking-tighter">FINALIZADO (SIN HALLAZGOS)</span>
                                                        ) : log.executed_bool ? (
                                                            <span className="text-[9px] font-black text-emerald-500 uppercase">REMEDIADO</span>
                                                        ) : (
                                                            <span className={`text-[9px] font-black uppercase ${
                                                                log.status === 'CORRELATED' ? 'text-[#06B6D4]' : 
                                                                log.status === 'AI_FAILED' ? 'text-red-400' : 'text-orange-500 animate-pulse'
                                                            }`}>
                                                                {log.status === 'CORRELATED' ? 'LISTO PARA APROBAR' : 
                                                                 log.status === 'AI_FAILED' ? 'FALLO IA (REINTENTANDO)' : 
                                                                 log.status === 'NEW' || log.status === 'PENDING' ? 'PENDIENTE IA' : log.status}
                                                            </span>
                                                        )}
                                                    </div>
                                                </td>"""

replacement = """                                                <td className="p-6">
                                                    <div className="flex items-center gap-2">
                                                        {['db-primary', 'db-replica-1', 'db-replica-2', 'cache', 'vault', 'gateway', 'storage', 'netdata', 'dozzle', 'opensign-mongo'].some(h => log.asset_name?.toLowerCase().includes(h)) ? (
                                                            <span className="text-[9px] font-black text-cyan-400 uppercase bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20" title="Mitigado nativamente mediante Hardening">SEGURO (HARDENING)</span>
                                                        ) : ['plane', 'penpot', 'gitea', 'redmine', 'camunda', 'sonar', 'wiki', 'drawio', 'plantuml', 'opendesign'].some(t => log.asset_name?.toLowerCase().includes(t)) ? (
                                                            <span className="text-[9px] font-black text-slate-400 uppercase bg-slate-800 px-2 py-0.5 rounded border border-slate-700" title="Soporte y remediaciones a cargo de proveedor">PROVEEDOR (SUITE)</span>
                                                        ) : log.cve_id === 'SCAN-AUDIT' ? (
                                                            <span className="text-[9px] font-black text-blue-400 uppercase tracking-tighter">FINALIZADO (SIN HALLAZGOS)</span>
                                                        ) : log.executed_bool ? (
                                                            <span className="text-[9px] font-black text-emerald-500 uppercase">REMEDIADO</span>
                                                        ) : (
                                                            <span className={`text-[9px] font-black uppercase ${
                                                                log.status === 'CORRELATED' ? 'text-[#06B6D4]' : 
                                                                log.status === 'AI_FAILED' ? 'text-red-400' : 'text-orange-500 animate-pulse'
                                                            }`}>
                                                                {log.status === 'CORRELATED' ? 'LISTO PARA APROBAR' : 
                                                                 log.status === 'AI_FAILED' ? 'FALLO IA (REINTENTANDO)' : 
                                                                 log.status === 'NEW' || log.status === 'PENDING' ? 'PENDIENTE IA' : log.status}
                                                            </span>
                                                        )}
                                                    </div>
                                                </td>"""

content_normalized = content.replace('\r\n', '\n')
target_normalized = target.replace('\r\n', '\n')

if target_normalized in content_normalized:
    content_normalized = content_normalized.replace(target_normalized, replacement)
    with open(filepath, 'w') as f:
        f.write(content_normalized)
    print('SUCCESS')
else:
    print('TARGET NOT FOUND')

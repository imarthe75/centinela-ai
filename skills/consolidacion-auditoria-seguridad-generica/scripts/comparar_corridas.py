#!/usr/bin/env python3
"""Compara dos corridas de Centinela (salida de parse_centinela.py) para verificar el cierre de hallazgos: qué se resolvió, qué es nuevo y qué persiste.

Uso: python comparar_corridas.py <antes.json> <despues.json> [--salida cierre.json] [--grupo-prefijo grupo/sistema]

La llave de una ocurrencia es (repositorio, regla, archivo, línea). Solo se concluye sobre reglas cuyas ubicaciones están COMPLETAS en ambas corridas: si el PDF recortó la
lista («Se muestran 60 de 81 archivos») en alguna de las dos, lo que desapareció puede ser solo lo que dejó de listarse, y se reporta como NO CONCLUYENTE.
Cuando el código se editó, las líneas se desplazan: una ocurrencia «resuelta» y otra «nueva» de la misma regla y archivo con el mismo conteo se marcan como POSIBLE DESPLAZAMIENTO
(hay que mirar el código; no se asume ni resuelto ni persistente).

Es la evidencia que pide el criterio de cierre «re-escaneo de Centinela sin la huella», pero sin acceso a su base de datos. NO sustituye la prueba funcional (p. ej. rol sin privilegio -> 403).
"""
import collections
import json
import sys


def occurrences(parsed):
    """{(repo, rule, file, line): sev} plus the set of (repo, rule) whose location list is not reliable."""
    occ, unreliable = {}, set()
    for repo, items in parsed.items():
        for it in items:
            rule = it['rule']
            shown = sum(max(1, len(u['lines'])) for u in it.get('ubicaciones') or [])
            if it.get('truncado') or (it.get('n_ubic_declaradas') and shown < it['n_ubic_declaradas']) or (not it.get('ubicaciones') and it['n']):
                unreliable.add((repo, rule))
            for u in it.get('ubicaciones') or []:
                for ln in (u['lines'] or [None]):
                    occ[(repo, rule, u['file'], ln)] = it['sev']
    return occ, unreliable


def compare(antes, despues):
    a, ua = occurrences(antes)
    d, ud = occurrences(despues)
    unreliable = ua | ud
    res = collections.defaultdict(list)
    for k in sorted(set(a) | set(d), key=lambda x: (x[0], x[1], x[2], x[3] or 0)):
        if (k[0], k[1]) in unreliable:
            res['no_concluyente'].append(k)
        elif k in a and k in d:
            res['persisten'].append(k)
        elif k in a:
            res['resueltas'].append(k)
        else:
            res['nuevas'].append(k)
    # moved lines: same repo/rule/file lost and gained the same number of occurrences
    lost = collections.Counter((k[0], k[1], k[2]) for k in res['resueltas'])
    gained = collections.Counter((k[0], k[1], k[2]) for k in res['nuevas'])
    moved = {key for key in lost if lost[key] == gained.get(key)}
    res['posible_desplazamiento'] = [k for k in res['resueltas'] if (k[0], k[1], k[2]) in moved]
    res['resueltas'] = [k for k in res['resueltas'] if (k[0], k[1], k[2]) not in moved]
    res['nuevas'] = [k for k in res['nuevas'] if (k[0], k[1], k[2]) not in moved]
    return res, unreliable


def main(path_a, path_d, salida=None, prefijo=None):
    antes, despues = json.load(open(path_a, encoding='utf-8')), json.load(open(path_d, encoding='utf-8'))
    if prefijo:
        antes = {r: v for r, v in antes.items() if any((i.get('asset') or '').find(prefijo) >= 0 for i in v)}
        despues = {r: v for r, v in despues.items() if any((i.get('asset') or '').find(prefijo) >= 0 for i in v)}
    res, unreliable = compare(antes, despues)
    only_a, only_d = sorted(set(antes) - set(despues)), sorted(set(despues) - set(antes))
    if only_a:
        print(f"Repositorios que estaban y ya no vienen en la segunda corrida (NO es lo mismo que «resueltos»): {', '.join(only_a)}")
    if only_d:
        print(f"Repositorios nuevos en la segunda corrida: {', '.join(only_d)}")
    print(f"{'repositorio':34} {'resueltas':>9} {'nuevas':>7} {'persisten':>9} {'¿desplaz.?':>10} {'no concl.':>9}")
    for repo in sorted(set(antes) | set(despues)):
        c = {k: sum(1 for x in v if x[0] == repo) for k, v in res.items()}
        print(f"{repo:34} {c.get('resueltas', 0):9} {c.get('nuevas', 0):7} {c.get('persisten', 0):9} {c.get('posible_desplazamiento', 0):10} {c.get('no_concluyente', 0):9}")
    print(f"TOTAL{'':29} {len(res['resueltas']):9} {len(res['nuevas']):7} {len(res['persisten']):9} {len(res['posible_desplazamiento']):10} {len(res['no_concluyente']):9}")
    if unreliable:
        print(f"\n{len(unreliable)} reglas con ubicaciones incompletas en alguna corrida: su desaparición NO prueba cierre (revisar en el dashboard de Centinela).")
    if salida:
        json.dump({k: [list(x) for x in v] for k, v in res.items()}, open(salida, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f"Detalle: {salida}")


if __name__ == '__main__':
    argv = sys.argv[1:]
    opts = {}
    for flag, key in (('--salida', 'salida'), ('--grupo-prefijo', 'prefijo')):
        if flag in argv:
            i = argv.index(flag)
            opts[key] = argv[i + 1]
            del argv[i:i + 2]
    if len(argv) < 2:
        sys.exit(__doc__)
    main(argv[0], argv[1], **opts)

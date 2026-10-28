"""Static check: every global name a function uses must exist in its module (or be a builtin). Catches the NameError class of bug that only
shows up when a rarely-run function finally executes. usage (inside a container): python scripts/check_globals.py module [module...]"""
import builtins, importlib, symtable, sys
sys.path.insert(0, "/app")
bad = 0
for modname in sys.argv[1:]:
    mod = importlib.import_module(modname)
    src = open(mod.__file__).read()
    def walk(t, path):
        global bad
        for s in t.get_symbols():
            if t.get_type() == "function" and s.is_global() and s.is_referenced():
                nm = s.get_name()
                if not hasattr(mod, nm) and not hasattr(builtins, nm):
                    print(f"UNDEFINED {modname}: {nm} used in {path}")
                    bad += 1
        for c in t.get_children():
            walk(c, f"{path}.{c.get_name()}" if path else c.get_name())
    walk(symtable.symtable(src, mod.__file__, "exec"), "")
print("módulos revisados:", len(sys.argv) - 1, "| nombres indefinidos:", bad)
sys.exit(1 if bad else 0)

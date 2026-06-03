# Plantilla base para registrar Habilidades y Herramientas a través de MCP (Model Context Protocol)

class ExampleMCPSkill:
    """
    Las habilidades MCP permiten que el Agente Residente ejecute comandos seguros en el host
    respetando los límites del Sandbox.
    """
    def __init__(self):
        self.name = "sys_explorer"
        self.description = "Permite inspeccionar directorios del sistema de archivos local de forma autorregulada."

    def execute(self, path: str) -> dict:
        import os
        try:
            # Control cognitivo antes de actuar (ECC)
            if not os.path.exists(path):
                return {"status": "error", "message": "El path proveído no existe en el host."}
            
            contents = os.listdir(path)
            return {
                "status": "success",
                "path": path,
                "contents": contents[:15] # Limitar salida para higiene de contexto
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

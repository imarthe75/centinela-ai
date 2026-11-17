// Mensajes de commit con Conventional Commits (rules/common/git-workflow.md). Plantilla del kit.
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    // Mensajes en español con acentos y nombres propios: no forzar minúsculas en el asunto.
    "subject-case": [0],
    "header-max-length": [2, "always", 100],
  },
};

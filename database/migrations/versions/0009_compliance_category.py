"""Accessibility (WCAG) findings move to their own finding category: COMPLIANCE.

Owner decision 2026-10-29: accessibility is a legal/contractual compliance requirement for the public-sector projects audited here, not
a security vulnerability. Those findings keep their SLA, AI analysis and visibility, but are counted apart from the vulnerability
headline. New writes are classified by core.deduplication_engine.classify_finding_category(); this migration reclassifies existing rows
with the same rule (cve_id WCAG-* / ACCESSIBILITY-WCAG*, or engines accessibility-wcag / wcag-render) and the comparison baselines that
snapshot the category.
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

_RULE = "(cve_id LIKE 'WCAG-%' OR cve_id LIKE 'ACCESSIBILITY-WCAG%' OR scan_engine IN ('accessibility-wcag', 'wcag-render'))"


def upgrade():
    op.execute(f"""
        UPDATE public.vulnerability_log SET finding_category = 'COMPLIANCE'
         WHERE {_RULE} AND finding_category IS DISTINCT FROM 'COMPLIANCE';
        UPDATE public.scan_run_baseline SET finding_category = 'COMPLIANCE'
         WHERE {_RULE} AND finding_category IS DISTINCT FROM 'COMPLIANCE';
        COMMENT ON COLUMN public.vulnerability_log.finding_category IS
            'VULNERABILITY = vulnerabilidad de seguridad accionable; COMPLIANCE = requisito de cumplimiento (accesibilidad WCAG 2.1), con SLA pero fuera del total de vulnerabilidades; INFORMATIONAL = marcador, métrica de calidad o deuda de proceso. Fuente única: core/deduplication_engine.classify_finding_category().';
    """)


def downgrade():
    op.execute("""
        UPDATE public.vulnerability_log SET finding_category = 'VULNERABILITY' WHERE finding_category = 'COMPLIANCE';
        UPDATE public.scan_run_baseline SET finding_category = 'VULNERABILITY' WHERE finding_category = 'COMPLIANCE';
    """)

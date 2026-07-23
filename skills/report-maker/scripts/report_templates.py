"""Report Maker — template & string producers (presentation strings only).

Pure string builders: Markdown/HTML wrappers, CSV tables, content templates
(briefing, digest, contract, ...), and Markdown→Typst conversion strings.
No I/O side effects beyond reading bundled template files / CSV inputs.

Implementations extracted to focused modules:
- report_templates_base.py:     md_template, html_template, table_from_csv, _format_list_item
- report_templates_brief.py:    _briefing_template, _daily_digest_template, _contract_template
- report_templates_security.py: _watchlist_template, _incident_report_template,
                                 _security_audit_template, _timeline_template
- report_templates_typst.py:    _escape_typst, _md_to_typst, _build_typst
"""
from report_templates_base import (  # noqa: F401
    _format_list_item,
    html_template,
    md_template,
    table_from_csv,
)
from report_templates_brief import (  # noqa: F401
    _briefing_template,
    _contract_template,
    _daily_digest_template,
)
from report_templates_security import (  # noqa: F401
    _incident_report_template,
    _security_audit_template,
    _timeline_template,
    _watchlist_template,
)
from report_templates_typst import (  # noqa: F401
    _build_typst,
    _escape_typst,
    _md_to_typst,
)

"""Display/formatting helpers for judge-facing reports.

Keeps ``finding_id`` (F followed by a zero-padded sequence number) as the internal canonical key --
state files, caches, validator, and tests all key off this string --
while rendering user-facing text as "Finding 1".
"""

from sift_sentinel.reporting.display import finding_title
from sift_sentinel.reporting.fallback import (
    apply_schema_warning_banner,
    render_fallback_report,
)
from sift_sentinel.reporting.format import display_finding_id

__all__ = [
    "apply_schema_warning_banner",
    "display_finding_id",
    "finding_title",
    "render_fallback_report",
]

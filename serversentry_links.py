"""Project links shown in exported reports. Single place to change them; no network access."""
from __future__ import annotations

from urllib.parse import quote

REPO_URL = "https://github.com/Kayvooo/ServerSentry"
DOCS_URL = REPO_URL + "/blob/main/docs/"
# Optional: invite link of a support/community server. Leave empty to hide it from reports.
COMMUNITY_URL = ""

PROJECT_LINKS = (
    ("Source code", REPO_URL),
    ("Report an issue", REPO_URL + "/issues/new"),
    ("Changelog", REPO_URL + "/blob/main/CHANGELOG.md"),
    ("License", REPO_URL + "/blob/main/LICENSE"),
)
DOC_LINKS = (
    ("Reports & history", DOCS_URL + "reports.md"),
    ("Rule reference", DOCS_URL + "rules.md"),
    ("Expectations & accepted risks", DOCS_URL + "expectations.md"),
    ("Guided repairs", DOCS_URL + "repairs.md"),
    ("Policy recipes", DOCS_URL + "policy-recipes.md"),
)


def rule_url(code: str) -> str:
    """Anchor of a rule in docs/rules.md (GitHub keeps underscores in heading slugs)."""
    return DOCS_URL + "rules.md#" + quote(code, safe="_")

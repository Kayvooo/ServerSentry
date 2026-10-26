# Contributing to ServerSentry

Keep changes focused and include an example of the user-visible behavior. This project uses the license in `LICENSE`; contributions do not change its terms.

## Local setup

Use Python 3.10 or later and an isolated environment, then:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python serversentry.py demo
```

On Windows, use `py` if needed. Tests and the demo need no token or network connection after dependencies are installed. Offline report commands themselves use only the standard library. To test only those commands without installing Discord dependencies:

```bash
python -m unittest discover -s tests -p test_reports.py -v
```

## Browser checks (optional for local development)

Node 24 and the development dependency in `package-lock.json` are used only for report checks:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

The check generates temporary synthetic reports and verifies filters, expandable evidence, mobile width, escaped server content and absence of external requests. Linux machines may need `npx playwright install --with-deps chromium`. Set `PYTHON` to the path of a Python executable if the `python` command is unavailable. Browser checks run separately in CI; report users do not need Node, npm or Playwright.

## Useful contributions

- Add a synthetic permission scenario that demonstrates a comparison edge case.
- Improve an unclear finding explanation with a concrete next step.
- Fix keyboard navigation, narrow-window layout or filtering behavior.
- Document an installation issue with OS, Python version and sanitized error output.

New rules should include a stable code, rationale, severity, scope limits and meaningful tests. Do not infer server intent solely from names. Update the ruleset metadata when rule behavior changes; see `docs/reports.md`.

## Repair changes

Keep planning separate from Discord writes. `serversentry_repair_model.py` projects actions on plain data; `serversentry_repair_run.py` submits one reviewed primitive at a time. Use fresh REST data for guards and readback. Preserve raw channel coverage flags when converting discord.py objects.

The synthetic adapter in `tests/repair_fakes.py` constructs real discord.py objects and intercepts HTTP methods. Cover repeated target edits, preflight failure, lost responses, partial execution, cancellation, persistence failure and recovery conflicts when changing a write path. A success response alone is insufficient: persist `in_progress` before the request, verify its effect afterward and stop on uncertainty. Never add automatic rollback or silently broaden a reviewed plan.

Recovery must preserve protected targets and privilege checks, require explicit step selection, and refuse unsupported/unknown outcomes. See `docs/repairs.md` for the journal contract and limitations.

## Keep private data out of contributions

Use invented names and short synthetic numeric IDs in fixtures. Do not attach real audit exports, policies, backups, tokens or member state to issues or pull requests. The repository sanitation check flags production-sized IDs and token-shaped strings. If a real token was exposed, rotate it; deleting it from a new commit is insufficient.

The current CI checks selected Python versions on Ubuntu and Windows. Live Discord testing should use an isolated test server and the smallest necessary permissions. Do not add a token to CI to test reports or comparisons.

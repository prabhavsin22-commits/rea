# Verification

Executed on macOS with Node v22.23.1, one change at a time on the state-targets branch, over the 50 published
capture-built environments (each app's latest capture). The served smoke rebuilds each manifest with the tree under
test and applies every served write tool. The serving check answers every recorded read made before the capture's
first write through state serving and compares it with the recording; it reads no calls from the five
browser-scenario captures. The session replay answers every recorded call in order, writes included, through state
serving, reading records with REA's own capture parser, and compares the reads; it covers all 50 captures.

## Gates

- `npm run -s check:fast`, `npm run -s format:check`, `npx knip`, `npm run -s scan:todos`, `npm run -s docs:check`,
  `npm run -s verify:test-discovery` and `npm run -s mcp-catalog:check`: passed.
- `npm run jscpd`: 3.57% duplicated lines over 4174 files (3.58% on the base).
- `npx vitest run --project domain --project services`: 9289 passed, 6 pre-existing skips.
- `npm run -s test:prepare`, then `npm run -s test:focused --` the environment serve and export CLI boundaries, the
  serve and served-writes MCP boundaries, the analysis-view CLI and MCP boundaries, the compact input schema boundary
  and tool schema validity: 8 files, 91 passed.

## Measurements

| Step                         | Served | No state target | State-backed read views | Reads before first write | Session reads  |
| ---------------------------- | ------ | --------------- | ----------------------- | ------------------------ | -------------- |
| state targets                | 62     | 59              | 1,151                   | 2,085 of 2,155           | 2,764 of 3,022 |
| blame and constant guard     | 63     | 59              | 1,151                   | 2,085 of 2,155           | 2,764 of 3,022 |
| update rules                 | 68     | 59              | 1,151                   | 2,085 of 2,155           | 2,763 of 3,022 |
| view order                   | 69     | 59              | 1,151                   | 2,085 of 2,155           | 2,763 of 3,022 |
| bulk writes and item actions | 71     | 48              | 1,151                   | 2,085 of 2,155           | 2,763 of 3,022 |
| per-response members         | 71     | 46              | 1,153                   | 2,087 of 2,162           | 2,766 of 3,031 |
| nested counters              | 71     | 46              | 1,153                   | 2,087 of 2,162           | 2,766 of 3,031 |
| created nested clocks        | 71     | 46              | 1,153                   | 2,087 of 2,162           | 2,766 of 3,031 |
| unshown writes refused       | 69     | 46              | 1,153                   | 2,087 of 2,162           | 2,766 of 3,031 |
| catalog values, atomic bulk  | 69     | 46              | 1,153                   | 2,087 of 2,162           | 2,766 of 3,031 |

All 187 write tools are counted at every step, and the served smoke applies every served write tool.

- **Newly served:** Ghost's post create and update, Metabase's card create and update, n8n's workflow update,
  Navidrome's playlist create, and the NocoDB and Mailpit bulk deletes.
- **No longer served:** Gitea's issue update. Its create, update and read share one second, so the evidence cannot show
  the update stamping `updated_at`, and serving it left the clock as it was.
- **Refused that were briefly served on this branch:** EspoCRM's task update, for the same reason, with `modifiedById`
  absent from its create response.
- **Session reads:** one read is lost at Ghost #74, a 404 right after the served create whose delete the recording
  lacks; Vault #80 answers 404 after an unserved create, as a served read on an entity only a replayed write made does.
- Ghost's create and update accept only the recorded html, and Metabase's create only the recorded collection,
  display, type and query; the served catalog shows those values.

Every change had an independent review that rebuilt it and tried to refute it; the corrections they found are part of
the change. A final review of the whole branch found one wrongly served update (EspoCRM) and the hidden pinned values,
both fixed.

## Not included

- Templating literal ids by value: an opt-in rule served Grafana's folder delete and Vault's policy delete, but both
  targets came from unserved writes, so serving them answered their own recorded calls wrongly.
- Completing a created entity from a later read: it served Bookstack's page create wrongly.
- Soft deletes, appended relation rows, rendered markup, reverse embeds, identity aliases and resource names.

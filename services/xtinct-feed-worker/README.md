# XTINCT Feed Worker reference

This directory is a sanitized, account-neutral Cloudflare Worker reference for the read contracts implemented by the public XTINCT X3 firmware:

- Daily Cards V1: an exact four-entry manifest, deterministic empty-state placeholders, conditional fetches, immutable 32-hex card revisions and optional revision-addressed text reports;
- Inbox V2: bounded decimal-cursor paging, immutable SHA-256 artifacts, expiry/overflow tombstones, a 64-item live cap and idempotent receipt batches;
- producer-facing write routes for publishing sample cards and Inbox artifacts without putting write authority on the X3;
- a private receipt readback route so a producer can consume `like`, `dislike`, `opened`, progress and other device feedback.

It contains no deployed hostname, account ID, email address, API key, bearer token, live data or private producer prompt. Nothing in this folder was deployed or authenticated while preparing the public reference.

## What the X3 calls

Every firmware route below requires `Authorization: Bearer <READ_TOKEN>`.

| Method | Route | Contract |
|---|---|---|
| `GET` | `/v1/manifest.json` | Schema 1 manifest, matching body/HTTP `ETag`, `If-None-Match` and `304` |
| `GET` | `/v1/cards/<task>.json?revision=<revision>` | Immutable requested card snapshot; the unqueried path returns current |
| `GET` | `/v1/reports/<task>/<revision>.txt` | Optional bounded UTF-8 card report |
| `GET` | `/v2/sync?cursor=<decimal>&limit=8` | Schema 2 page of deliveries and tombstones |
| `GET` | `/v2/artifacts/<sha256>` | Immutable artifact with exact length, MIME, quoted digest `ETag` and `nosniff` |
| `POST` | `/v2/acks` | Idempotent event batch; counts accepted, duplicate and rejected events |

The V1 task allowlist is deliberately identical to the firmware:

1. `market-briefing`
2. `weekday-freelancer-scan`
3. `3d-job-search`
4. `outlook-attention-watch`

Inbox V2 supports `card`, `text`, `image-1bit`, `epub`, `action` and `sleep-screen`. The public code enforces the firmware's IDs, lengths, MIME combinations, digest sizes, action vocabulary, two-line digest metadata and page bounds.

## Storage model

- D1 owns current V1 pointers, immutable card snapshots, V2 change cursors, current deliveries and deduplicated acknowledgements.
- R2 owns report and artifact bytes.
- A producer writes immutable bytes first and publishes the D1 pointer second. A failed database commit can leave an unreachable R2 object, but cannot expose a card or delivery that points at half-written bytes.
- V2 delivery and tombstone entries use D1's monotonic integer primary key as the cursor. A newer change for the same `item_id` compacts its older pending change so a page never contains duplicate delivery IDs that the firmware would reject.
- Each V2 sync scans at most 89 newest live rows (88 plus a sentinel), repairs at most 24 expired or overflow items in one D1 transaction, and serves no cursor page until the live set has converged to at most 64 items. Tombstones are inserted and deliveries deleted with the same exact item/delivery/revision predicate, so a concurrent replacement is preserved.
- The sync count and `limit + 1` change rows are read in one D1 batch snapshot. This avoids advancing a device cursor from a page whose `has_more` decision came from a different database state.

This is a small reference service, not a multi-tenant publishing platform. Add Access/WAF policy, rate limits, backups, retention and operational monitoring before accepting untrusted producers.

## Local tests

The unit tests use Node's built-in test runner and do not require Cloudflare credentials or a dependency install:

```powershell
npm test
npm run check
```

Wrangler is pinned exactly in `package.json`. To run the Worker locally, install that pinned tool, copy `.dev.vars.example` to `.dev.vars`, replace both placeholders with different random values of at least 32 printable characters, and apply the D1 migration locally:

```powershell
npm install
npx wrangler d1 migrations apply xtinct-feed-reference --local
npm run dev
```

`.dev.vars` and Wrangler's local state are ignored. Never commit either bearer token.

## Cloudflare resources

No setup command below was run for this public reference. In your own Cloudflare account:

1. Create one D1 database named `xtinct-feed-reference` and one R2 bucket named `xtinct-feed-reference-artifacts`.
2. Replace only the `REPLACE_WITH_D1_DATABASE_ID` placeholder in `wrangler.jsonc`; the R2 bucket name is already non-secret.
3. Apply `migrations/0001_initial.sql` with `wrangler d1 migrations apply`.
4. Store independent 32-256 character `READ_TOKEN` and `WRITE_TOKEN` values with `wrangler secret put`; do not put them in `wrangler.jsonc`.
5. Deploy to the standard two-label `https://<worker>.<account-subdomain>.workers.dev` origin expected by the public firmware policy.
6. Install only the Worker origin and `READ_TOKEN` on the X3 over the firmware's physical USB credential command. Never install the write token on the reader.

The firmware rejects custom domains, paths, query strings, fragments, redirects and non-Workers origins for this public reference build.

## Publishing a V1 card

Use the separate `WRITE_TOKEN` on every `/admin/` route. The request JSON in `examples/v1-card.json` is fictional. The Worker derives the 32-hex revision, report digest, byte count and immutable report URL.

```text
PUT /admin/v1/cards/market-briefing
Authorization: Bearer <WRITE_TOKEN>
Content-Type: application/json

<examples/v1-card.json>
```

An AI or scheduled task should validate its complete result before making this single external write. The endpoint is idempotent for byte-identical content.

When no producer has published a task yet, the manifest still contains all four firmware task IDs in firmware order. The Worker derives a stable empty-state card for that task. Its current URL is `private, no-cache`; the matching revision-pinned URL is `private, immutable`; unrelated revisions and placeholder reports are `404`. A retained D1 row with mismatched card identity is treated as corruption and stops safely with `500` instead of being hidden behind a placeholder.

## Publishing an Inbox V2 item

Publishing is intentionally two-phase so the feed never advertises unknown bytes.

First compute the lowercase SHA-256 of the exact artifact and upload those raw bytes:

```text
PUT /admin/v2/artifacts/<sha256>?kind=text
Authorization: Bearer <WRITE_TOKEN>
Content-Type: text/plain; charset=utf-8

<raw UTF-8 artifact bytes>
```

Then replace the placeholder digest in `examples/v2-delivery.json` and publish the delivery:

```text
POST /admin/v2/deliveries
Authorization: Bearer <WRITE_TOKEN>
Content-Type: application/json

<examples/v2-delivery.json>
```

The Worker derives the 64-hex delivery revision. Republish an `item_id` to create a new delivery change. To withdraw its currently active revision:

```text
DELETE /admin/v2/deliveries/<item_id>
Authorization: Bearer <WRITE_TOKEN>
```

That publishes a revision-bound tombstone. The reference keeps the newest pending change per `item_id`; deleted cursor numbers remain gaps and are never reused.

Expiry and capacity enforcement happens at sync time. Expired rows are repaired before overflow is calculated, then only the newest 64 non-expired rows are retained. A repair that needs another bounded pass, or that observes a concurrent replacement, returns `503 repair_pending` with `Retry-After: 1` and no cursor; the client must retry the same cursor. Publishing remains a short atomic write and does not claim that later repair or device sync has happened.

The deliberately simple D1 schema has no per-device acknowledged sync cursor. It therefore retains one pending delivery or tombstone change per `item_id` until that item is replaced; tombstones are not pruned merely because one reader may have observed them. Add an explicit device-cursor/retention design before introducing tombstone cleanup. R2 artifact lifecycle cleanup is a separate operation and must not remove bytes referenced by a live delivery.

## Reading device feedback

The X3 retries acknowledgement events safely by `event_id`. A producer or adapter can read a bounded newest-first sample using the write token:

```text
GET /admin/v2/acks?limit=100
Authorization: Bearer <WRITE_TOKEN>
```

Returned event types include `like`, `dislike`, `opened`, `downloaded`, `progress`, `deleted`, state actions and device status. Treat these as device receipts, not proof that a scheduled producer ran unattended.

## Sleep-screen boundary

The upload route checks the exact X3 native header: 528x792, uncompressed 4-bpp BMP, 209,158 bytes, with the four native 0/85/170/255 palette entries. It does **not** have the original master image and therefore cannot prove crop, tonal preservation, edge retention or absence of visible periodic patterns. Before publishing a `sleep-screen` artifact, run the repository's `scripts/check_x3_sleep_screen.py` against the exact original master. Physical E-Ink appearance remains a hardware check.

## Deliberate omissions

- No email, Gmail, Sheets, Gemini, Grok, ChatGPT or other account integration is embedded. Those are producer adapters and should call the write routes with their own secret management.
- No private prompts, schedules, recipient addresses, task IDs beyond the firmware's public V1 allowlist, or real content are included.
- No UI, billing, user directory or public write endpoint is provided.
- Local tests and a successful deployment do not prove a specific X3 synced or opened content.

The service is covered by the repository's GPL-3.0-or-later license. Cloudflare platform services and Wrangler have their own terms and licenses.

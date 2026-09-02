# Architecture

XTINCT separates content production, private publication and constrained device consumption.

## Producers

A producer can be an AI scheduled task, an Apps Script, a local program or a manual publisher. Producers never talk directly to the X3. They emit one of the documented bounded contracts to an operator-owned relay.

The public [Scheduled AI content producer guide](SCHEDULED_AI_CONTENT_PRODUCERS.md)
shows how recurring ChatGPT/Codex, Gemini Spark, and Grok tasks can emit those
contracts. It includes sanitized content prompts and excludes the operator's
private Grok content prompt.

Typical implemented content jobs include:

- daily/weekly project watchlist cards;
- calendar deadlines and plans;
- an original fiction serial with like/dislike feedback;
- a daily puzzle page;
- a three-article reading batch;
- a Today digest EPUB;
- generated sleep-screen candidates;
- operator-defined private modules that are outside this public reference.

The names above describe content shapes, not bundled accounts or prompts. Public examples use synthetic people, projects, addresses and content.

## Private relay

The relay owns authentication, producer admission, persistence and device delivery. The X3 firmware expects one canonical Cloudflare Workers origin and a reader bearer provisioned as an atomic pair.

### Cards V1

Cards V1 is the tiny glanceable path:

- one manifest with revisions and SHA-256 metadata;
- four bounded card objects;
- conditional requests and cache-first rendering;
- atomic staging before the active set changes;
- explicit refresh progress and safe failure messages.

### Inbox V2

Inbox V2 is the durable reading path:

- cursor-based bounded paging;
- immutable artifacts addressed by SHA-256;
- text, EPUB and native X3 BMP kinds;
- byte count, MIME and digest admission checks;
- sidecar metadata and atomic promotion;
- open/delete actions;
- like/dislike feedback;
- download/open/delete/feedback receipts;
- a bounded retryable outbox;
- tombstones and cursor-zero recovery.

The device downloads into a candidate path, verifies the complete artifact, then promotes it. Interrupted or malformed responses do not replace a known-good local artifact.

## X3 firmware

The ESP32-C3 is the constrained client. It does not run the AI and should not retain large JSON trees or duplicate artifact buffers. Long loops must service watchdog requirements, SD writes must remain transactional, and the display path must use the real 528×792 geometry.

The schedule stores the user's explicit auto-sync request separately from effective readiness. A missing credential, unsynchronized clock or invalid schedule prevents network/timer activation while preserving a useful diagnostic.

## Feedback loop

Feedback is intentionally small: the X3 records like/dislike plus content identity, queues it locally and retries delivery. A producer may use that history to avoid disliked genres or formats. The relay and producer decide how feedback influences generation; the X3 does not infer preferences itself.

## Trust and redirect policy

The first public firmware accepts only canonical `workers.dev` deployment origins covered by its narrow trust bundle. The origin and token occupy one versioned NVS record. SD configuration cannot supply either effective field, phone setup rejects them, and authenticated clients set redirect hops to zero.

Custom domains require a later design that accounts for certificate-chain and trust-store cost within the X3 flash/heap budget.

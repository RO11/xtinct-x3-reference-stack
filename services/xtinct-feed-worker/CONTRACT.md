# Firmware contract map

This reference was derived only from the sanitized public firmware tree beside it. The authoritative client checks remain in firmware source; this file records where each server behavior comes from so future changes can be reviewed for drift.

| Worker behavior | Public firmware authority |
|---|---|
| V1 task allowlist and 32-hex report naming | `firmware/crosspoint-source/src/util/XtinctReportCacheNaming.h` |
| V1 manifest, card fields, lengths, report path and 8/16/24 KiB limits | `firmware/crosspoint-source/src/network/XtinctFeedClient.cpp` and `.h` |
| V2 kinds, MIME pairs, ID/digest rules, action receipt types and artifact limits | `firmware/crosspoint-source/src/util/XtinctSyncContract.h` |
| Eight-change page and 28 KiB response | `firmware/crosspoint-source/src/util/InboxSyncPagingPolicy.h` |
| Digest summary and point bounds | `firmware/crosspoint-source/src/util/InboxDigestContract.h` |
| `/v2/sync`, `/v2/artifacts/<sha256>`, exact response headers and `/v2/acks` | `firmware/crosspoint-source/src/network/XtinctSyncClient.cpp` |
| Worker-origin and 32-256 character read-token policy | `firmware/crosspoint-source/src/util/XtinctFeedCredentialPolicy.h` |
| Full sleep-screen perceptual gate | repository-root `scripts/check_x3_sleep_screen.py` |

## Daily Cards V1 envelope

The manifest body is:

```json
{
  "schema": 1,
  "etag": "\"v1-<server-derived-sha256>\"",
  "cards": [
    {
      "id": "market-briefing",
      "revision": "<32-lowercase-hex>",
      "url": "/v1/cards/market-briefing.json"
    }
  ]
}
```

The `ETag` HTTP header must equal the `etag` body string byte-for-byte. A revision-pinned card request uses the manifest URL plus `?revision=<revision>`.

A card has schema, task identity, revision, generation time, title, summary, priority, state, at most four metrics and at most three sections of four lines. Its optional report descriptor has exactly `url`, `bytes` and `sha256`, and its URL is `/v1/reports/<task>/<revision>.txt`.

## Inbox V2 page

```json
{
  "schema": 2,
  "device_id": "x3-reference",
  "cursor": "42",
  "has_more": false,
  "deliveries": [],
  "tombstones": []
}
```

Each page contains at most eight total changes. Cursor numbers are decimal, monotonic D1 row IDs; gaps are valid. The reference compacts an older pending change when the same `item_id` is republished, preventing duplicate item IDs in a page.

A delivery contains `delivery_id`, `item_id`, `module_id`, `kind`, `title`, 64-hex `revision`, artifact `sha256`, `bytes`, exact `mime`, `created_at`, nullable `expires_at`, up to five unique actions and a bounded metadata object. A tombstone contains delivery and item IDs, the withdrawn revision and `deleted_at`.

Artifact responses are successful only when the R2 object's size still matches D1 metadata. They include exact `Content-Type`, exact `Content-Length`, `ETag: "<sha256>"` and `X-Content-Type-Options: nosniff`.

## Acknowledgement batch

The X3 sends:

```json
{
  "schema": 2,
  "events": [
    {
      "event_id": "x3-reference-1760000000-1",
      "item_id": "reference-article-001",
      "revision": "<64-lowercase-hex>",
      "type": "like",
      "occurred_at": "2026-01-15T00:00:00Z",
      "data": {}
    }
  ]
}
```

The response's `accepted + duplicates + rejected` must equal the number of submitted events. D1's `event_id` primary key makes an ambiguous retry idempotent.

## Drift rule

If any listed firmware file changes, re-audit this service and rerun both the firmware HTTP contract suite and this folder's tests. Passing these Node tests alone does not prove the ESP32-C3 client, QEMU image, network deployment or physical X3.


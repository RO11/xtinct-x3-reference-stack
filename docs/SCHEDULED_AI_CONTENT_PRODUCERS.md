# Scheduled AI content producers

This is the public, account-neutral version of the XTINCT producer setup. The
important point is easy to miss: **these are recurring scheduled tasks**. The
X3 does not run an AI model. ChatGPT/Codex, Gemini Spark, or Grok creates a
bounded item on a schedule; a private relay validates it; the X3 later fetches
the accepted Cards V1 or Inbox V2 revision.

The content instructions below are faithful, sanitized versions of the real
scheduled-task prompts. Mailbox addresses, private endpoints, credentials,
personal project names, exact account configuration, and private source
context are replaced with placeholders. The operator's private Grok content
prompt is deliberately **not** included. No adult or sensitive example content
is bundled here.

## What is scheduled

A typical deployment creates these recurring jobs before the reader's normal
morning wake. Choose times in `<LOCAL_TIMEZONE>` that leave enough time for
research, validation, relay polling, and a retry-free failure report.

| Scheduled task | Cadence | Device lane | Output |
| --- | --- | --- | --- |
| Daily Originals | Daily | Inbox V2 | One E-Ink Serial and one Daily Puzzle |
| Reader Genome | Daily | Inbox V2 | Exactly three independent articles |
| Project Watchlist | Daily | Inbox V2 | One verified project-status brief |
| Business Opportunities | Weekdays | Inbox V2 | One current opportunity brief |
| Hardware Research | Weekly | Inbox V2 | One compatibility-aware research brief |
| Local Weekend | Weekly | Inbox V2 | One source-checked local guide |
| Market Briefing | Recurring market days | Cards V1 | One replace-in-place market card |
| Opportunity Scan | Weekdays | Cards V1 | One replace-in-place opportunity card |
| 3D Job Search | Weekly | Cards V1 | One card whose title and cadence say WEEKLY |
| Attention Watch | Weekdays | Cards V1 | One replace-in-place attention card |

Daily Originals may be one composite scheduled task that prepares and validates
both payloads before sending either. Weekly Research may likewise be one
scheduled task with mutually exclusive weekday branches. This reduces active
task count without allowing two jobs to share a payload.

## The non-negotiable ownership rule

For one logical job and one local date, enable exactly one producer. Do not run
ChatGPT, Spark, and Grok for the same job/date. When changing providers:

1. create the replacement disabled;
2. validate one complete test result without overlapping the old owner;
3. disable and verify the old recurring task;
4. enable the replacement;
5. wait for a real future scheduled run before calling it unattended-proven.

A manual run proves only that manual run. A scheduler success badge proves only
that the scheduler finished. Neither proves that the relay accepted the item or
that a physical X3 downloaded and opened it.

## How each AI produces the same contract

The content prompt is mostly model-neutral. The delivery adapter is not.

### ChatGPT or local Codex automation

Create a recurring scheduled task in the operator's timezone. Paste the common
fence, one selected content prompt, and the ChatGPT delivery adapter below. A
connected mail action may send one exact-subject message whose entire
`text/plain` body is the JSON object. A local Codex automation can use the same
contract when it has the required source access.

```text
CHATGPT DELIVERY ADAPTER

After the complete payload has passed every content and JSON check, use the
connected mail send action exactly once. Send to <INGEST_ADDRESS> with the
selected job's exact XTINCT AUTOMATION subject. The entire text/plain body is
the one JSON object. Add no greeting, signature, Markdown fence, HTML-only
body, attachment, excerpt, or wrapper text. Never retry an ambiguous or failed
send. A send notification is not relay-acceptance proof.
```

For the Market Briefing, ChatGPT can optionally use the official Interactive
Brokers app as a read-only evidence source. The task must remove account IDs,
order IDs, raw connector output, and unsupported quote claims; it must state
`No trades placed or modified`. The producer publishes only its owned V1 card
handoff and never places or changes an order.

### Gemini Spark

Create the same recurring task with the same content prompt and envelope.
Spark should not receive a general Worker administration credential. Where
direct sending is unavailable, use a constrained relay or one self-addressed
draft that a read-only bridge can validate and relay.

```text
SPARK DRAFT ADAPTER

After the complete payload has passed every content and JSON check, create
exactly one new self-addressed mail draft. Do not send it. Use the selected
job's exact XTINCT AUTOMATION subject and put the one complete JSON object in
the text/plain body. Add no greeting, signature, Markdown fence, attachment,
excerpt, or wrapper text. Never create a second draft for an ambiguous result.
```

Treat Spark as an alternative owner, not a mirror. Keep the ChatGPT owner
disabled for every date Spark can emit. A draft appearing in mail proves
transport only; relay acceptance and device sync remain separate checks.

### Grok

The operator's private Grok content prompt is intentionally omitted. To
reproduce the safe transport pattern, use one isolated, write-only MCP tool
that accepts only an allowlisted `job` and its matching `payload`. It must not
read mail, files, inbox items, devices, credentials, or prior content, and it
must not expose general Worker administration.

```text
GROK WRITE-ONLY DELIVERY ADAPTER

Generate and validate the complete payload in memory. Do not email it. Call
the isolated publish_xtinct_automation_content tool exactly once with the
allowlisted job and matching payload. Treat only a successful tool response as
transport. Never retry an ambiguous or failed call, and never fall back to a
truncated notification email.
```

The current reference pattern permits the research/brief jobs through this
adapter. E-Ink Serial and Daily Puzzle are deliberately excluded from the Grok
route. Do not add a private or sensitive Grok prompt to a public repository.

## Common scheduled-task fence

Prepend this to each selected content prompt.

```text
You are the sole scheduled XTINCT producer for <JOB_NAME>. This recurring task
runs <CADENCE> in <LOCAL_TIMEZONE>. At the start of each scheduled run,
determine the current date in that timezone. Use that date in the run_id. Never
run a catch-up or backfill for a missed date.

Before any external write, generate the complete result in memory and validate
its JSON shape, job ID, run date, UTF-8 limits, required headings, word count,
source rules, and renderer safety. If research, generation, validation, or
delivery cannot complete, publish nothing partial and leave the previous good
item in place. Make no second write after an ambiguous result.

The X3 is a narrow renderer, not an AI client. Use plain text inside body. Do
not include HTML, Markdown tables, code fences, device IDs, actions, hashes,
revisions, publication keys, credentials, hidden reasoning, or raw connector
payloads. The relay supplies device-facing identity, digest, byte count,
revision, and allowlisted actions.
```

## Common single-item envelope

E-Ink Serial, Daily Puzzle, Project Watchlist, Business Opportunities,
Hardware Research, and Local Weekend use this shape. Replace every placeholder
and serialize real JSON; do not paste comments into the payload.

```json
{
  "schema": "xtinct.automation-content-email/v1",
  "job": "<JOB_ID>",
  "run_id": "<JOB_ID>/YYYY-MM-DD",
  "content": {
    "title": "Exact first visible line of body",
    "summary": "One short line",
    "points": ["One useful signal", "One useful next check"],
    "body": "complete renderer-safe plain text",
    "sources": [
      { "name": "Public source name", "url": "https://example.com/source" }
    ]
  }
}
```

Common limits:

- no extra keys;
- title at most 120 UTF-8 bytes;
- summary is one trimmed line at most 144 UTF-8 bytes;
- one or two distinct points, each one line and at most 64 UTF-8 bytes;
- body below 64 KiB, with no line over 1,000 UTF-8 bytes;
- the first visible body line is exactly the title;
- required uppercase headings appear exactly once, in the documented order,
  separated by blank lines;
- original fiction and puzzles use `sources: []` exactly;
- research jobs use unique public HTTPS sources and repeat every source name
  and exact URL under the final `SOURCE NOTES` heading.

## Copy-ready scheduled content prompts

Combine the common fence, exactly one block below, and exactly one provider
adapter. The subjects and job IDs are part of the contract.

### E-Ink Serial

- Subject: `XTINCT AUTOMATION — E-INK SERIAL`
- Job: `eink-serial-daily`
- Cadence: daily, through the Daily Originals scheduled task

```text
Write one complete installment of an original serialized fiction work intended
for a calm once-daily reading session on a small e-ink device. Continue only
story facts established in this scheduled task's own prior installments when
they are available. If no prior installment is available, begin a new original
serial and say in RECAP that this is the opening installment. Keep character
names, setting, conflict, and continuity internally consistent. Do not continue
a copyrighted fictional universe, imitate a living author's distinctive style,
quote another work, browse for source material, or claim factual research. End
at a satisfying but forward-looking stopping point rather than cutting off
mid-sentence.

Use the common single-item envelope with job eink-serial-daily and sources: [].
Write 800-1,200 words. The body begins with the exact title, then uses RECAP,
EPISODE, and STOPPING POINT exactly once and in that order. Do not include
SOURCE NOTES, citations, external URLs, or fabricated provenance. The relay,
not the producer, assigns Like and Dislike actions.
```

### Daily Puzzle

- Subject: `XTINCT AUTOMATION — DAILY PUZZLE`
- Job: `daily-puzzle-page`
- Cadence: daily, through the Daily Originals scheduled task

```text
Create one original, self-contained puzzle page for a once-daily e-ink session.
Include a varied set of three to five solvable challenges such as logic,
wordplay, pattern, or lateral-reasoning puzzles. Construct and verify every
answer yourself. Do not reproduce a published puzzle, current-facts trivia,
copyrighted text, or a puzzle attributed to another creator. Make each problem
unambiguous, put useful but non-spoiling hints after all puzzles, and put
complete answers after all hints.

Use the common single-item envelope with job daily-puzzle-page and sources: [].
Write 300-900 words. The body begins with the exact title, then uses PUZZLES,
HINTS, and ANSWERS exactly once and in that order. Use plain labels such as
PUZZLE ONE, HINT ONE, and ANSWER ONE rather than Markdown lists. The relay, not
the producer, assigns Like and Dislike actions.
```

### Reader Genome

- Subject: `XTINCT AUTOMATION — READER GENOME`
- Job: `reader-genome-daily`
- Cadence: daily

```text
Research and write exactly three complete, useful, source-backed articles
tailored to <YOUR_PUBLIC_SAFE_INTEREST_PROFILE>. Select three genuinely
different topics and three distinct domain values from <ALLOWED_DOMAINS>. Do
not repeat a recent topic when trusted recent-topic context is available.
Prefer primary or official sources and current information; use one independent
corroborating source for each article. Never invent a source or URL.

Return one xtinct.reader-genome-email/v1 JSON object with run_id
reader-genome/YYYY-MM-DD and exactly three articles. Each article contains a
metadata object and one complete artifact string. Article indices are 1, 2,
and 3 in array order, domains are distinct, and every article shares one
generated_at timestamp with the local UTC offset.

Each article is 700-1,200 words. Its first visible line exactly matches its
metadata title. Use at least four short uppercase headings and eight prose
paragraphs. The first heading is WHY THIS FITS; the last prose heading is
TAKEAWAY; the artifact ends with PRIMARY SOURCES and every exact source name
and URL. Require 2-6 unique public HTTPS sources per article, including one
primary or official source and one independent corroborating source. If any
one article fails, deliver none of the three.
```

The Reader Genome envelope is intentionally different from the common
single-item shape:

```json
{
  "schema": "xtinct.reader-genome-email/v1",
  "run_id": "reader-genome/YYYY-MM-DD",
  "articles": [
    {
      "metadata": {
        "schema": "xtinct.reader-genome/v1",
        "title": "Exact article title",
        "module_id": "google-spark-genome",
        "mime": "text/plain; charset=utf-8",
        "article_index": 1,
        "domain": "one allowed domain",
        "generated_at": "YYYY-MM-DDTHH:mm:ss+LOCAL_OFFSET",
        "profile_mode": "inline-static",
        "primary_sources": [
          { "name": "Public source", "url": "https://example.com/source" }
        ]
      },
      "artifact": "complete renderer-safe article"
    }
  ]
}
```

The shortened array shows field placement only. Supply exactly three complete
articles. ChatGPT email and Spark draft producers include the exact `module_id`
and `mime` fields above. The Grok write-only adapter uses its separately
allowlisted wrapper and omits those two fields so the relay can insert them.
The relay always adds item, revision, digest, and action data.

### Project Watchlist

- Subject: `XTINCT AUTOMATION — PROJECT WATCHLIST`
- Job: `project-watchlist-daily`
- Cadence: daily

```text
Produce one compact but substantive status brief covering
<YOUR_PUBLIC_SAFE_PROJECT_SET>. Use only changes you can verify from sources
available to this scheduled task. Never infer a local build, device state,
deployment, deadline, or completion from silence. When no verified change
exists, say that plainly and give the most useful next check. Do not modify a
repository, send a message, apply for anything, trade, purchase, or trigger
another service.

Use the common single-item envelope with job project-watchlist-daily, 1-8
unique public HTTPS sources, and 350-1,200 words. The body begins with the exact
title and uses PROJECT STATUS, CHANGES, RISKS, NEXT ACTIONS, and SOURCE NOTES in
that order. If trustworthy evidence is unavailable, state the limitation
instead of fabricating progress.
```

### Business Opportunities

- Subject: `XTINCT AUTOMATION — BUSINESS OPPORTUNITIES`
- Job: `business-opportunities-daily`
- Cadence: weekdays

```text
Find concrete, current, lawful opportunities relevant to
<YOUR_PUBLIC_SAFE_SKILLS_AND_REGION>. Prefer opportunities that can be evaluated
or started cheaply. Distinguish a verified opportunity from a speculative idea,
include eligibility or geographic limits, and give a bounded next action. Do
not apply, register, purchase, contact anyone, disclose personal data, or make a
financial commitment.

Use the common single-item envelope with job business-opportunities-daily, 2-8
unique public HTTPS sources, and 500-1,400 words. The body begins with the exact
title and uses OPPORTUNITIES, WHY THEY FIT, COST AND EFFORT, NEXT ACTIONS, and
SOURCE NOTES in that order. Include dates, costs, and eligibility only when
supported and label uncertainty.
```

### Hardware Research

- Subject: `XTINCT AUTOMATION — HARDWARE RESEARCH`
- Job: `hardware-research-weekly`
- Cadence: weekly

```text
Research useful current firmware forks, additions, libraries, tools, and
feature ideas for this class of small ESP32-C3 e-ink reader. Prefer official
repositories, release notes, datasheets, and upstream documentation. Explain
what is actually downloadable and what requires original engineering. Never
claim compatibility merely because a project targets ESP32 or e-ink.

For every recommendation consider final OTA image size, linked DRAM, task
stack, peak free heap and largest block, network/JSON/file buffers, SD
transaction space, watchdog servicing, 528 x 792 four-gray output, and physical
radio/button/SD/e-ink testing. Label anything not verified against the current
resource contract and exact firmware SHA as UNVERIFIED. Do not download,
install, flash, publish, or change a repository from this scheduled task.

Use the common single-item envelope with job hardware-research-weekly, 3-8
unique public HTTPS sources, and 700-1,600 words. The body begins with the exact
title and uses WHAT CHANGED, WHY IT MATTERS, COMPATIBILITY, RISKS AND LIMITS,
RECOMMENDATION, and SOURCE NOTES in that order.
```

### Local Weekend

- Subject: `XTINCT AUTOMATION — BRISBANE WEEKEND`
- Reference job: `brisbane-weekend-weekly`
- Cadence: weekly before the weekend

```text
Create a general, practical guide to what to do in <YOUR_CITY_OR_REGION> during
the coming weekend. Cover a useful mix such as free events, exhibitions, live
performance, markets, food, outdoors, and unusual one-off activities across the
city and reachable nearby areas. Verify dates, session times, venue, price,
booking status, accessibility or transport caveats, and weather sensitivity
from current primary event or venue pages. Prefer events still bookable or
genuinely open. Never invent availability, pricing, or an event.

Use the common single-item envelope with the reference job ID, 3-8 unique
public HTTPS sources, and 500-1,400 words. The body begins with the exact title
and uses THIS WEEKEND, TOP PICKS, PLAN YOUR DAY, PRACTICAL DETAILS, and SOURCE
NOTES in that order. A fork that renames the legacy location-specific job ID
must update and retest the relay allowlist rather than changing only the prompt.
```

## Scheduled Cards V1 blueprints

Cards V1 is a separate scheduled-task lane. Its four slots replace their own
current card; they do not append Inbox items and must never be mirrored into
Inbox V2. These are public-safe blueprints rather than copies of private source
or account instructions.

Every V1 scheduled task must produce one schema-valid card with its exact owned
task ID, unique run ID, explicit-offset timestamps, deliberate expiry, visible
cadence in the summary/first metric/report, up to four metrics, up to three
sections, no actions, and a complete plain-text report within the current
contract. Commit `[run_id, minified_payload_json, identical_run_id]` atomically
to that task's reserved handoff. On any source, validation, or write failure,
leave the previous complete card unchanged.

- **Market Briefing:** read-only market and optional portfolio evidence;
  reconcile quote freshness; exclude account/order identifiers and raw source
  output; state `No trades placed or modified`.
- **Opportunity Scan:** current, lawful, region-eligible opportunities; separate
  verified openings from search limitations; never apply or contact anyone.
- **3D Job Search:** a weekly scan whose title and visible cadence both say
  `WEEKLY`; do not make an old weekly result look daily.
- **Attention Watch:** bounded same-day signals only; exclude full private
  messages and sensitive raw connector material.

## Set up and verify a scheduled task

1. Choose one job and one provider.
2. Create the recurrence in `<LOCAL_TIMEZONE>` and keep its first run in the
   future. Name it clearly as an XTINCT scheduled task.
3. Paste the common fence, the selected job prompt, and one delivery adapter.
4. Replace only the public placeholders. Keep addresses, tokens, source account
   configuration, and relay URLs in private task configuration.
5. Start the new owner disabled. Validate a complete synthetic payload locally.
6. Prove transport once in a bounded maintenance window without overlapping an
   existing owner.
7. Verify relay acceptance separately from transport.
8. Enable the recurring owner only after the previous owner is disabled and
   verified unable to emit the same job/date.
9. Observe a future scheduled run before claiming unattended operation.
10. Verify feed visibility, physical X3 sync, and opening as separate stages.

Use precise evidence labels: `configured`, `producer-completed`,
`transport-observed`, `worker-accepted`, `feed-visible`, `device-synced`,
`device-opened`, and `unattended-proven`. A fixture, manual run, emulator pass,
or successful deployment is not physical-device proof.

## What this repository does not do

- It does not create provider accounts or scheduled tasks automatically.
- It contains no live mailbox, Worker origin, token, Sheet, device identity, or
  private content.
- It does not include the operator's private Grok content prompt.
- It does not enable adult or sensitive content.
- It does not prove that any public example ran unattended or appeared on a
  physical X3.

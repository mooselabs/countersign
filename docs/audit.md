# countersign audit log

`cnd` keeps an append-only, hash-chained log of everything that touches a
secret: requests, approvals, uses, reveals, hides and store changes. The log is
owned by the `countersign` user. The agent, running as the developer's uid, can
read it through `cnd` and can never modify it. This document specifies the
record format, the chain, checkpoints, rotation, and what tamper-evidence does
and does not give you. Process and key layout are in [design.md](design.md).

## Location and access

```text
/var/lib/countersign/audit/            countersign 0700
  000001.jsonl                         closed segment
  000002.jsonl                         current segment, 0600, O_APPEND
  checkpoint.pub                       Ed25519 public key, "ed25519:<base64>"
```

`[audit] dir` moves the directory. Clients read the log only through `cnd`
(`audit_query`, `audit_segments`). Root, or the `countersign` user, can read
the files directly and verify them offline with
`sudo /usr/bin/cn audit verify --dir /var/lib/countersign/audit`.

## Record schema

One JSON object per line (JSONL). Common fields on every record:

| Field | Type | Notes |
| --- | --- | --- |
| `v` | int | Schema version, `1`. |
| `seq` | int | Monotonic from 1 across all segments. Never reused. |
| `ts` | string | RFC 3339 UTC with microseconds. |
| `boot` | string | First 8 hex characters of the boot id. |
| `event` | string | Event type, below. |
| `session` | object or null | `{id, anchor_pid, anchor_comm, registered, labels}`; labels are untrusted and stored as reported (at most 8, each at most 128 bytes of printable ASCII). |
| `prev` | string | Hex SHA-256 of the previous record (`hash`), or 64 zeros for `seq` 1. |
| `hash` | string | Hex SHA-256 of this record, defined below. |

Event-specific fields:

| Event | Fields |
| --- | --- |
| `daemon.start` | `version`, `pid`, `unseal` (`systemd-creds`) |
| `daemon.stop` | `reason` |
| `config.load` | `path`, `sha256` of the config file, `approvers` (each instance with its `adapter` and `trusted_display`). Written at start and on each reload. |
| `store.init` | `slots`. The first record of a new log, written by `cnd init`. |
| `store.unseal` | `slot` |
| `session.start` / `session.end` | `chain` (`[{pid, comm}]` from the caller to the anchor at discovery) / `grants_expired` |
| `list` | `count`, `window_start`, `window_end` (coalesced, see below) |
| `request.create` | `request_id`, `code`, `secrets`, `mode` (`use`, `reveal`, `mutate`), `operation` (store changes only: `add NAME`, `rm a b`, ...), `ttl_seconds` (0 for store changes), `reason`, `cwd` (or null), `digest`, `canonical` (base64 of the JCS bytes the digest covers) |
| `request.approve` / `request.deny` | `request_id`, `digest`, `approver`, `credential_id` (Phase 2; null), `grant_ids` (on the last approval), `evidence` |
| `request.approve_fail` | `request_id`, `approver`, `credential_id`, `error`. No Phase 1 approver writes it. |
| `request.expire` | `request_id` |
| `grant.revoke` | `grant_id`, `secrets`, `by` (`client`, `store_change`, `restart`) |
| `grant.expire` | `grant_id`, `secrets`, `by` (`ttl`, `anchor_exit`, `uses`) |
| `use.start` | `run_id`, `secrets`, `env`, `argv0`, `argc`, `cwd`, `pid` |
| `use.end` | `run_id`, `status` (`exited`/`signaled`/`client_lost`), `exit`, `signal`, `duration_ms`, `hits` |
| `reveal` | `secret`, `grant_id`, `uses_left` |
| `hide` | `bytes_in`, `hits` (name → count), `patterns` (the number of patterns: values and their encodings). No `bytes_out`: with `bytes_in` and the hits it would give away the matched values' lengths. |
| `store.add` / `store.set` / `store.edit` / `store.rm` | `secret`, `request_id`, `fields_changed`, `value_changed` (bool), `generation`; `store.add` and `store.edit` also carry `metadata` (the new non-secret metadata) |
| `import` | `request_id`, `count`, after the batch's `store.add` records, in the same write |
| `keyslot.add` | `slot`, `credential_id`, `request_id`. Written by `cnd recover`. |
| `peer.reject` | `uid`, `pid`, `code` |
| `checkpoint` | `upto_seq`, `upto_hash`, `host`, `sig` |
| `segment.open` | `segment`, `prev_segment_last_hash` |

Phase 2 adds `export` (`request_id`, `count`, `recipient`), `unlock` (`slot`,
`result`) and `prune`.

`evidence` is `{adapter, at, detail}`. For polkit, `detail` is `{action_id,
subject, is_authorized, dismissed, duration_ms}`. A `request.deny` with
approver `client` is a `cn deny`, and its evidence is `{reason, peer: {uid,
pid, comm}, from, session}`: who ran it, and whether `from` its request's
own session (`own_session`), another agent session (`other_session`), a
terminal outside any session (`terminal`) or no session (`no_session`). A
`request.deny` with approver `cnd` means no decision was possible (an
unavailable approver, a fault, an approval that could not be recorded), and
its evidence is `{error}`.

`digest` is the request digest (design.md, section 6). It is a hash of request
metadata, never of a value. `reason`, a `cn deny` reason and the session
labels are the client's text after the session's hide set has redacted it
(`[audit] redact_agent_text`). A `cn deny` reason passes through the hide
sets of both the request's session and the denier's, and a `cn session exec`
label through the hide set of the session it was run from, since the text's
author may hold grants there.

### Examples

Lines are shown wrapped here; on disk each is one line.

```json
{"v":1,"seq":1,"ts":"2026-11-08T09:00:01.120044Z","boot":"5e1c9a07","event":"daemon.start","session":null,"version":"0.1.0","pid":812,"unseal":"systemd-creds","prev":"0000…0000","hash":"9b1f…"}
{"v":1,"seq":214,"ts":"2026-11-08T09:20:11.004118Z","boot":"5e1c9a07","event":"request.create","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{"CLAUDE_CODE_SESSION_ID":"9f3c…"}},"request_id":"r_q4m8…","code":"K7M-Q2X","secrets":["clickhouse-prod"],"mode":"use","ttl_seconds":3600,"reason":"run the drift report against prod","cwd":"/home/patrick/projects/x","digest":"6f2a91c0…","canonical":"eyJhbmNo…","prev":"a01c…","hash":"77de…"}
{"v":1,"seq":215,"ts":"2026-11-08T09:20:40.551302Z","boot":"5e1c9a07","event":"request.approve","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"request_id":"r_q4m8…","digest":"6f2a91c0…","approver":"polkit","credential_id":null,"grant_ids":["g_2b7c…"],"evidence":{"adapter":"polkit","at":"2026-11-08T09:20:40Z","detail":{"action_id":"computer.mooselabs.countersign.approve","subject":{"kind":"unix-process","pid":41210,"start-time":8812345,"uid":1000},"is_authorized":true,"dismissed":false,"duration_ms":29411}},"prev":"77de…","hash":"c4a0…"}
{"v":1,"seq":216,"ts":"2026-11-08T09:21:02.118870Z","boot":"5e1c9a07","event":"use.start","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"run_id":"u_8d1e…","secrets":["clickhouse-prod"],"env":["CLICKHOUSE_PROD"],"argv0":"./scripts/drift.py","argc":3,"cwd":"/home/patrick/projects/x","pid":41377,"prev":"c4a0…","hash":"0e93…"}
{"v":1,"seq":217,"ts":"2026-11-08T09:21:47.902551Z","boot":"5e1c9a07","event":"use.end","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"run_id":"u_8d1e…","status":"exited","exit":0,"signal":null,"duration_ms":45784,"hits":{},"prev":"0e93…","hash":"5f21…"}
{"v":1,"seq":220,"ts":"2026-11-08T09:30:12.000417Z","boot":"5e1c9a07","event":"reveal","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"secret":"github-token","grant_id":"g_9a10…","uses_left":0,"prev":"1b3d…","hash":"e8c7…"}
{"v":1,"seq":221,"ts":"2026-11-08T09:31:05.230980Z","boot":"5e1c9a07","event":"hide","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"bytes_in":18234,"hits":{"github-token":2},"patterns":96,"prev":"e8c7…","hash":"44b2…"}
{"v":1,"seq":230,"ts":"2026-11-08T10:02:44.771201Z","boot":"5e1c9a07","event":"store.set","session":{"id":"h_0k4d2m8x1p7q","anchor_pid":40102,"anchor_comm":"bash","registered":false,"labels":{}},"secret":"clickhouse-prod","request_id":"r_z0p1…","fields_changed":["value","rotated"],"value_changed":true,"generation":43,"prev":"9a6f…","hash":"b3e0…"}
{"v":1,"seq":1000,"ts":"2026-11-08T14:00:00.000981Z","boot":"5e1c9a07","event":"checkpoint","session":null,"upto_seq":999,"upto_hash":"d71a…","host":"4f1c2a9e…","sig":"ed25519:Mq3…","prev":"d71a…","hash":"6c08…"}
```

### Coalescing

`list` is frequent and low-value. Per session, the first `list` call opens a
window of `[audit] list_coalesce` (default 10 minutes) and is written at once,
so a session's first look at the store is always timestamped exactly. Later
calls in the window are counted, not written. The count goes into the record
written when the window ends, when the next call after it arrives, when the
session ends, or when `cnd` stops, so no call goes uncounted. `cn show` is a
`list` call. Every other event is written individually.

## Hash chain

```text
hash_n = SHA-256( "countersign/audit/v1\0" || JCS(record_n without the "hash" field) )
record_n.prev = hash_{n-1}
```

- `JCS` is RFC 8785 canonical JSON: keys sorted by UTF-16 code units, no
  whitespace, shortest number form, UTF-8. The line on disk is the JCS form
  with `hash` added, so the verifier can re-derive it byte for byte. Records
  hold no floating-point numbers.
- `prev` is inside the hashed object, so each record commits to the whole
  history before it.
- `seq` must be contiguous. A gap, a repeated `seq`, a `prev` mismatch, a
  `hash` mismatch or a line that is not in JCS form is a verification
  failure.

Writes: `cnd` serializes the record, computes the hash, appends one line with
`write(2)` on an `O_APPEND` descriptor, and `fdatasync`s before replying to the
client. The records of one store change (its `store.*` records, and `import`)
go in one write and one sync: all of them are in the log, or none. A write
that fails part way (a full disk, a file size limit) is cut off again, so a
later record never follows a fragment; if the cut fails, the log refuses
every later write until `cnd` restarts. A checkpoint that fails after its
record was written does not make that record fail; it is retried on the next
append and by the timer. An action whose audit write fails is not performed: a request whose
`request.create` cannot be written is not created; for `run` and `reveal` the
value is not returned; for a store change the store rename happens before the
audit write, so on audit failure `cnd` restores `store.v1.prev` and the
request ends denied by `cnd`. `cnd` refuses to start serving if it cannot
write its start records. At start it cuts an unfinished last line (a crash
during a write) and says so in the journal. Audit is on the critical path by
design; volume is small (hundreds of records a day).

## Checkpoints

A `checkpoint` record is written every 1000 records
(`checkpoint_every_records`), every hour if any record was written since the
last checkpoint (`checkpoint_interval`), before a segment closes, and when
`cnd` stops.

```text
payload = JCS({"domain":"countersign/audit-checkpoint/v1",
               "host":"<machine-id>","upto_seq":999,"upto_hash":"d71a…",
               "ts":"2026-11-08T14:00:00.000981Z"})
sig     = Ed25519(AK, payload)
```

The signing key is derived from the store's data key (`AK = HKDF(DK,
"countersign/v1/audit-sign")`, design.md section 3), so it exists only while
the store is open and is never written to disk in the clear. `cnd recover`
keeps the same key. `cnd init` prints the public key once; it is also in
`audit/checkpoint.pub`, which `cnd` serves to `cn audit verify`. `cnd` refuses
to use an audit directory whose `checkpoint.pub` holds another key.

### Off-box export

Checkpoints are only useful against an attacker who can rewrite the box if a
copy lives somewhere else. Keep the public key `cnd init` printed off the
machine, and copy the checkpoint records out regularly. Each is one small,
self-contained line:

```sh
cn audit --event checkpoint --since 7d --limit 1000 --json >> ~/sync/countersign-checkpoints.jsonl
```

Phase 2 adds `cn audit checkpoints` and `cn audit pubkey` for this, and a
`checkpoint_command` that `cnd` hands each new checkpoint line to.

## Rotation

- A segment closes at 64 MiB or at the first record of a new calendar month,
  whichever comes first. Closing writes a `checkpoint`; the new segment begins
  with `segment.open`, whose `prev` is the last hash of the old segment. The
  chain runs unbroken across segments.
- A crash during rotation is recovered at the next open: a new segment that
  is empty or has a torn `segment.open` is removed, and the next append
  rotates again. A `segment.open` whose write failed is written by the next
  append.
- Phase 1 keeps every segment. `[audit] retention` is parsed and ignored with
  a warning; pruning (with a `prune` record that becomes the verifier's
  starting anchor) is Phase 2.

## Sinks

Phase 1 writes the files only. `[[audit.sink]]` is parsed and ignored with a
warning. Planned:

| Sink | Notes |
| --- | --- |
| journald | One entry per record via the native protocol: `MESSAGE` (short summary), `COUNTERSIGN_EVENT`, `COUNTERSIGN_SEQ`, `COUNTERSIGN_HASH`, `COUNTERSIGN_SESSION`, `COUNTERSIGN_JSON` (full line). Gives a second, root-owned copy; with journald Forward Secure Sealing (`journalctl --setup-keys`) it is independently sealed. |
| Remote | Append-only HTTPS or syslog-over-TLS collector off the box. |

A sink failure will be logged to the daemon log and will not block requests;
the file sink stays authoritative.

## What is never logged

- Secret values, in any form: not raw, not encoded, not truncated.
- Hashes, HMACs or fingerprints of values. A hash of a weak password is a
  guessing oracle for anyone who can read the log, and the agent can.
- Value lengths. `store.set` records only `value_changed: true`; the length
  class the dialog shows is not recorded.
- The child's full argv (only `argv0` and `argc`), its environment, and its
  output. `hide` records byte counts and hit counts, not content.

## Querying: `cn audit`

`cn audit` asks `cnd` with `audit_query` and needs no grant. It is read-only;
there is no command that deletes or edits records.

```sh
cn audit                                  # last 50 records, human table
cn audit --current                        # current session only
cn audit --session s_7k2mq9d4x1ha --since 2h
cn audit --secret clickhouse-prod --event use.start --event reveal --since 30d
cn audit --json | jq 'select(.event=="reveal")'
```

```text
SEQ  TIME      SESSION         EVENT            DETAIL
214  09:20:11  s_7k2mq9d4x1ha  request.create   K7M-Q2X use clickhouse-prod 1h "run the drift report against prod"
215  09:20:40  s_7k2mq9d4x1ha  request.approve  r_q4m8… polkit -> g_2b7c…
216  09:21:02  s_7k2mq9d4x1ha  use.start        u_8d1e… clickhouse-prod argv0=./scripts/drift.py pid=41377
217  09:21:47  s_7k2mq9d4x1ha  use.end          u_8d1e… exited exit=0 signal=null 45784ms hits={}
```

## Verifying: `cn audit verify`

`cn audit verify` fetches the raw segments with `audit_segments` and checks
them in `cn`, not in `cnd`:

1. Recompute every `hash`, check JCS form, `prev` linkage and `seq`
   contiguity. The log must start at `seq` 1, or exactly at `--from SEQ`: a
   log whose first segments were deleted fails, rather than verifying from
   wherever it now starts.
2. Verify every checkpoint signature against the public key given with
   `--pubkey FILE`, or the `checkpoint.pub` that `cnd` serves if none is
   given.
3. With `--checkpoints FILE` (JSON Lines of checkpoint records), check that
   each exported checkpoint's `upto_seq` and `upto_hash` match the chain as it
   is now.

With `--dir DIR` it reads the segment files and `checkpoint.pub` from the
directory instead of asking `cnd` (root, or the `countersign` user).

```text
$ cn audit verify --pubkey ~/sync/countersign.pub --checkpoints ~/sync/countersign-checkpoints.jsonl
chain ok: 48211 records (1..48211), 61 checkpoints (61 signatures verified), head 9c1e4f02a..., last checkpoint 2026-11-08T14:00:00.000981Z, 58 exported checkpoints match
```

On failure it prints the first bad `seq` and the reason (hash, chain,
signature, or mismatch with an exported checkpoint) and exits 13
(`audit_broken`, see [cli.md](cli.md#exit-codes)). A log it cannot fetch fails
with the general exit codes (3 when `cnd` is unreachable). `--approvals`,
which re-verifies FIDO2 approvals, is Phase 2.

## What tamper-evidence guarantees

| Threat | Detected? | How |
| --- | --- | --- |
| Agent (developer uid) edits or deletes records | Prevented | Files are owned by `countersign` in a 0700 directory. |
| Agent forges records | Prevented | Only `cnd` writes; clients have no write message. |
| Disk corruption, partial writes | Detected | Hash or `seq` mismatch. |
| Root edits a record and does not recompute | Detected | Hash mismatch. |
| Root rewrites history and recomputes the chain | **Not detected locally** | Root can read MK, unwrap DK, derive AK, re-sign checkpoints. |
| Root rewrites history before an exported checkpoint | Detected | The exported `upto_hash` no longer matches. |
| Root truncates the tail after the last export | **Not detected** | Nothing off-box covers those records. `cn audit verify` checks the records it is given; it cannot tell that later ones existed. |
| Root deletes the whole log and the public key | Only with off-box copies | The exported public key and checkpoints show a log existed and what its head was. |

The chain gives integrity against everything below root. Against root, it
gives detection only up to the last checkpoint that left the box. Checkpoint
signatures prove a checkpoint came from this store's key, which stops someone
without the key from planting fake checkpoints in the off-box copy; they do
not stop root, who can derive the key. Frequent off-box export is what turns
"root could rewrite this" into "root could rewrite only the last hour".

## Open questions

1. **Audit on the critical path.** Refusing to release a value when the audit
   write fails is the safe default. Is a full disk then a denial of service
   the developer will accept, or should there be a small reserved-space
   mechanism?
2. **Rollback of the mutation on audit failure.** Restoring `store.v1.prev`
   after a successful rename adds a second write path. The alternative is to
   write a `store.*.intent` record before the rename and a completion record
   after; that costs an extra record per mutation but avoids the rollback.
3. **Checkpoint key derived from the store.** Deriving AK from the data key
   keeps key management simple but ties checkpoint signing to unseal. A
   separate key held on the YubiKey would mean root cannot re-sign, but then
   every checkpoint needs the key present. Worth it for an opt-in "strict"
   mode?
4. ~~**Labels in the chain.**~~ Settled: labels are capped at 8 per session,
   each at most 128 bytes of printable ASCII.
5. **`cwd` and `argv0` are agent-controlled.** They are recorded as reported.
   The query output should mark them as such, or they will be read as fact.
6. **`list` coalescing window.** 10 minutes is a guess. If `list` before
   `request` turns out to be a useful signal, record every `list`.

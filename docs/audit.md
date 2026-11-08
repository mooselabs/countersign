# countersign audit log

`cnd` keeps an append-only, hash-chained log of everything that touches a
secret: requests, approvals, uses, reveals, hides and store changes. The log is
owned by the `countersign` user. The agent, running as the developer's uid, can
read it through `cnd` and can never modify it. This document specifies the
record format, the chain, checkpoints, retention, sinks, and what
tamper-evidence does and does not give you. Process and key layout are in
[design.md](design.md).

## Location and access

```text
/var/lib/countersign/audit/            countersign 0700
  000001.jsonl                         closed segment
  000002.jsonl                         current segment, 0600, O_APPEND
  checkpoint.pub                       Ed25519 public key (copy of what init printed)
```

Clients read the log only through `cnd` (`audit_query`, `audit_segments`).
Root can read the files directly and verify them offline with
`sudo cn audit verify --dir /var/lib/countersign/audit`.

## Record schema

One JSON object per line (JSONL). Common fields on every record:

| Field | Type | Notes |
| --- | --- | --- |
| `v` | int | Schema version, `1`. |
| `seq` | int | Monotonic from 1 across all segments. Never reused. |
| `ts` | string | RFC 3339 UTC with microseconds. |
| `boot` | string | First 8 hex characters of the boot id. |
| `event` | string | Event type, below. |
| `session` | object or null | `{id, anchor_pid, anchor_comm, registered, labels}`; labels are untrusted and stored as reported. |
| `prev` | string | Hex SHA-256 of the previous record (`hash`), or 64 zeros for `seq` 1. |
| `hash` | string | Hex SHA-256 of this record, defined below. |

Event-specific fields:

| Event | Fields |
| --- | --- |
| `daemon.start` | `version`, `pid`, `unseal` (`systemd-creds`/`fido2`/`sealed`) |
| `daemon.stop` | `reason` |
| `config.load` | `path`, `sha256` of the config file, `approvers` summary (each approver instance, and each FIDO2 record with its credential id, AAGUID and attestation result, loaded or rejected) |
| `store.unseal` | `slot` |
| `session.start` / `session.end` | `chain` (pid/comm list at discovery) / `grants_expired` |
| `list` | `count`, `window_start`, `window_end` (coalesced, see below) |
| `request.create` | `request_id`, `code`, `secrets`, `mode`, `ttl_seconds`, `reason`, `cwd`, `digest`, `canonical` (base64 of the JCS bytes the digest covers) |
| `request.approve` / `request.deny` | `request_id`, `digest`, `approver`, `credential_id`, `grant_ids`, `evidence` (adapter-specific; for FIDO2: flags, sign count, authenticator data, signature) |
| `request.approve_fail` | `request_id`, `approver`, `credential_id`, `error` |
| `request.expire` | `request_id` |
| `grant.revoke` / `grant.expire` | `grant_id`, `secrets`, `by` (`client`/`ttl`/`anchor_exit`/`store_change`/`restart`) |
| `use.start` | `run_id`, `secrets`, `env`, `argv0`, `argc`, `cwd`, `pid` |
| `use.end` | `run_id`, `status` (`exited`/`signaled`/`client_lost`), `exit`, `signal`, `duration_ms`, `hits` |
| `reveal` | `secret`, `grant_id`, `uses_left` |
| `hide` | `bytes_in`, `bytes_out`, `hits` (name → count), `patterns` (count) |
| `store.add` / `store.set` / `store.edit` / `store.rm` | `secret`, `request_id`, `fields_changed`, `value_changed` (bool), `generation`; `store.add` and `store.edit` also carry `metadata` (the new non-secret metadata) |
| `keyslot.add` | `slot`, `credential_id`, `request_id` |
| `export` / `import` | `request_id`, `count`, `recipient` (export) |
| `unlock` | `slot`, `result` |
| `peer.reject` | `uid`, `pid`, `code` |
| `checkpoint` | `upto_seq`, `upto_hash`, `sig` |
| `segment.open` | `segment`, `prev_segment_last_hash` |
| `prune` | `removed_segments`, `removed_upto_seq`, `removed_upto_hash` |

`digest` is the request digest the approver signed (design.md, section 6). It
is a hash of request metadata, never of a value.

### Examples

Lines are shown wrapped here; on disk each is one line.

```json
{"v":1,"seq":1,"ts":"2026-11-08T09:00:01.120044Z","boot":"5e1c9a07","event":"daemon.start","session":null,"version":"0.1.0","pid":812,"unseal":"systemd-creds","prev":"0000…0000","hash":"9b1f…"}
{"v":1,"seq":214,"ts":"2026-11-08T09:20:11.004118Z","boot":"5e1c9a07","event":"request.create","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{"CLAUDE_CODE_SESSION_ID":"9f3c…"}},"request_id":"r_q4m8…","code":"K7M-Q2X","secrets":["clickhouse-prod"],"mode":"use","ttl_seconds":3600,"reason":"run the drift report against prod","cwd":"/home/patrick/projects/x","digest":"6f2a91c0…","canonical":"eyJhbmNo…","prev":"a01c…","hash":"77de…"}
{"v":1,"seq":215,"ts":"2026-11-08T09:20:40.551302Z","boot":"5e1c9a07","event":"request.approve","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"request_id":"r_q4m8…","digest":"6f2a91c0…","approver":"desk-key","credential_id":"pQx7…","grant_ids":["g_2b7c…"],"evidence":{"flags":"0x01","sign_count":0,"authenticator_data":"SZYN…","signature":"MEUC…"},"prev":"77de…","hash":"c4a0…"}
{"v":1,"seq":216,"ts":"2026-11-08T09:21:02.118870Z","boot":"5e1c9a07","event":"use.start","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"run_id":"u_8d1e…","secrets":["clickhouse-prod"],"env":["CLICKHOUSE_PROD"],"argv0":"./scripts/drift.py","argc":3,"cwd":"/home/patrick/projects/x","pid":41377,"prev":"c4a0…","hash":"0e93…"}
{"v":1,"seq":217,"ts":"2026-11-08T09:21:47.902551Z","boot":"5e1c9a07","event":"use.end","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"run_id":"u_8d1e…","status":"exited","exit":0,"signal":null,"duration_ms":45784,"hits":{},"prev":"0e93…","hash":"5f21…"}
{"v":1,"seq":220,"ts":"2026-11-08T09:30:12.000417Z","boot":"5e1c9a07","event":"reveal","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"secret":"github-token","grant_id":"g_9a10…","uses_left":0,"prev":"1b3d…","hash":"e8c7…"}
{"v":1,"seq":221,"ts":"2026-11-08T09:31:05.230980Z","boot":"5e1c9a07","event":"hide","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"bytes_in":18234,"bytes_out":18190,"hits":{"github-token":2},"patterns":96,"prev":"e8c7…","hash":"44b2…"}
{"v":1,"seq":230,"ts":"2026-11-08T10:02:44.771201Z","boot":"5e1c9a07","event":"store.set","session":{"id":"s_7k2mq9d4x1ha","anchor_pid":41210,"anchor_comm":"claude","registered":true,"labels":{}},"secret":"clickhouse-prod","request_id":"r_z0p1…","fields_changed":["value","rotated"],"value_changed":true,"generation":43,"prev":"9a6f…","hash":"b3e0…"}
{"v":1,"seq":1000,"ts":"2026-11-08T14:00:00.000981Z","boot":"5e1c9a07","event":"checkpoint","session":null,"upto_seq":999,"upto_hash":"d71a…","sig":"ed25519:Mq3…","prev":"d71a…","hash":"6c08…"}
```

### Coalescing

`list` is frequent and low-value. `cnd` writes at most one `list` record per
session per 10-minute window, with a count. Every other event is written
individually. The first `list` in a window is written immediately so a
session's first look at the store is always timestamped exactly.

## Hash chain

```text
hash_n = SHA-256( "countersign/audit/v1\0" || JCS(record_n without the "hash" field) )
record_n.prev = hash_{n-1}
```

- `JCS` is RFC 8785 canonical JSON: keys sorted by UTF-16 code units, no
  whitespace, shortest number form, UTF-8. The line on disk is the JCS form
  with `hash` added, so the verifier can re-derive it byte for byte.
- `prev` is inside the hashed object, so each record commits to the whole
  history before it.
- `seq` must be contiguous. A gap, a repeated `seq`, a `prev` mismatch or a
  `hash` mismatch is a verification failure.

Writes: `cnd` serializes the record, computes the hash, appends one line with
`write(2)` on an `O_APPEND` descriptor, and `fdatasync`s before replying to the
client. An action whose audit write fails is not performed: for `run` and
`reveal` the value is not returned; for mutations the store rename happens
before the audit write, so on audit failure `cnd` restores `store.v1.prev`
and returns `internal`. Audit is on the critical path by design; volume is
small (hundreds of records a day).

## Checkpoints

A `checkpoint` record is written every 1000 records, every hour if any record
was written since the last checkpoint, and at `daemon.stop`.

```text
payload = JCS({"domain":"countersign/audit-checkpoint/v1",
               "host":"<machine-id>","upto_seq":999,"upto_hash":"d71a…",
               "ts":"2026-11-08T14:00:00.000981Z"})
sig     = Ed25519(AK, payload)
```

The signing key is derived from the master key (`AK = HKDF(MK,
"countersign/v1/audit-sign")`, design.md section 3), so it exists only while
the store is unsealed and is never written to disk in the clear. `cnd init`
prints the public key; it is also at `audit/checkpoint.pub` and from
`cn audit pubkey`. A sealed `cnd` (FIDO2-only unlock, not yet unlocked) writes
records but defers checkpoints until unlock.

### Off-box export

Checkpoints are only useful against an attacker who can rewrite the box if a
copy lives somewhere else. Each checkpoint line is small and self-contained:

```sh
cn audit checkpoints --since 7d >> ~/sync/countersign-checkpoints.jsonl
cn audit checkpoints --since 7d | ssh backup 'cat >> countersign/$(hostname).jsonl'
```

A config option `checkpoint_command = ["/usr/local/bin/cn-push-checkpoint"]`
lets `cnd` hand each new checkpoint line to a command on stdin (running as
`countersign`, with the unit's sandbox). Remote push is left to that command
in v1.

## Rotation and retention

- A segment closes at 64 MiB or at the first record of a new calendar month,
  whichever comes first. Closing writes a `checkpoint`; the new segment begins
  with `segment.open`, whose `prev` is the last hash of the old segment. The
  chain runs unbroken across segments.
- Closed segments may be compressed to `.jsonl.zst`; the verifier reads both.
- Retention default: keep everything. `retention = "400d"` deletes whole
  closed segments older than that, and only if a checkpoint covers them. A
  `prune` record names the removed range and its last hash, which becomes the
  verifier's starting anchor. Pruning is itself audited and checkpointed.

## Sinks

| Sink | Status | Notes |
| --- | --- | --- |
| File | v1, always on | The authoritative chain. |
| journald | v1, optional | One entry per record via the native protocol: `MESSAGE` (short summary), `COUNTERSIGN_EVENT`, `COUNTERSIGN_SEQ`, `COUNTERSIGN_HASH`, `COUNTERSIGN_SESSION`, `COUNTERSIGN_JSON` (full line). Gives a second, root-owned copy; with journald Forward Secure Sealing (`journalctl --setup-keys`) it is independently sealed. |
| Remote | later | Append-only HTTPS or syslog-over-TLS collector off the box. Until then, `checkpoint_command`. |

Sink failure other than the file sink is logged to the daemon log and does not
block requests.

## What is never logged

- Secret values, in any form: not raw, not encoded, not truncated.
- Hashes, HMACs or fingerprints of values. A hash of a weak password is a
  guessing oracle for anyone who can read the log, and the agent can.
- Value lengths. `store.set` records only `value_changed: true`.
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
SEQ  TIME      SESSION        EVENT            DETAIL
214  09:20:11  s_7k2mq9d4x1ha request.create   clickhouse-prod use 1h "run the drift report…"
215  09:20:40  s_7k2mq9d4x1ha request.approve  fido2:desk-key
216  09:21:02  s_7k2mq9d4x1ha use.start        clickhouse-prod → ./scripts/drift.py
217  09:21:47  s_7k2mq9d4x1ha use.end          exit 0, 45.8s, 0 hits
```

## Verifying: `cn audit verify`

`cn audit verify` fetches the raw segments with `audit_segments` and checks
them in `cn`, not in `cnd`:

1. Recompute every `hash`, check `prev` linkage and `seq` contiguity from
   `seq` 1 or from the latest `prune` anchor.
2. Verify every checkpoint signature against the public key given with
   `--pubkey`, or `audit/checkpoint.pub` if none is given.
3. With `--checkpoints FILE`, check that each exported checkpoint's
   `upto_seq` and `upto_hash` match the chain as it is now.

```text
$ cn audit verify --pubkey ~/sync/countersign.pub --checkpoints ~/sync/countersign-checkpoints.jsonl
segments   3 (000001..000003), records 1..48211
chain      ok
signatures 61 checkpoints ok
external   58 of 58 exported checkpoints match
result     OK
```

On failure it prints the first bad `seq` and the reason (chain, signature, or
mismatch with an exported checkpoint) and exits 13 (`audit_broken`, see
[cli.md](cli.md#exit-codes)). A log it cannot fetch fails with the general exit
codes (3 when `cnd` is unreachable).

## What tamper-evidence guarantees

| Threat | Detected? | How |
| --- | --- | --- |
| Agent (developer uid) edits or deletes records | Prevented | Files are owned by `countersign` in a 0700 directory. |
| Agent forges records | Prevented | Only `cnd` writes; clients have no write message. |
| Disk corruption, partial writes | Detected | Hash or `seq` mismatch. |
| Root edits a record and does not recompute | Detected | Hash mismatch. |
| Root rewrites history and recomputes the chain | **Not detected locally** | Root can read MK, derive AK, re-sign checkpoints. |
| Root rewrites history before an exported checkpoint | Detected | The exported `upto_hash` no longer matches. |
| Root truncates the tail after the last export | **Not detected** | Nothing off-box covers those records. |
| Root deletes the whole log and the public key | Only with off-box copies | The exported public key and checkpoints show a log existed and what its head was. |

The chain gives integrity against everything below root. Against root, it
gives detection only up to the last checkpoint that left the box. Checkpoint
signatures prove a checkpoint came from this `cnd`'s key, which stops someone
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
3. **Checkpoint key derived from MK.** Deriving AK from MK keeps key
   management simple but ties checkpoint signing to unseal. A separate key
   held on the YubiKey would mean root cannot re-sign, but then every
   checkpoint needs the key present. Worth it for an opt-in "strict" mode?
4. **Labels in the chain.** Untrusted labels (session ids from env vars) are
   hashed into the chain. They are useful for linking to transcripts but let
   the agent put arbitrary strings into the log. Cap their length (proposal:
   128 bytes each, 8 labels) and restrict to printable ASCII?
5. **`cwd` and `argv0` are agent-controlled.** They are recorded as reported.
   The query output should mark them as such, or they will be read as fact.
6. **`list` coalescing window.** 10 minutes is a guess. If `list` before
   `request` turns out to be a useful signal, record every `list`.

# Implementation entrypoint

**The main milestones through RELEASE-1 and M4–M8 are implemented and accepted only for their recorded scopes. Midway1.85 startup and first-screen HTTPS interception are verified on the recorded phone; login remains deferred. See [current target results](../targets/midway-pinning.md), [observed evidence](progress.md) and [future work](../FUTURE-WORK.md).**

The bootstrap, interception and identity tracks, public artifact CLI and measured extensions
are implemented. M2-CT, M2-DEX, DEX-only mode, broader API/ABI cells and deferred options are
not complete. Fixture acceptance alone does not establish another target's compatibility. Current observations
live in progress.md.

## First pass

1. Read [PLAN.md §1, §3, §7 and §8](../../PLAN.md).
2. Read [CONTRACT.md](CONTRACT.md).
3. Read the final target observations and limits in [progress](progress.md). Earlier guides document accepted prerequisites.
4. Read only architecture subsections named by the active task.

| Packet | Open after | Guide |
|---|---|---|
| M0 | Accepted on the configured API30 phone | [M0.md](M0.md) |
| BOOTSTRAP | M0 accepted; T-A01/T-A02 pass | [M1a.md](M1a.md), tasks 1–2 only |
| Interception: M1b-5 | BOOTSTRAP accepted | [routing](M1b.md#m1b-5--routing-and-persistence) |
| M2, then M3 | M1b-5, then M2 accepted | [M2-M3.md](M2-M3.md), current subsection only |
| Remaining M1a identity | BOOTSTRAP; by default after M3 | [M1a.md](M1a.md), tasks 3–6 |
| Identity: M1b-1 through M1b-4 | Full M1a, then the prior identity gate accepted | [M1b.md](M1b.md), current subsection only |
| M2-CT | M2 and available API36 cell; not needed for M3 | [CT extension](M2-M3.md#m2-ct--additional-api36-trust-coverage) |
| M2-DEX | M2; optional, not needed for M3 | [runtime trust experiment](M2-M3.md#m2-dex--optional-runtime-trust-experiment) |
| Legacy metadata subpacket | Recorded API28–34 first/release target and M1a task 3 access probe | [M1b-1](M1b.md#m1b-1--signing-contracts-and-caches), task 3 / T-A16; may run before full M1a if needed |
| RELEASE-1 | Both M3 and M1b-4 accepted | PLAN §5 / CONTRACT |
| M4–M8 | RELEASE-1 and extension prerequisites accepted | [LATER.md](LATER.md) |

After BOOTSTRAP, work interception-first (M1b-5 → M2 → M3), then remaining M1a and the identity track.
The two tracks share existing bootstrap/fixture preflight/report helpers. Neither track requires
acceptance of the other until RELEASE-1. Record the next eligible gate when another is blocked.
Identity inventory/T-A06 open in M1a task 3; they are absent from M0 and bootstrap prerequisites.

[Architecture](../ARCHITECTURE.md) preserves reasoning, not a second task list. PLAN owns shared
policy, this index owns loading order, milestone guides own tasks, CONTRACT owns runner behavior.

## Task convention and handoff

Use the same task template: **Files / Steps / Pass / Fail→ / Interpretation**. Steps are numbered
imperatives and include the command/check; Pass lists observed acceptance fields; Fail→ names
the next action. Keep stop/next gating explicit. Interpretation holds the task's short rationale
or limit rather than creating additional actions. Split a long task into numbered steps rather
than adding several competing default strategies. A repository script mentioned in a command must be implemented by the task introducing
it. Add only handlers needed by the active gate, not a general plugin framework.

Update [progress.md](progress.md) during implementation; its dated inventory is historical, not
proof of current prerequisites. Maintain:

```text
Current gate:
State: use PLAN §7's gate-progress value
Last completed task:
Evidence paths:
Next task:
Blocking prerequisite or failed experiment:
```

DO finish the active task and retain real observations. DON'T add public flags before M1b-3,
start B/native/gadget in M0/M1a, silently widen the first cell, or generate artificial PASS output.
If a guide conflicts with shared policy, resolve the document conflict before dependent code.
Keep private keys/passwords/captured target traffic out of tracked handoff documents.
The internal patch --proxy option opens in M1b-5; its public exposure still waits for M1b-3.

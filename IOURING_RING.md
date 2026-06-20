# seaweedvfs io_uring_cmd channel (design)

The kernel↔daemon channel today is the `/dev/seaweedvfs` char device driven by
blocking `read()` (deliver one request) + `write()` (ingest one reply), matched
by a monotonic `tag`. This document specifies an **optional** `io_uring_cmd`
fast path (ublk-style) that delivers requests and collects replies through an
io_uring ring instead of `read()`/`write()` syscalls — fewer syscalls per op,
many in-flight requests, and the natural substrate for RDMA zero-copy later.

The `read()`/`write()` fops **remain** as a runtime-selectable fallback; the
transport is latched per `open` (see "single transport"). Only one daemon
connects (`-EBUSY` on a second `open`).

> This design was adversarially reviewed against the real Linux **v6.12** source
> (`io_uring/uring_cmd.c`, `io_uring/io_uring.c`, `include/linux/io_uring/cmd.h`,
> `drivers/block/ublk_drv.c`). Claims marked **[verified]** were checked there.
> lockdep (`CONFIG_PROVE_LOCKING`) + `CONFIG_DEBUG_ATOMIC_SLEEP` + KASAN under a
> daemon-kill stress loop is the **pre-merge** gate.

## Why this is safe to bolt on

`swvfs_submit()` / `swvfs_wait()` / `swvfs_make_req()` and the `swvfs_pending` /
`swvfs_inflight` lists are **transport-agnostic**. The ring is a second
*delivery* mechanism that consumes the same `swvfs_pending` list and completes
the same `struct swvfs_request`. The VFS operation code does not change.

A request is delivered to **exactly one** consumer because both the `read()`
path and the ring pop from `swvfs_pending` under `swvfs_lock`. The reply is
matched to its `swvfs_request` by `tag` on `swvfs_inflight` (reused verbatim);
a late reply for a timed-out (already-removed) request gets `-ESRCH`, no UAF —
exactly as `swvfs_dev_write` does today.

## Buffer model (chosen: copy, not mmap)

The daemon allocates one buffer per **slot** (`SWVFS_RING_QD` slots). The buffer
holds the request (in) and later the reply (out). Its userspace address+length
ride in the inline SQE `cmd[]`. The kernel `copy_to_user`s the request into it
and `copy_from_user`s the reply out of it — a near-mechanical lift of the
existing copy logic, reusing `struct swvfs_request` unchanged. (mmap +
`io_uring_cmd_import_fixed` zero-copy is a later option for the 1 MiB READ data
plane only.)

**Daemon buffer contract.** The kernel guarantees only fault-safety, not
anti-corruption. The daemon must fully read a reply *out* of `slot[i].buf`
before submitting `COMMIT_AND_FETCH(i)`, and must treat `slot[i].buf` as
**kernel-owned** from the moment any SQE for slot `i` is submitted until that
SQE's CQE arrives. Slot buffers must have **stable addresses** for the whole run
(own them in a startup-sized table; never grow/move).

## Wire additions (`swvfs_proto.h`)

```c
#define SWVFS_URING_FETCH            1 /* cmd_op: park to receive one request */
#define SWVFS_URING_COMMIT_AND_FETCH 2 /* cmd_op: ingest a reply, then re-park */
#define SWVFS_RING_QD              256  /* slots = max concurrent in-flight upcalls */

/* Inline SQE cmd[] payload (24 B, fits the 80 B SQE128 cmd area). */
struct swvfs_uring_cmd {
    __u64 buf_addr;  /* slot buffer: request written here (FETCH),
                      * reply read from here (COMMIT). */
    __u32 buf_len;   /* must hold max(88+payload, 96+1 MiB) */
    __u32 slot;      /* 0..SWVFS_RING_QD-1, daemon-owned slot index */
    __u32 reply_len; /* COMMIT: total reply bytes in buf_addr (96 + data) */
    __u32 _pad;
};
```

`swvfs_req`(88), `swvfs_reply`(96), `swvfs_dirent`(336), `swvfs_statfs`(48),
`swvfs_attr`(72) stay **byte-identical**.

### CQE result convention (`ret` passed to `io_uring_cmd_done`)

- `ret > 0`  — a request was delivered into `buf_addr`; `ret` = request byte
  count (88 + payload). The daemon dispatches it, writes the reply into the same
  buffer, and submits `COMMIT_AND_FETCH(slot, buf_addr, reply_len)`.
- `ret == -ENODEV` — channel shutting down (cancel / wrong-context abort); exit.
- other `ret < 0` — that fetch failed (`-EMSGSIZE` short buffer, `-EFAULT`);
  the daemon re-submits `FETCH` for the slot.

## Kernel state

```c
struct swvfs_slot {
    struct io_uring_cmd *cmd; /* parked cmd owning this slot, else NULL (claim token) */
    u64 buf_addr;
    u32 buf_len;
    bool scheduled;           /* a task_work cb is queued for this slot's cmd */
};
static struct swvfs_slot swvfs_slots[SWVFS_RING_QD]; /* guarded by swvfs_lock */
static struct task_struct *swvfs_daemon;             /* pinned ring daemon, or NULL */
static enum { SWVFS_TP_NONE, SWVFS_TP_LEGACY, SWVFS_TP_RING } swvfs_transport;

struct swvfs_cmd_pdu { u32 slot; u32 reply_len; u64 buf_addr; u32 buf_len; };
/* via io_uring_cmd_to_pdu(); 20 B ≤ 32; BUILD_BUG_ON enforces it */
```

`struct swvfs_request` gains a **`struct kref refcount`** (init 1 in
`swvfs_make_req`; `swvfs_free_req` becomes `kref_put(&r->refcount, release)`).
The cb takes a transient ref across its no-lock `copy_*_user`, so a concurrent
`swvfs_wait` timeout cannot free `r` mid-copy. (The `read()`/`write()` path is
unchanged — it holds `swvfs_lock` across its copy and never holds `uring_lock`,
so its existing in-lock trick stays safe; only the cbs, which run with
`uring_lock` held, must drop `swvfs_lock` before faulting and thus need the ref.)

## Lifetime invariants [verified v6.12]

- **`pdu` is stable** for the cmd's whole life (the `u8 pdu[32]` is inline in
  `struct io_uring_cmd`, overlaid on the same `io_kiocb` across the task_work
  hop). All per-cmd state (slot/buf_addr/buf_len/reply_len) is copied from
  `io_uring_sqe_cmd(sqe)` into `pdu` during `->uring_cmd` issue.
- **`cmd->sqe` is NULLed by the cancel walk** when `!req_has_async_data(req)`
  (`io_uring_try_cancel_uring_cmd`). Therefore the cbs and the cancel handler
  read **only `pdu`, never `cmd->sqe`/`io_uring_sqe_cmd()`**, and the
  `IO_URING_F_CANCEL` check is strictly first in `->uring_cmd`, before any sqe
  deref.
- **`->uring_cmd` never returns `-EAGAIN`** (io_uring would cache+re-issue) and
  never returns `>= 0`. It returns `-EIOCBQUEUED` to park, or a negative errno
  to complete inline.
- **A parked cmd holds an `fget` ref on `req->file`** (the `/dev/seaweedvfs`
  file), dropped only after the cmd completes (`io_put_file`). The file's
  `.owner = THIS_MODULE` pins the module ⇒ **no `rmmod` window** while any cmd is
  parked, and `swvfs_dev_release` (the final `fput`) provably runs **after**
  `io_ring_exit_work` has driven the cancel walk on every parked cmd.

## Lock ordering [verified v6.12] — `uring_lock` ⊃ `swvfs_lock`

io_uring holds `ctx->uring_lock` across: (a) `->uring_cmd` issue on the normal
path (`io_issue_sqe` runs with `IO_URING_F_NONBLOCK|IO_URING_F_COMPLETE_DEFER`
and `__must_hold(&ctx->uring_lock)`); (b) task_work cbs (`io_handle_tw_list` and
the PF_EXITING fallback `io_fallback_req_func` both `mutex_lock(&ctx->uring_lock)`
across the callback); (c) the cancel walk (`io_uring_try_cancel_uring_cmd`,
`lockdep_assert_held(&ctx->uring_lock)`). **`swvfs_lock` nests strictly inside
`uring_lock` everywhere.** Rules:

- `io_uring_cmd_done` with `IO_URING_F_COMPLETE_DEFER` (what the cbs and cancel
  receive) **requires `uring_lock` held** (`io_req_complete_defer` is
  `__must_hold(&ctx->uring_lock)`). So it MUST be called **synchronously within
  the same cb / cancel invocation** io_uring handed us — never deferred to our
  own kthread/workqueue. It is fine to call it after dropping `swvfs_lock` (we
  still hold `uring_lock`, which is what it needs).
- **Never hold `swvfs_lock` across `io_uring_cmd_done`** (claim the slot, drop
  `swvfs_lock`, then complete) — and **never across `copy_to_user`/
  `copy_from_user`** in a cb: the cb already holds `uring_lock`, so faulting
  under two mutexes risks (a) self-deadlock if `buf_addr` is backed by a file on
  this fs (the fault re-enters `swvfs_submit`→`swvfs_lock`) and (b) stalling the
  whole ring under reclaim. Pop+claim under `swvfs_lock`, `kref_get(r)`, drop the
  lock, copy, re-acquire only to finalize, `kref_put(r)`.
- `mark_cancelable` keys purely off `IO_URING_F_UNLOCKED` (via
  `io_ring_submit_lock`); in the normal issue path `UNLOCKED` is clear, so it is
  a no-op asserting-held. It is **not** a tool for avoiding ordering; place it as
  the last step before `-EIOCBQUEUED`.
- `->uring_cmd` is **reachable with `IO_URING_F_UNLOCKED`** (uring_lock *not*
  held) via the io-wq path (`io_wq_submit_work` passes
  `IO_URING_F_UNLOCKED|IO_URING_F_IOWQ`), reachable if the daemon sets
  `IOSQE_ASYNC` or after apoll abort. Handle it ublk-style: defer the whole body
  to task_work (below).

## Control flow

### `swvfs_dev_uring_cmd(cmd, issue_flags)`

```
1. if (issue_flags & IO_URING_F_CANCEL)            /* FIRST, before any sqe deref */
       return swvfs_uring_cancel(cmd, issue_flags);
2. if (issue_flags & IO_URING_F_UNLOCKED) {        /* io-wq path: re-issue in task ctx */
       io_uring_cmd_complete_in_task(cmd, swvfs_resubmit_cb);
       return -EIOCBQUEUED;
   }
3. parse swvfs_uring_cmd c = *io_uring_sqe_cmd(cmd->sqe);
   pdu = io_uring_cmd_to_pdu(cmd, struct swvfs_cmd_pdu);
   *pdu = { c.slot, c.reply_len, c.buf_addr, c.buf_len };
4. if (c.slot >= SWVFS_RING_QD)        return -EINVAL;   /* inline complete */
   if (c.buf_len < SWVFS_REQ_MINBUF)   return -EINVAL;
5. lock swvfs_lock
       if (swvfs_transport == SWVFS_TP_LEGACY) { unlock; return -EBUSY; }
       swvfs_transport = SWVFS_TP_RING;
       if (!swvfs_connected)             { unlock; return -ENOTCONN; }
       if (!swvfs_daemon) swvfs_daemon = get_task_struct(current);  /* pin */
       s = &swvfs_slots[c.slot];
       if (s->cmd)                       { unlock; return -EEXIST; } /* double-arm */
       s->cmd = cmd; s->buf_addr = c.buf_addr; s->buf_len = c.buf_len;
       /* COMMIT always needs a cb (to ingest); FETCH only if work is waiting */
       commit = (cmd->cmd_op == SWVFS_URING_COMMIT_AND_FETCH);
       kick = commit || !list_empty(&swvfs_pending);
       if (kick) s->scheduled = true;
   io_uring_cmd_mark_cancelable(cmd, issue_flags);   /* LAST; only on the park path */
   unlock
6. if (kick)
       io_uring_cmd_complete_in_task(cmd,
              commit ? swvfs_commit_cb : swvfs_deliver_cb);
7. return -EIOCBQUEUED;
```

`mark_cancelable` is reached **only** after the slot is claimed, so no inline
error return (`-EINVAL`/`-EBUSY`/`-ENOTCONN`/`-EEXIST`) ever leaves a stale
entry on `ctx->cancelable_uring_cmd` (which io_uring would otherwise deref after
freeing the inline-completed req — the most dangerous bug this ordering avoids).
`swvfs_resubmit_cb` re-runs steps 3–7 in task context.

### `swvfs_submit()` wake path → `swvfs_kick()`

After `list_add_tail(&r->list, &swvfs_pending)` and unlocking, in addition to
`wake_up_interruptible(&swvfs_read_wq)` (legacy fallback), call `swvfs_kick()`:

```
swvfs_kick():
    lock swvfs_lock
        find slot s with s->cmd && !s->scheduled   /* a parkable cmd, not already queued */
        if (s && !list_empty(&swvfs_pending)) { s->scheduled = true; cmd = s->cmd; }
    unlock
    if (cmd) io_uring_cmd_complete_in_task(cmd, swvfs_deliver_cb);
```

`scheduled` (set under `swvfs_lock`) guarantees one task_work per parked cmd: a
slot is eligible only when `cmd && !scheduled`, so two concurrent kicks cannot
double-schedule the same cmd.

### `swvfs_deliver_cb(cmd, issue_flags)` — task_work, `uring_lock` held

```
pdu = io_uring_cmd_to_pdu(cmd); s = &swvfs_slots[pdu->slot];
lock swvfs_lock
    if (s->cmd != cmd) { unlock; return; }            /* cancel already claimed it */
    if (current != swvfs_daemon || (current->flags & PF_EXITING)) {  /* fallback kworker */
        s->cmd = NULL; s->scheduled = false;
        unlock; io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags); return;
    }
    if (list_empty(&swvfs_pending)) {                 /* raced empty */
        s->scheduled = false;                         /* stay parked, do NOT complete */
        /* (no re-arm needed: a future swvfs_submit kicks again) */
        unlock; return;
    }
    r = pop pending; move to swvfs_inflight; r->on_inflight = true;
    s->cmd = NULL; s->scheduled = false;              /* claim: this cb completes cmd */
    total = sizeof(r->req) + r->payload_len;
    kref_get(&r->refcount);                           /* pin across no-lock copy */
unlock
if (pdu->buf_len < total) ret = -EMSGSIZE;
else {
    ret = total;
    if (copy_to_user(pdu->buf_addr, &r->req, 88)) ret = -EFAULT;
    else if (r->payload_len &&
             copy_to_user(pdu->buf_addr+88, r->payload, r->payload_len)) ret = -EFAULT;
}
lock swvfs_lock
    if (ret < 0 && r->on_inflight && !r->answered) { /* delivery failed: wake waiter */
        list_del_init(&r->list); r->on_inflight=false;
        r->reply.error=-EIO; r->answered=true; complete(&r->done);
    }
unlock
kref_put(&r->refcount, swvfs_req_release);
io_uring_cmd_done(cmd, ret, 0, issue_flags);
```

On `ret > 0`, `r` stays on inflight awaiting its COMMIT; if none comes,
`swvfs_wait` times out and removes it (a late COMMIT then gets `-ESRCH`).

### `swvfs_commit_cb(cmd, issue_flags)` — task_work, `uring_lock` held

```
pdu = io_uring_cmd_to_pdu(cmd); s = &swvfs_slots[pdu->slot];
/* wrong-context guard FIRST (don't copy_from_user in a fallback kworker) */
if (current != swvfs_daemon || (current->flags & PF_EXITING)) {
    lock; if (s->cmd==cmd){ s->cmd=NULL; s->scheduled=false; } unlock;
    io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags); return;
}
/* (1) ingest the reply: read from pdu->buf_addr, validate, match swvfs_inflight
       by tag, copy dirents/data, complete(&r->done). Structurally the
       swvfs_dev_write body, reading from buf_addr instead of the write() buf,
       BUT following the no-fault-under-two-locks rule (kref_get the matched r,
       drop swvfs_lock for the data copy_from_user, re-lock to finalize).
       Validate reply_len <= buf_len; clamp nentries/datalen via min_t against
       r->max_dirents / r->max_data with per-copy length checks. -ESRCH if no
       inflight tag matches (a late commit for a timed-out request). */
swvfs_ingest_reply(pdu->buf_addr, pdu->reply_len);
/* (2) deliver-next / re-park this same cmd (it owns slot pdu->slot): run the
       swvfs_deliver_cb body. If cancel won the claim between (1) and (2)
       (s->cmd != cmd), do NOT complete — the next request (if any) just waits
       for another parked cmd. The reply was already ingested in (1); if cancel
       won before the cb ran at all, ingest is skipped and the waiter falls back
       to the release -ENOTCONN drain / timeout (NOT "harmless, already done"). */
__swvfs_deliver(cmd, pdu->slot, issue_flags);
```

Buffer reuse is safe: step (1) reads the whole reply out of `buf_addr` before
step (2) makes the slot eligible to receive a request *into* `buf_addr`; a
`swvfs_deliver_cb` writing the next request can only run after (2) re-parks and a
`swvfs_kick` schedules it — strictly after (1).

### `swvfs_uring_cancel(cmd, issue_flags)` — from `->uring_cmd(IO_URING_F_CANCEL)`

io_uring drives this for every still-cancelable cmd when the ring tears down
(daemon close/exit). Read **only `pdu`** (`cmd->sqe` may be NULL here).

```
pdu = io_uring_cmd_to_pdu(cmd); s = &swvfs_slots[pdu->slot];
lock swvfs_lock
    claimed = (s->cmd == cmd);
    if (claimed) { s->cmd = NULL; s->scheduled = false; }
unlock
if (claimed) io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags);
/* else a deliver/commit cb already claimed+completed it — do nothing */
```

### `swvfs_dev_release` (daemon closed the fd) [invariant: runs after all cancels]

A parked cmd pins `req->file` ⇒ this final `fput` runs **after** the cancel walk
completed every parked cmd. So release does **not** complete cmds or clear
`slot->cmd` as a teardown action (the claim-token xchg is the sole province of
deliver/commit/cancel). Release only:

```
lock swvfs_lock
    swvfs_connected = false; swvfs_transport = SWVFS_TP_NONE;
    drain swvfs_pending + swvfs_inflight with reply.error = -ENOTCONN (as today);
    for each slot: WARN_ON_ONCE(s->cmd != NULL);   /* must already be cancelled */
    d = swvfs_daemon; swvfs_daemon = NULL;
unlock
if (d) put_task_struct(d);
```

## Daemon side (`crates/sw-kd`)

- Add `io-uring = "0.7"`. Build `IoUring::<squeue::Entry128, cqueue::Entry>` —
  **SQE128 comes from the entry type, not a setup flag**. Do **not** use
  `setup_single_issuer` / `setup_defer_taskrun` (incompatible with multi-thread
  tokio submitting from worker threads).
- **Single-owner ring-driver task**: one thread owns the ring and does *all*
  `submit()` and *all* CQ drains. Handlers (read-only on `rt.spawn`, mutations on
  a serial consumer) send `(slot, reply_bytes)` back over an mpsc; only the
  ring-driver submits `COMMIT_AND_FETCH`. Drive wakeups via `register_eventfd` +
  tokio `AsyncFd` (no busy loop).
- Submit `opcode::UringCmd80::new(types::Fd(dev_fd), cmd_op)
  .cmd(<[u8;80] little-endian swvfs_uring_cmd>).user_data(slot).build()`. Read
  completions via `cqe.result(): i32` and `cqe.user_data(): u64` (= slot). Never
  set CQE32 (res2 always 0).
- **Serialize mutations + READDIR by `req.tag`, not CQE arrival order** — CQEs
  for QD parked FETCHes complete in task_work order, *not* `swvfs_pending` FIFO
  order. `tag` (assigned under `swvfs_lock` at submit via `atomic64_inc_return`)
  is the true delivery order; the serial consumer feeds the single mutation
  executor in `tag` order. This preserves the single-slot readdir cache and
  per-path `WriteBuf` invariants.
- **Slot buffers** as `Box<[u8]>` in a startup-sized table (`with_capacity(QD)`,
  never grown) owned by the ring-driver for the whole run; pass
  `Box::as_mut_ptr` as `buf_addr`. Drain/await all in-flight (and `-ENODEV`
  cancel) completions before dropping the table on shutdown.
- **No slot starvation**: a slot is owned by its request from FETCH-delivery
  until *that slot's* COMMIT (never re-FETCH a slot before its COMMIT). Over-
  provision `QD` and cap spawned read-only concurrency with a
  `Semaphore(QD - K)` so ≥ K slots stay parked for FETCH and a mutation can
  always be delivered (its VFS caller may hold inode locks).
- `--io-uring` flag (opt-in) selects the ring; default stays `read()`/`write()`
  until proven, then the default flips. `State`, `dispatch`, all `handle_*`, and
  the sw-client backend are unchanged.

## Single transport per open

`swvfs_transport` is latched under `swvfs_lock`: `swvfs_dev_read` sets/requires
`LEGACY` (`-EBUSY` if `RING`), `swvfs_dev_uring_cmd` sets/requires `RING`
(`-EBUSY` if `LEGACY`), reset to `NONE` in release. Memory-safety is already
guaranteed by the single pending/inflight under `swvfs_lock`; the latch is about
the FIFO-ordering assumption for mutations/READDIR.

## Top risks (all mitigations specified above)

1. **Double `io_uring_cmd_done` ⇒ UAF.** Single claim token (`slot->cmd`
   xchg→NULL under `swvfs_lock`) + `scheduled` flag (no double task_work). Every
   completer (deliver, commit-deliver, cancel) re-checks `s->cmd == cmd`. Inline
   errors complete by *returning* the errno (io_uring completes them), and
   `mark_cancelable` is reached only on the park path, so no stale cancelable
   entry on an inline-completed req.
2. **`IO_URING_F_UNLOCKED` issue (io-wq).** Reachable; defer the whole body to
   task_work (`swvfs_resubmit_cb`).
3. **Cancel vs commit-cb race.** Both contend on the claim token; the loser
   skips completion. If cancel wins before the commit cb ingests, the reply is
   *dropped* and the waiter gets `-ENOTCONN` (release drain) or times out — not
   "already done."
4. **Wrong-context cb (fallback kworker, PF_EXITING).** `io_fallback_req_func`
   runs the cb in a system-wq kworker with a borrowed/NULL mm. Guard both cbs
   with `current != swvfs_daemon || PF_EXITING` *before any copy*; abort with
   `-ENODEV`.
5. **Faulting under two mutexes / fs-recursion.** Never hold `swvfs_lock` across
   `copy_*_user` in a cb (it holds `uring_lock` too); `kref`-pin `r`, drop the
   lock, copy, re-lock to finalize.
6. **Untrusted inline cmd / reply_len.** Validate `slot < QD`,
   `buf_len ≥ needed`, `reply_len ≤ buf_len`; clamp `nentries`/`datalen` via
   `min_t` against `r->max_dirents`/`r->max_data` with per-copy checks. Single
   daemon (mode 0600) bounds exposure.
7. **Release vs cancel ordering.** The parked-cmd file-ref serializes them:
   release runs last and must not touch `slot->cmd` (only `WARN_ON_ONCE`).
8. **Daemon buffer contract / starvation / tag-ordering.** See daemon section.

## Pre-merge validation — DONE (KASAN + lockdep, 2026-06-15)

Built a custom `6.12.90-swvfsdbg` kernel with `CONFIG_KASAN=y` +
`CONFIG_PROVE_LOCKING=y` + `CONFIG_DEBUG_ATOMIC_SLEEP=y` (and `CONFIG_RDMA_RXE=m`),
booted swdev into it, rebuilt a KASAN-instrumented `seaweedvfs.ko` against it, and
re-ran the full suite: both transports (`posix_itest` 17/17, write→cold→md5 ×2
clean) **and** the daemon-`SIGKILL`-mid-I/O teardown stress (4 active readers,
exercising the cancel walk). **All `dmesg`-clean** — no KASAN use-after-free, no
lockdep circular-dependency, no atomic-sleep `BUG` on any path, and `rmmod`
unloads clean. So the four bug classes the design review fixed (double-`done`
UAF, `uring_lock`↔`swvfs_lock` inversion, wrong-context kworker copy,
faulting-under-two-locks) are clean under instrumentation.

Still worth doing later for completeness: force the io-wq/`IO_URING_F_UNLOCKED`
path explicitly via `IOSQE_ASYNC`; point a slot `buf_addr` at an mmap of a file
on the seaweedvfs mount to exercise the fault-recursion case directly; and diff
`io_uring/uring_cmd.c` + `io_uring/io_uring.c` of 6.12.90 vs the v6.12 tag
(citations are from v6.12). The normal teardown path already drives the cancel
walk on every daemon stop.

// SPDX-License-Identifier: GPL-2.0
/*
 * seaweedvfs - a Linux kernel filesystem client for SeaweedFS.
 *
 * A registered in-kernel filesystem whose operations are served by a userspace
 * daemon over the /dev/seaweedvfs character device. The kernel owns the VFS
 * (inodes, dentries, page cache) and does zero networking; the daemon does all
 * SeaweedFS I/O. This is the WEKA-style split.
 *
 * Path-based / stateless: every request carries the FS-relative path(s) of its
 * target (reconstructed from dentries via dentry_path_raw), so the daemon keeps
 * no inode map and a daemon restart is transparent. Inode numbers are a stable
 * hash of the path, computed by the daemon and returned in replies. See
 * swvfs_proto.h.
 *
 * Kernel modules link the Linux kernel and are GPL-2.0; the rest of the
 * seaweed-vfs project is Apache-2.0.
 */

#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#if __has_include(<linux/filelock.h>)
#include <linux/filelock.h>	/* split out of fs.h in 6.5; absent on older LTS */
#endif
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>	/* rcu_barrier() before kmem_cache_destroy in exit */
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <linux/overflow.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>

#include "swvfs_proto.h"
#include "compat.h"

#ifdef SWVFS_HAVE_URING
#include <linux/io_uring/cmd.h>
#else
struct io_uring_cmd;	/* fwd-decl only: swvfs_slot keeps a pointer to it */
#endif

/* When set (insmod distributed_locks=1), advisory locks (flock) are routed
 * through the daemon to the filer's lock service so they hold across mounts;
 * otherwise the VFS handles them locally (single-node, the default). */
static bool distributed_locks;
module_param(distributed_locks, bool, 0444);
MODULE_PARM_DESC(distributed_locks,
		 "route advisory locks (flock) through the filer for cross-mount locking");

#define SEAWEEDVFS_VERSION "0.1.4"
#define SEAWEEDVFS_MAGIC 0x53574653 /* "SWFS" */
#define SEAWEEDVFS_ROOT_INO 1
#define SWVFS_TIMEOUT_MS 30000
#define SWVFS_READAHEAD_MAX (1024 * 1024) /* bytes per READ upcall */
#define SWVFS_RA_PAGES (4 * 1024 * 1024 / PAGE_SIZE) /* 4 MiB read-ahead window
						       * = 4 concurrent 1 MiB upcalls */
/* Attr cache validity before a getattr re-fetches from the filer. The daemon's
 * metadata subscription push-invalidates changed inodes in ~ms, so this is only
 * a backstop for the gaps the subscription can't cover (startup, a reconnect
 * window, a dropped invalidation) — hence seconds, not the old sub-second TTL. */
#define SWVFS_ATTR_TTL_MS 30000

/* inode/time/uid helpers come from linux/fs.h; current_fsuid from linux/cred.h. */

/* ------------------------------------------------------------------ */
/* Channel: kernel <-> userspace daemon                               */
/* ------------------------------------------------------------------ */

struct swvfs_request {
	struct list_head list;
	u64 tag;
	struct swvfs_req req; /* header */
	char *payload; /* path1|path2|data sent after the header, or NULL */
	u32 payload_len;
	struct swvfs_reply reply;
	struct swvfs_dirent *dirents; /* READDIR reply batch, or NULL */
	u32 max_dirents;
	void *data; /* READ reply buffer, or NULL */
	u32 max_data;
	bool on_pending;
	bool on_inflight;
	bool answered;
	struct completion done;
	struct kref refcount; /* 1 = caller's ref; a ring cb takes a transient ref
			       * across its lockless copy so a concurrent
			       * swvfs_wait() timeout cannot free r mid-copy. */
};

static DEFINE_MUTEX(swvfs_lock);
static LIST_HEAD(swvfs_pending);  /* awaiting delivery to the daemon */
static LIST_HEAD(swvfs_inflight); /* delivered, awaiting a reply */
static DECLARE_WAIT_QUEUE_HEAD(swvfs_read_wq);
static atomic64_t swvfs_tag = ATOMIC64_INIT(1);
static bool swvfs_connected;

/* Workqueue for asynchronous read-ahead: a window's folios are fetched off the
 * read path so the fetch overlaps the application consuming earlier pages. */
static struct workqueue_struct *swvfs_ra_wq;

/* Optional io_uring_cmd (ublk-style) ring transport — a fast path beside the
 * read()/write() fops; see kernel/IOURING_RING.md. All of it is guarded by
 * swvfs_lock. The transport is latched per open: a daemon uses either the ring
 * or read()/write(), never both (both pop swvfs_pending, so memory-safe either
 * way, but mixing would break the FIFO ordering mutations/READDIR rely on). */
struct swvfs_slot {
	struct io_uring_cmd *cmd; /* parked cmd owning this slot, else NULL (the
				   * single claim token for exactly-once completion) */
	u64 buf_addr;
	u32 buf_len;
	bool scheduled; /* a task_work cb is already queued for this slot's cmd */
};

/* Stashed in io_uring_cmd.pdu[32] during ->uring_cmd; read by the cbs and the
 * cancel handler (which must not touch cmd->sqe — it is NULLed on cancel). */
struct swvfs_cmd_pdu {
	u32 slot;
	u32 reply_len;
	u64 buf_addr;
	u32 buf_len;
};

static struct swvfs_slot swvfs_slots[SWVFS_RING_QD];
static struct task_struct *swvfs_daemon; /* pinned ring-driver task, or NULL */
static enum { SWVFS_TP_NONE, SWVFS_TP_LEGACY, SWVFS_TP_RING } swvfs_transport;
/* Mounted superblocks, so a daemon-pushed invalidation reaches the cached inode
 * in every mount (inode numbers are hash(path), shared across mounts of the same
 * filer; a single global pointer invalidated only the most recent mount).
 * swvfs_sb_sem guards the list: an invalidation holds it for read across the whole
 * ilookup..iput so a sb can't be torn down underneath it (an inode ref does NOT
 * pin the sb — evict_inodes just warns and proceeds); fill_super/kill_sb take it
 * for write. Each sb's link hangs off sb->s_fs_info. */
struct swvfs_mount {
	struct list_head node;
	struct super_block *sb;
};
static LIST_HEAD(swvfs_mounts);
static DECLARE_RWSEM(swvfs_sb_sem);

/* Per-inode state beyond the generic struct inode. cache_gen counts invalidations
 * pushed for this inode; a slow getattr upcall snapshots it before the call and
 * re-checks after, dropping a reply that raced an invalidation instead of
 * re-stamping stale attrs as fresh (see seaweedvfs_getattr). */
struct swvfs_inode {
	struct inode vfs_inode;
	atomic_t cache_gen;
};
static struct kmem_cache *swvfs_inode_cachep;

static inline struct swvfs_inode *SWVFS_I(struct inode *inode)
{
	return container_of(inode, struct swvfs_inode, vfs_inode);
}

static void swvfs_kick(void);

/* Allocate a request for `op` carrying path1 (+ optional path2, data). */
static struct swvfs_request *swvfs_make_req(u32 op, const char *p1, size_t l1,
					    const char *p2, size_t l2,
					    const void *d, size_t dl)
{
	struct swvfs_request *r = kzalloc(sizeof(*r), GFP_KERNEL);

	if (!r)
		return NULL;
	kref_init(&r->refcount);
	r->req.op = op;
	r->req.plen1 = l1;
	r->req.plen2 = l2;
	r->req.dlen = dl;
	r->payload_len = l1 + l2 + dl;
	if (r->payload_len) {
		r->payload = kvmalloc(r->payload_len, GFP_KERNEL);
		if (!r->payload) {
			kfree(r);
			return NULL;
		}
		memcpy(r->payload, p1, l1);
		if (l2)
			memcpy(r->payload + l1, p2, l2);
		if (dl)
			memcpy(r->payload + l1 + l2, d, dl);
	}
	return r;
}

static void swvfs_req_release(struct kref *kref)
{
	struct swvfs_request *r = container_of(kref, struct swvfs_request, refcount);

	kvfree(r->payload);
	kfree(r->dirents);
	kvfree(r->data); /* may be kvmalloc'd (large READ buffers) */
	kfree(r);
}

static void swvfs_free_req(struct swvfs_request *r)
{
	if (r)
		kref_put(&r->refcount, swvfs_req_release);
}

/* Allocate a request whose single path is that of `dentry`. */
static struct swvfs_request *swvfs_req_from_dentry(u32 op, struct dentry *dentry)
{
	char *buf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	struct swvfs_request *r;
	char *p;

	if (!buf)
		return ERR_PTR(-ENOMEM);
	p = dentry_path_raw(dentry, buf, SWVFS_PATH_MAX);
	if (IS_ERR(p)) {
		kfree(buf);
		return ERR_CAST(p);
	}
	r = swvfs_make_req(op, p, strlen(p), NULL, 0, NULL, 0);
	kfree(buf);
	return r ? r : ERR_PTR(-ENOMEM);
}

/* Queue a request for the daemon without blocking. Returns 0, or -ENOTCONN if
 * no daemon is connected. Pairs with swvfs_wait(); several requests can be in
 * flight at once (the daemon, which is concurrent, replies by tag). */
static int swvfs_submit(struct swvfs_request *r)
{
	mutex_lock(&swvfs_lock);
	if (!swvfs_connected) {
		mutex_unlock(&swvfs_lock);
		return -ENOTCONN;
	}
	r->tag = atomic64_inc_return(&swvfs_tag);
	r->req.tag = r->tag;
	r->answered = false;
	init_completion(&r->done);
	list_add_tail(&r->list, &swvfs_pending);
	r->on_pending = true;
	mutex_unlock(&swvfs_lock);

	wake_up_interruptible(&swvfs_read_wq); /* legacy read() transport */
	swvfs_kick(); /* ring transport: hand off to a parked uring_cmd, if any */
	return 0;
}

/* Block for a submitted request's reply. Returns reply.error (<= 0) or a
 * negative errno on timeout/interrupt. */
static int swvfs_wait(struct swvfs_request *r)
{
	long left = wait_for_completion_killable_timeout(
		&r->done, msecs_to_jiffies(SWVFS_TIMEOUT_MS));

	if (left > 0)
		return r->reply.error;

	mutex_lock(&swvfs_lock);
	if (r->answered) {
		mutex_unlock(&swvfs_lock);
		return r->reply.error;
	}
	if (r->on_pending || r->on_inflight)
		list_del_init(&r->list);
	r->on_pending = false;
	r->on_inflight = false;
	r->answered = true;
	mutex_unlock(&swvfs_lock);
	return left == 0 ? -ETIMEDOUT : -EINTR;
}

/* Submit a request and block for the daemon's reply. */
static int swvfs_send(struct swvfs_request *r)
{
	int err = swvfs_submit(r);

	return err ? err : swvfs_wait(r);
}

static ssize_t swvfs_dev_read(struct file *f, char __user *buf, size_t len,
			      loff_t *off)
{
	struct swvfs_request *r;
	size_t total;

	if (len < sizeof(struct swvfs_req))
		return -EINVAL;

	mutex_lock(&swvfs_lock);
	if (swvfs_transport == SWVFS_TP_RING) {
		mutex_unlock(&swvfs_lock);
		return -EBUSY; /* this daemon already chose the io_uring transport */
	}
	swvfs_transport = SWVFS_TP_LEGACY;
	while (list_empty(&swvfs_pending)) {
		mutex_unlock(&swvfs_lock);
		if (wait_event_interruptible(swvfs_read_wq,
					     !list_empty(&swvfs_pending)))
			return -EINTR;
		mutex_lock(&swvfs_lock);
	}
	r = list_first_entry(&swvfs_pending, struct swvfs_request, list);
	list_del_init(&r->list);
	r->on_pending = false;
	list_add_tail(&r->list, &swvfs_inflight);
	r->on_inflight = true;

	/*
	 * Keep swvfs_lock held across copy_to_user. It can sleep (page fault),
	 * and dropping the lock here would let swvfs_send() time out / be
	 * signalled, remove r, and let its caller free r while we still
	 * dereference it -> use-after-free. The mutex is sleepable, so holding
	 * it across the copy is fine; the daemon's read buffer is anonymous
	 * memory, so a fault while holding the lock cannot recurse into us.
	 */
	total = sizeof(r->req) + r->payload_len;
	if (len < total)
		goto efault;
	if (copy_to_user(buf, &r->req, sizeof(r->req)))
		goto efault;
	if (r->payload_len &&
	    copy_to_user(buf + sizeof(r->req), r->payload, r->payload_len))
		goto efault;
	mutex_unlock(&swvfs_lock);
	return total;

efault:
	if (r->on_inflight && !r->answered) {
		list_del_init(&r->list);
		r->on_inflight = false;
		r->reply.error = -EIO;
		r->answered = true;
		complete(&r->done);
	}
	mutex_unlock(&swvfs_lock);
	return -EFAULT;
}

/* Daemon-pushed cache invalidation (a write whose tag is 0, which is never a
 * request tag): the inode named by hdr.attr.ino changed on another client.
 *
 * For a file inode we drop its attr stamp (the next getattr re-fetches) and its
 * page cache. invalidate_inode_pages2_range (not invalidate_mapping_pages) is
 * deliberate: it locks each folio, so it waits out an in-flight read-ahead that
 * is about to install now-stale bytes, and it unmaps mmap'd folios — neither of
 * which invalidate_mapping_pages does, so that path lost races with reads/mmap.
 *
 * cache_gen is bumped first. For a file it makes getattr and in-flight reads
 * re-fetch. For a directory the same counter is its namespace generation: each
 * child dentry records the parent's gen when cached, and d_revalidate re-resolves
 * any child whose snapshot is now stale. The VFS calls d_revalidate on cached
 * dentries — positive AND negative — in the lookup and open paths (lookup_open /
 * lookup_fast), so the generation alone covers remote creates (stale negatives),
 * deletes, and renames, including names a process holds open or is looking up
 * concurrently. We deliberately do NOT shrink_dcache the subtree per event: it is
 * unnecessary given the generation check, and a single change (e.g. at the root)
 * would synchronously evict most of the mount's cache.
 *
 * invalidate_inode_pages2_range then drops the page cache (a no-op for a
 * directory mapping).
 *
 * Every mounted sb is visited (inode numbers are shared across mounts).
 * swvfs_sb_sem is held for read across the whole walk so kill_sb (which takes it
 * for write) can't free a sb while we still reference one of its inodes. */
static void swvfs_invalidate(u64 ino)
{
	struct swvfs_mount *m;

	if (ino == 0)
		return;
	down_read(&swvfs_sb_sem);
	list_for_each_entry(m, &swvfs_mounts, node) {
		struct inode *inode = ilookup(m->sb, ino);

		if (!inode)
			continue;
		atomic_inc(&SWVFS_I(inode)->cache_gen);
		inode->i_private = NULL; /* next getattr re-fetches */
		invalidate_inode_pages2_range(inode->i_mapping, 0, -1);
		iput(inode);
	}
	up_read(&swvfs_sb_sem);
}

/* Invalidate every cached inode in one sb: bump each generation (re-fetching
 * attrs, re-resolving child names, discarding in-flight reads) and drop page
 * caches. Walks sb->s_inodes with the standard pin-the-cursor dance so the list
 * stays valid across the lock drops the per-inode work needs (cf.
 * drop_pagecache_sb). igrab skips inodes already being freed. */
static void swvfs_flush_sb(struct super_block *sb)
{
	struct inode *inode, *toput = NULL;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct inode *pinned = igrab(inode);

		if (!pinned)
			continue; /* being freed; list lock still held, cursor safe */
		spin_unlock(&sb->s_inode_list_lock);
		iput(toput);	/* release the previous iteration's anchor */
		toput = pinned;	/* keep this one pinned to anchor the cursor */
		atomic_inc(&SWVFS_I(pinned)->cache_gen);
		pinned->i_private = NULL;
		invalidate_inode_pages2_range(pinned->i_mapping, 0, -1);
		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput);
}

/* Drop all cached state in every mount. Called when the daemon disconnects: its
 * successor's subscription resumes from "now", so anything that changed during
 * the outage would otherwise be served stale forever. */
static void swvfs_flush_all(void)
{
	struct swvfs_mount *m;

	down_read(&swvfs_sb_sem);
	list_for_each_entry(m, &swvfs_mounts, node)
		swvfs_flush_sb(m->sb);
	up_read(&swvfs_sb_sem);
}

static ssize_t swvfs_dev_write(struct file *f, const char __user *buf,
			       size_t len, loff_t *off)
{
	struct swvfs_reply hdr;
	struct swvfs_request *r = NULL, *it;

	if (len < sizeof(hdr))
		return -EINVAL;
	if (copy_from_user(&hdr, buf, sizeof(hdr)))
		return -EFAULT;

	/* tag 0 is never a request tag (they start at 2): a daemon-pushed cache
	 * invalidation for the inode in hdr.attr.ino, not a reply. */
	if (hdr.tag == 0) {
		swvfs_invalidate(hdr.attr.ino);
		return len;
	}

	mutex_lock(&swvfs_lock);
	list_for_each_entry(it, &swvfs_inflight, list) {
		if (it->tag == hdr.tag) {
			r = it;
			break;
		}
	}
	if (!r) {
		mutex_unlock(&swvfs_lock);
		return -ESRCH;
	}

	r->reply = hdr;
	if (hdr.error == 0 && r->req.op == SWVFS_OP_READDIR && hdr.nentries > 0) {
		u32 n = min_t(u32, hdr.nentries, r->max_dirents);
		size_t need = sizeof(hdr) +
			      (size_t)n * sizeof(struct swvfs_dirent);

		if (len < need || !r->dirents) {
			r->reply.error = -EIO;
			r->reply.nentries = 0;
		} else if (copy_from_user(r->dirents, buf + sizeof(hdr),
					  (size_t)n *
						  sizeof(struct swvfs_dirent))) {
			r->reply.error = -EFAULT;
			r->reply.nentries = 0;
		} else {
			r->reply.nentries = n;
		}
	} else if (hdr.error == 0 && r->data && hdr.datalen > 0) {
		/* READ/READLINK/GETXATTR/LISTXATTR: copy the reply data. */
		u32 n = min_t(u32, hdr.datalen, r->max_data);
		size_t need = sizeof(hdr) + n;

		if (len < need) {
			r->reply.error = -EIO;
			r->reply.datalen = 0;
		} else if (copy_from_user(r->data, buf + sizeof(hdr), n)) {
			r->reply.error = -EFAULT;
			r->reply.datalen = 0;
		} else {
			r->reply.datalen = n;
		}
	}

	list_del_init(&r->list);
	r->on_inflight = false;
	r->answered = true;
	complete(&r->done);
	mutex_unlock(&swvfs_lock);
	return len;
}

#ifdef SWVFS_HAVE_URING
/* ---- io_uring_cmd ring transport ------------------------------------------ */
/*
 * A ublk-style ring: the daemon arms FETCH commands that park until a request
 * is available, then commits replies with COMMIT_AND_FETCH which re-arms the
 * same slot. swvfs_submit()/swvfs_wait() and the pending/inflight lists are
 * reused unchanged; the ring is just a second delivery path. The hard part is
 * lifetime + teardown — see the invariants and lock ordering in IOURING_RING.md.
 *
 * Lock ordering: io_uring holds ctx->uring_lock across ->uring_cmd issue, the
 * task_work cbs, and the cancel walk; swvfs_lock nests strictly inside it. We
 * never hold swvfs_lock across io_uring_cmd_done or across a faulting copy in a
 * cb (the cb also holds uring_lock; faulting under two mutexes risks fs-recursion
 * self-deadlock). We kref-pin r across the lockless copy instead.
 */

/* Ingest a COMMIT reply from the daemon's slot buffer: read the 96-byte header,
 * match the inflight request by tag, copy the READDIR/READ payload, complete it.
 * Runs in the daemon's task_work (uring_lock held), so the data copy is done
 * with swvfs_lock dropped and r kref-pinned. */
static void swvfs_commit_ingest(const struct swvfs_cmd_pdu *pdu)
{
	const void __user *ubuf = (const void __user *)(unsigned long)pdu->buf_addr;
	struct swvfs_reply hdr;
	struct swvfs_request *r = NULL, *it;

	if (pdu->reply_len < sizeof(hdr) || pdu->reply_len > pdu->buf_len)
		return; /* malformed; original request will time out */
	if (copy_from_user(&hdr, ubuf, sizeof(hdr)))
		return;

	mutex_lock(&swvfs_lock);
	list_for_each_entry(it, &swvfs_inflight, list) {
		if (it->tag == hdr.tag) {
			r = it;
			break;
		}
	}
	if (!r) {
		mutex_unlock(&swvfs_lock); /* late commit for a timed-out request */
		return;
	}
	/* Claim r off inflight now so a concurrent swvfs_wait() timeout cannot also
	 * handle it; pin it across the lockless data copy below. */
	list_del_init(&r->list);
	r->on_inflight = false;
	kref_get(&r->refcount);
	mutex_unlock(&swvfs_lock);

	r->reply = hdr;
	if (hdr.error == 0 && r->req.op == SWVFS_OP_READDIR && hdr.nentries > 0) {
		u32 n = min_t(u32, hdr.nentries, r->max_dirents);
		size_t need = sizeof(hdr) +
			      (size_t)n * sizeof(struct swvfs_dirent);

		if (pdu->reply_len < need || !r->dirents) {
			r->reply.error = -EIO;
			r->reply.nentries = 0;
		} else if (copy_from_user(r->dirents, ubuf + sizeof(hdr),
					  (size_t)n *
						  sizeof(struct swvfs_dirent))) {
			r->reply.error = -EFAULT;
			r->reply.nentries = 0;
		} else {
			r->reply.nentries = n;
		}
	} else if (hdr.error == 0 && r->data && hdr.datalen > 0) {
		u32 n = min_t(u32, hdr.datalen, r->max_data);
		size_t need = sizeof(hdr) + n;

		if (pdu->reply_len < need) {
			r->reply.error = -EIO;
			r->reply.datalen = 0;
		} else if (copy_from_user(r->data, ubuf + sizeof(hdr), n)) {
			r->reply.error = -EFAULT;
			r->reply.datalen = 0;
		} else {
			r->reply.datalen = n;
		}
	}

	mutex_lock(&swvfs_lock);
	if (!r->answered) {
		r->answered = true;
		complete(&r->done);
	}
	mutex_unlock(&swvfs_lock);
	kref_put(&r->refcount, swvfs_req_release);
}

/* Deliver one pending request to the cmd parked on its slot, or leave it parked
 * if none is pending. Completes cmd iff it delivers a request or hits an error;
 * otherwise the cmd stays parked. task_work context (uring_lock held). */
static void __swvfs_deliver(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct swvfs_cmd_pdu *pdu = io_uring_cmd_to_pdu(cmd, struct swvfs_cmd_pdu);
	struct swvfs_slot *s = &swvfs_slots[pdu->slot];
	void __user *ubuf = (void __user *)(unsigned long)pdu->buf_addr;
	struct swvfs_request *r;
	size_t total;
	int ret;

	mutex_lock(&swvfs_lock);
	if (s->cmd != cmd) { /* cancel already claimed and completed this cmd */
		mutex_unlock(&swvfs_lock);
		return;
	}
	if (current != swvfs_daemon || (current->flags & PF_EXITING)) {
		/* PF_EXITING fallback runs the cb in a kworker with the wrong mm. */
		s->cmd = NULL;
		s->scheduled = false;
		mutex_unlock(&swvfs_lock);
		io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags);
		return;
	}
	if (list_empty(&swvfs_pending)) {
		s->scheduled = false; /* stay parked; a later swvfs_kick() re-arms */
		mutex_unlock(&swvfs_lock);
		return; /* do NOT complete cmd */
	}
	r = list_first_entry(&swvfs_pending, struct swvfs_request, list);
	list_del_init(&r->list);
	r->on_pending = false;
	list_add_tail(&r->list, &swvfs_inflight);
	r->on_inflight = true;
	s->cmd = NULL; /* claim: this cb is the sole completer of cmd */
	s->scheduled = false;
	total = sizeof(r->req) + r->payload_len;
	kref_get(&r->refcount); /* pin across the lockless copy_to_user below */
	mutex_unlock(&swvfs_lock);

	if (pdu->buf_len < total) {
		ret = -EMSGSIZE;
	} else {
		ret = total;
		if (copy_to_user(ubuf, &r->req, sizeof(r->req)))
			ret = -EFAULT;
		else if (r->payload_len &&
			 copy_to_user(ubuf + sizeof(r->req), r->payload,
				      r->payload_len))
			ret = -EFAULT;
	}

	if (ret < 0) { /* delivery failed: wake the waiter with an error */
		mutex_lock(&swvfs_lock);
		if (r->on_inflight && !r->answered) {
			list_del_init(&r->list);
			r->on_inflight = false;
			r->reply.error = -EIO;
			r->answered = true;
			complete(&r->done);
		}
		mutex_unlock(&swvfs_lock);
	}
	kref_put(&r->refcount, swvfs_req_release);
	io_uring_cmd_done(cmd, ret, 0, issue_flags);
}

static void swvfs_deliver_cb(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	__swvfs_deliver(cmd, issue_flags);
}

static void swvfs_commit_cb(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct swvfs_cmd_pdu *pdu = io_uring_cmd_to_pdu(cmd, struct swvfs_cmd_pdu);
	struct swvfs_slot *s = &swvfs_slots[pdu->slot];

	if (current != swvfs_daemon || (current->flags & PF_EXITING)) {
		mutex_lock(&swvfs_lock);
		if (s->cmd == cmd) {
			s->cmd = NULL;
			s->scheduled = false;
		}
		mutex_unlock(&swvfs_lock);
		io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags);
		return;
	}
	swvfs_commit_ingest(pdu); /* deliver the reply to its inflight request */
	__swvfs_deliver(cmd, issue_flags); /* re-park this cmd / deliver the next */
}

/* Parse, validate, claim a slot, and park the cmd; schedule its task_work cb if
 * there is work (COMMIT always ingests; FETCH only when a request is waiting).
 * Returns -EIOCBQUEUED on success (parked) or a negative errno to complete
 * inline. Runs with uring_lock held (inline issue or the resubmit task_work). */
static int swvfs_uring_arm(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	const struct swvfs_uring_cmd *c = io_uring_sqe_cmd(cmd->sqe);
	struct swvfs_cmd_pdu *pdu = io_uring_cmd_to_pdu(cmd, struct swvfs_cmd_pdu);
	bool commit = cmd->cmd_op == SWVFS_URING_COMMIT_AND_FETCH;
	struct swvfs_slot *s;
	bool kick;

	if (!commit && cmd->cmd_op != SWVFS_URING_FETCH)
		return -EINVAL;
	if (c->slot >= SWVFS_RING_QD || c->buf_len < SWVFS_RING_BUF)
		return -EINVAL;

	pdu->slot = c->slot;
	pdu->reply_len = c->reply_len;
	pdu->buf_addr = c->buf_addr;
	pdu->buf_len = c->buf_len;

	mutex_lock(&swvfs_lock);
	if (swvfs_transport == SWVFS_TP_LEGACY) {
		mutex_unlock(&swvfs_lock);
		return -EBUSY; /* this daemon already chose read()/write() */
	}
	if (!swvfs_connected) {
		mutex_unlock(&swvfs_lock);
		return -ENOTCONN;
	}
	swvfs_transport = SWVFS_TP_RING;
	if (!swvfs_daemon && !(current->flags & PF_KTHREAD)) {
		get_task_struct(current);
		swvfs_daemon = current;
	}
	s = &swvfs_slots[c->slot];
	if (s->cmd) { /* the daemon double-armed this slot */
		mutex_unlock(&swvfs_lock);
		return -EEXIST;
	}
	s->cmd = cmd;
	s->buf_addr = c->buf_addr;
	s->buf_len = c->buf_len;
	kick = commit || !list_empty(&swvfs_pending);
	if (kick)
		s->scheduled = true;
	/* Mark cancelable LAST and only on the park path (after the slot is
	 * claimed): no inline-error return above reaches here, so io_uring never
	 * completes a cmd that is still on its cancelable list. Done before the cb
	 * is scheduled, so the cb (which calls io_uring_cmd_done ->
	 * del_cancelable) cannot run first. */
	io_uring_cmd_mark_cancelable(cmd, issue_flags);
	mutex_unlock(&swvfs_lock);

	if (kick)
		io_uring_cmd_complete_in_task(
			cmd, commit ? swvfs_commit_cb : swvfs_deliver_cb);
	return -EIOCBQUEUED;
}

static void swvfs_resubmit_cb(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	int ret = swvfs_uring_arm(cmd, issue_flags);

	if (ret != -EIOCBQUEUED)
		io_uring_cmd_done(cmd, ret, 0, issue_flags);
}

/* io_uring tears the ring down (daemon close/exit) by walking its cancelable
 * cmds and calling us with IO_URING_F_CANCEL for each. cmd->sqe may be NULL
 * here, so read only pdu. Complete the cmd exactly once via the claim token. */
static void swvfs_uring_cancel(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct swvfs_cmd_pdu *pdu = io_uring_cmd_to_pdu(cmd, struct swvfs_cmd_pdu);
	struct swvfs_slot *s = &swvfs_slots[pdu->slot];
	bool claimed;

	mutex_lock(&swvfs_lock);
	claimed = s->cmd == cmd;
	if (claimed) {
		s->cmd = NULL;
		s->scheduled = false;
	}
	mutex_unlock(&swvfs_lock);
	if (claimed)
		io_uring_cmd_done(cmd, -ENODEV, 0, issue_flags);
	/* else a deliver/commit cb already claimed and completed it */
}

static int swvfs_dev_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	if (issue_flags & IO_URING_F_CANCEL) { /* FIRST, before any sqe deref */
		swvfs_uring_cancel(cmd, issue_flags);
		return 0;
	}
	if (issue_flags & IO_URING_F_UNLOCKED) {
		/* io-wq path (uring_lock not held): re-issue in task context where
		 * the lock ordering and completion rules hold. */
		io_uring_cmd_complete_in_task(cmd, swvfs_resubmit_cb);
		return -EIOCBQUEUED;
	}
	return swvfs_uring_arm(cmd, issue_flags);
}

/* From swvfs_submit(): wake one parked-and-unscheduled cmd to deliver the
 * freshly queued request. The scheduled flag (set here under swvfs_lock)
 * guarantees one task_work per parked cmd. Process context only. */
static void swvfs_kick(void)
{
	struct io_uring_cmd *cmd = NULL;
	int i;

	mutex_lock(&swvfs_lock);
	if (swvfs_transport != SWVFS_TP_RING || list_empty(&swvfs_pending)) {
		mutex_unlock(&swvfs_lock);
		return;
	}
	for (i = 0; i < SWVFS_RING_QD; i++) {
		if (swvfs_slots[i].cmd && !swvfs_slots[i].scheduled) {
			swvfs_slots[i].scheduled = true;
			cmd = swvfs_slots[i].cmd;
			break;
		}
	}
	mutex_unlock(&swvfs_lock);
	if (cmd)
		io_uring_cmd_complete_in_task(cmd, swvfs_deliver_cb);
}
#else
/* No io_uring ring transport on this kernel: char-device transport only. */
static void swvfs_kick(void) { }
#endif /* SWVFS_HAVE_URING */

static int swvfs_dev_open(struct inode *inode, struct file *f)
{
	mutex_lock(&swvfs_lock);
	if (swvfs_connected) {
		mutex_unlock(&swvfs_lock);
		return -EBUSY;
	}
	swvfs_connected = true;
	swvfs_transport = SWVFS_TP_NONE;
	mutex_unlock(&swvfs_lock);
	pr_info("seaweedvfs: daemon connected\n");
	return 0;
}

static int swvfs_dev_release(struct inode *inode, struct file *f)
{
	struct swvfs_request *r, *tmp;
	struct task_struct *d;
	int i;

	/*
	 * A parked uring_cmd pins req->file (this device file) via fget, so this
	 * final fput runs only AFTER io_ring_exit_work has driven swvfs_uring_cancel
	 * on every parked cmd. Release therefore must NOT complete cmds or clear
	 * slot->cmd as a teardown action (the claim-token xchg is owned by the
	 * deliver/commit/cancel paths); every slot must already be drained here.
	 */
	mutex_lock(&swvfs_lock);
	swvfs_connected = false;
	swvfs_transport = SWVFS_TP_NONE;
	list_for_each_entry_safe(r, tmp, &swvfs_pending, list) {
		list_del_init(&r->list);
		r->on_pending = false;
		if (!r->answered) {
			r->reply.error = -ENOTCONN;
			r->answered = true;
			complete(&r->done);
		}
	}
	list_for_each_entry_safe(r, tmp, &swvfs_inflight, list) {
		list_del_init(&r->list);
		r->on_inflight = false;
		if (!r->answered) {
			r->reply.error = -ENOTCONN;
			r->answered = true;
			complete(&r->done);
		}
	}
	for (i = 0; i < SWVFS_RING_QD; i++) {
		WARN_ON_ONCE(swvfs_slots[i].cmd); /* cancel walk should have drained */
		swvfs_slots[i].scheduled = false;
	}
	d = swvfs_daemon;
	swvfs_daemon = NULL;
	mutex_unlock(&swvfs_lock);
	if (d)
		put_task_struct(d);
	/* The daemon is gone and a successor's subscription resumes from "now", so
	 * drop every mount's caches; anything changed during the outage re-fetches on
	 * next access. Safe here: swvfs_connected is already false, so a racing read
	 * fails fast (ENOTCONN) rather than blocking with a folio locked. */
	swvfs_flush_all();
	pr_info("seaweedvfs: daemon disconnected\n");
	return 0;
}

static const struct file_operations swvfs_dev_fops = {
	.owner = THIS_MODULE,
	.open = swvfs_dev_open,
	.release = swvfs_dev_release,
	.read = swvfs_dev_read,
	.write = swvfs_dev_write,
#ifdef SWVFS_HAVE_URING
	.uring_cmd = swvfs_dev_uring_cmd,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice swvfs_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "seaweedvfs",
	.fops = &swvfs_dev_fops,
	.mode = 0600,
};

/* ------------------------------------------------------------------ */
/* Filesystem                                                          */
/* ------------------------------------------------------------------ */

static const struct inode_operations seaweedvfs_dir_inode_ops;
static const struct file_operations seaweedvfs_dir_ops;
static const struct inode_operations seaweedvfs_file_inode_ops;
static const struct file_operations seaweedvfs_file_ops;
static const struct file_operations seaweedvfs_file_ops_dlm;
static const struct address_space_operations seaweedvfs_aops;
static const struct inode_operations seaweedvfs_symlink_inode_ops;

static void swvfs_apply_attr(struct inode *inode, const struct swvfs_attr *a)
{
	inode->i_mode = a->mode;
	i_uid_write(inode, a->uid);
	i_gid_write(inode, a->gid);
	set_nlink(inode, a->nlink ? a->nlink : 1);
	/* a->rdev is the portable new_encode_dev() form (matching FUSE/SeaweedFS
	 * on-disk layout); decode it into a kernel dev_t. */
	inode->i_rdev = new_decode_dev(a->rdev);
	i_size_write(inode, a->size);
	SWVFS_INODE_SET_MTIME(inode, a->mtime_sec, a->mtime_nsec);
	inode_set_ctime(inode, a->ctime_sec, a->ctime_nsec);
	SWVFS_INODE_SET_ATIME(inode, a->atime_sec, a->atime_nsec);
	/* A regular file with no set-id bits has nothing for the write path to
	 * strip, so mark it S_NOSEC: file_remove_privs() then short-circuits
	 * instead of issuing a GETXATTR (security.capability) upcall on every
	 * write. Cleared again if the mode later gains a set-id bit. */
	if (S_ISREG(inode->i_mode) && !(inode->i_mode & (S_ISUID | S_ISGID)))
		inode_set_flags(inode, S_NOSEC, S_NOSEC);
	else
		inode_set_flags(inode, 0, S_NOSEC);
	/* Stamp the attr-cache time (jiffies; 0 means "never", so avoid it). */
	inode->i_private = (void *)(jiffies | 1UL);
}

/* Get-or-create an inode with the daemon-assigned (hashed) number. */
/* `trust` says the attrs come from our own mutation (create/mkdir/mknod/symlink),
 * so reinitialize even a reused inode and drop its page cache: a path-hashed ino
 * can resolve to an unlink-while-open inode still cached at nlink 0 with stale
 * size/mode/pages, and recreating the name must not inherit them. An untrusted
 * reply (lookup/readdir) applies only to a fresh inode — re-stamping an existing
 * one risks masking an invalidation the reply raced, so the generation-guarded
 * getattr refreshes it instead. */
static struct inode *swvfs_iget(struct super_block *sb,
				const struct swvfs_attr *a, bool trust)
{
	struct inode *inode = iget_locked(sb, a->ino);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (SWVFS_I_STATE(inode) & I_NEW) {
		swvfs_apply_attr(inode, a);
		if (S_ISDIR(inode->i_mode)) {
			inode->i_op = &seaweedvfs_dir_inode_ops;
			inode->i_fop = &seaweedvfs_dir_ops;
		} else if (S_ISLNK(inode->i_mode)) {
			inode->i_op = &seaweedvfs_symlink_inode_ops;
		} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
			   S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
			init_special_inode(inode, inode->i_mode, inode->i_rdev);
		} else {
			inode->i_op = &seaweedvfs_file_inode_ops;
			inode->i_fop = distributed_locks ? &seaweedvfs_file_ops_dlm
							 : &seaweedvfs_file_ops;
			inode->i_mapping->a_ops = &seaweedvfs_aops;
		}
		unlock_new_inode(inode);
	} else if (trust) {
		swvfs_apply_attr(inode, a);
		invalidate_inode_pages2_range(inode->i_mapping, 0, -1);
	}
	return inode;
}

/* Build one READ sub-request for [off, off+seg). */
static struct swvfs_request *swvfs_make_read(const char *path, size_t plen,
					     loff_t off, size_t seg)
{
	struct swvfs_request *r =
		swvfs_make_req(SWVFS_OP_READ, path, plen, NULL, 0, NULL, 0);

	if (!r)
		return NULL;
	r->data = kvmalloc(seg, GFP_KERNEL);
	if (!r->data) {
		swvfs_free_req(r);
		return NULL;
	}
	r->max_data = seg;
	r->req.offset = off;
	r->req.size = seg;
	return r;
}

/* Copy a completed READ sub-request into dst[seg_off..], zero-filling a short
 * read. */
static void swvfs_read_copy(char *dst, size_t seg_off, size_t seg,
			    struct swvfs_request *r)
{
	size_t got = min_t(size_t, r->reply.datalen, seg);

	memcpy(dst + seg_off, r->data, got);
	if (got < seg)
		memset(dst + seg_off + got, 0, seg - got);
}

/* Read [off, off+len) for `path` into a kernel buffer in SWVFS_READAHEAD_MAX
 * chunks; short reads are zero-filled. A multi-chunk read submits all its
 * chunks at once so the concurrent daemon fetches them in parallel — a single
 * sequential reader then approaches the multi-stream aggregate. */
static int swvfs_read_into(const char *path, size_t plen, loff_t off, char *dst,
			   size_t len)
{
	size_t nseg, i;
	struct swvfs_request **reqs;
	int err = 0;
	size_t submitted = 0;

	if (len == 0)
		return 0;
	nseg = (len + SWVFS_READAHEAD_MAX - 1) / SWVFS_READAHEAD_MAX;

	if (nseg == 1) {
		struct swvfs_request *r = swvfs_make_read(path, plen, off, len);

		if (!r)
			return -ENOMEM;
		err = swvfs_send(r);
		if (!err)
			swvfs_read_copy(dst, 0, len, r);
		swvfs_free_req(r);
		return err;
	}

	reqs = kcalloc(nseg, sizeof(*reqs), GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;

	/* Submit all chunks concurrently. */
	for (i = 0; i < nseg; i++) {
		size_t seg_off = i * SWVFS_READAHEAD_MAX;
		size_t seg = min_t(size_t, len - seg_off, SWVFS_READAHEAD_MAX);
		struct swvfs_request *r = swvfs_make_read(path, plen,
							  off + seg_off, seg);

		if (!r) {
			err = -ENOMEM;
			break;
		}
		if (swvfs_submit(r)) {
			swvfs_free_req(r);
			err = -ENOTCONN;
			break;
		}
		reqs[i] = r;
		submitted++;
	}

	/* Wait for (and copy) everything submitted; reap all even on error. */
	for (i = 0; i < submitted; i++) {
		size_t seg_off = i * SWVFS_READAHEAD_MAX;
		size_t seg = min_t(size_t, len - seg_off, SWVFS_READAHEAD_MAX);
		int e = swvfs_wait(reqs[i]);

		if (e == 0 && err == 0)
			swvfs_read_copy(dst, seg_off, seg, reqs[i]);
		else if (e && err == 0)
			err = e;
		swvfs_free_req(reqs[i]);
	}
	kfree(reqs);
	return err;
}

static int seaweedvfs_read_folio(struct file *file, struct folio *folio)
{
	size_t len = folio_size(folio);
	char *pbuf, *path, *buf;
	int err;

	if (!file) {
		folio_unlock(folio);
		return -EIO;
	}
	pbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!pbuf) {
		folio_unlock(folio);
		return -ENOMEM;
	}
	path = dentry_path_raw(file->f_path.dentry, pbuf, SWVFS_PATH_MAX);
	if (IS_ERR(path)) {
		kfree(pbuf);
		folio_unlock(folio);
		return PTR_ERR(path);
	}
	buf = kvmalloc(len, GFP_KERNEL);
	err = buf ? swvfs_read_into(path, strlen(path), folio_pos(folio), buf, len)
		  : -ENOMEM;
	if (!err)
		SWVFS_MEMCPY_TO_FOLIO(folio, 0, buf, len);
	kvfree(buf);
	kfree(pbuf);
	if (!err)
		folio_mark_uptodate(folio);
	folio_unlock(folio);
	return err;
}

/* Fill one read-ahead folio from the window buffer (or zero-fill past EOF), mark
 * it uptodate, and unlock it. On a fetch error the folio is left not-uptodate so
 * the next access retries it synchronously via read_folio. */
static void swvfs_ra_fill_folio(struct folio *folio, const char *buf,
				loff_t start, size_t total, int err)
{
	if (!err) {
		size_t foff = folio_pos(folio) - start;
		size_t flen = folio_size(folio);
		size_t avail = foff < total ? min_t(size_t, flen, total - foff) : 0;

		if (avail)
			SWVFS_MEMCPY_TO_FOLIO(folio, 0, buf + foff, avail);
		if (avail < flen)
			folio_zero_range(folio, avail, flen - avail);
		folio_mark_uptodate(folio);
	}
	folio_unlock(folio);
}

/* Deferred read-ahead: holds a window's locked folios while the fetch runs. */
struct swvfs_ra_work {
	struct work_struct work;
	char *path;
	loff_t start;
	size_t total;
	unsigned int nr;
	struct folio *folios[]; /* each carries a ref (from __readahead_folio) */
};

static void swvfs_ra_worker(struct work_struct *w)
{
	struct swvfs_ra_work *r = container_of(w, struct swvfs_ra_work, work);
	char *buf = kvmalloc(r->total, GFP_KERNEL);
	int err = buf ? swvfs_read_into(r->path, strlen(r->path), r->start, buf,
					r->total)
		      : -ENOMEM;
	unsigned int i;

	for (i = 0; i < r->nr; i++) {
		swvfs_ra_fill_folio(r->folios[i], buf, r->start, r->total, err);
		folio_put(r->folios[i]);
	}
	kvfree(buf);
	kfree(r->path);
	kfree(r);
}

/* Queue the window's folios for asynchronous fetch. Returns true if it took
 * ownership of (all) the folios; false (consuming none) so the caller falls back
 * to a synchronous fetch. */
static bool swvfs_try_async_readahead(struct readahead_control *rac, loff_t start,
				      size_t total)
{
	unsigned int count = readahead_count(rac);
	struct swvfs_ra_work *r;
	struct folio *folio;
	char *pbuf, *path;
	unsigned int i = 0;

	r = kmalloc(struct_size(r, folios, count), GFP_KERNEL);
	if (!r)
		return false;
	pbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!pbuf) {
		kfree(r);
		return false;
	}
	path = dentry_path_raw(rac->file->f_path.dentry, pbuf, SWVFS_PATH_MAX);
	r->path = IS_ERR(path) ? NULL : kstrdup(path, GFP_KERNEL);
	kfree(pbuf);
	if (!r->path) {
		kfree(r);
		return false;
	}
	r->start = start;
	r->total = total;
	while (i < count && (folio = __readahead_folio(rac)) != NULL)
		r->folios[i++] = folio;
	r->nr = i;
	INIT_WORK(&r->work, swvfs_ra_worker);
	queue_work(swvfs_ra_wq, &r->work);
	return true;
}

static void seaweedvfs_readahead(struct readahead_control *rac)
{
	loff_t start = readahead_pos(rac);
	size_t total = readahead_length(rac);
	struct folio *folio;
	char *pbuf, *path, *buf = NULL;
	int err = -EIO;

	/* Asynchronous: hand the locked folios to the workqueue so the fetch
	 * overlaps the application consuming the previous window. */
	if (rac->file && swvfs_ra_wq &&
	    swvfs_try_async_readahead(rac, start, total))
		return;

	/* Synchronous fallback (no file / no workqueue / setup failed). */
	if (rac->file) {
		pbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
		if (pbuf) {
			path = dentry_path_raw(rac->file->f_path.dentry, pbuf,
					       SWVFS_PATH_MAX);
			if (!IS_ERR(path)) {
				buf = kvmalloc(total, GFP_KERNEL);
				err = buf ? swvfs_read_into(path, strlen(path),
							    start, buf, total)
					  : -ENOMEM;
			}
			kfree(pbuf);
		}
	}

	while ((folio = readahead_folio(rac)) != NULL)
		swvfs_ra_fill_folio(folio, buf, start, total, err);
	kvfree(buf);
}

/* Snapshot the parent directory's namespace generation onto a child dentry (in
 * d_fsdata), so d_revalidate can later tell whether the parent changed under it.
 * Always pass the generation sampled BEFORE the upcall that confirmed the name
 * (lookup, readdir, or a create/mkdir/... mutation): if an invalidation races the
 * upcall and bumps the parent's generation first, the stale snapshot then fails
 * d_revalidate and the name is re-resolved, instead of silently inheriting the
 * bumped value and passing. */
static void swvfs_stamp_dentry(struct dentry *dentry, unsigned int gen)
{
	dentry->d_fsdata = (void *)(unsigned long)gen;
}

/* readdirplus: instantiate the child dentry+inode with the attrs the daemon
 * already returned, so the follow-up lookup/getattr for `ls -l` hit the cache. */
static void swvfs_prime_dcache(struct dentry *parent, struct swvfs_dirent *d,
			       unsigned int gen)
{
	struct qstr name;
	struct dentry *dentry, *alias;
	struct inode *inode;

	name.name = d->name;
	name.len = min_t(u32, d->namelen, SWVFS_NAME_MAX);
	name.hash = full_name_hash(parent, name.name, name.len);

	dentry = d_lookup(parent, &name);
	if (dentry) {
		/* Already cached. Don't re-stamp its attrs from this readdir
		 * batch: the batch may predate a remote change whose invalidation
		 * already landed, and re-stamping would mask it until the TTL.
		 * A gen-guarded getattr refreshes it instead (seaweedvfs_getattr). */
		dput(dentry);
		return;
	}
	dentry = d_alloc(parent, &name);
	if (!dentry)
		return;
	inode = swvfs_iget(parent->d_sb, &d->attr, false);
	if (IS_ERR(inode)) {
		dput(dentry);
		return;
	}
	alias = d_splice_alias(inode, dentry);
	if (!IS_ERR(alias))
		swvfs_stamp_dentry(alias ? alias : dentry, gen);
	if (!IS_ERR_OR_NULL(alias))
		dput(alias);
	dput(dentry);
}

static int seaweedvfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry *parent = file->f_path.dentry;
	char *pbuf, *dirpath;
	int err = 0;
	/* Snapshot the directory's namespace generation before the READDIR upcall(s),
	 * to stamp the primed child dentries (see swvfs_prime_dcache). */
	unsigned int gen = atomic_read(&SWVFS_I(d_inode(parent))->cache_gen);

	if (!dir_emit_dots(file, ctx))
		return 0;

	pbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!pbuf)
		return -ENOMEM;
	dirpath = dentry_path_raw(file->f_path.dentry, pbuf, SWVFS_PATH_MAX);
	if (IS_ERR(dirpath)) {
		kfree(pbuf);
		return PTR_ERR(dirpath);
	}

	while (1) {
		struct swvfs_request *r;
		u32 i;

		r = swvfs_make_req(SWVFS_OP_READDIR, dirpath, strlen(dirpath),
				   NULL, 0, NULL, 0);
		if (!r) {
			err = -ENOMEM;
			break;
		}
		r->dirents = kmalloc_array(SWVFS_MAX_DIRENTS,
					   sizeof(struct swvfs_dirent),
					   GFP_KERNEL);
		if (!r->dirents) {
			swvfs_free_req(r);
			err = -ENOMEM;
			break;
		}
		r->max_dirents = SWVFS_MAX_DIRENTS;
		r->req.offset = ctx->pos - 2; /* exclude "." and ".." */

		err = swvfs_send(r);
		if (err) {
			swvfs_free_req(r);
			break;
		}
		for (i = 0; i < r->reply.nentries; i++) {
			struct swvfs_dirent *d = &r->dirents[i];
			u32 nl = min_t(u32, d->namelen, SWVFS_NAME_MAX);

			swvfs_prime_dcache(parent, d, gen);
			if (!dir_emit(ctx, d->name, nl, d->attr.ino, d->type)) {
				swvfs_free_req(r);
				goto out;
			}
			ctx->pos++;
		}
		if (r->reply.eof || r->reply.nentries == 0) {
			swvfs_free_req(r);
			break;
		}
		swvfs_free_req(r);
	}
out:
	kfree(pbuf);
	return err < 0 ? err : 0;
}

/* A child dentry is valid while its parent directory's namespace generation still
 * matches the snapshot taken when the name was cached. A namespace change
 * (create/delete/rename) bumps the parent's gen via swvfs_invalidate, so a stale
 * name is re-resolved on next use — including a dentry still referenced by an open
 * file or a concurrent lookup, which shrink_dcache cannot reclaim. The compare is
 * lockless, so RCU-walk need not drop to ref-walk. */
static int seaweedvfs_d_revalidate(SWVFS_D_REVALIDATE_ARGS)
{
	struct inode *pdir;

	if (IS_ROOT(dentry))
		return 1; /* the root always exists; no parent namespace to track */
	pdir = SWVFS_REVAL_DIR(dentry);
	if (!pdir)
		return -ECHILD;
	return (unsigned long)dentry->d_fsdata ==
	       (unsigned long)atomic_read(&SWVFS_I(pdir)->cache_gen);
}

static const struct dentry_operations seaweedvfs_dentry_ops = {
	.d_revalidate = seaweedvfs_d_revalidate,
};

static struct dentry *seaweedvfs_lookup(struct inode *dir,
					struct dentry *dentry,
					unsigned int flags)
{
	struct swvfs_request *r;
	struct inode *inode = NULL;
	struct dentry *res;
	unsigned int gen;
	int err;

	if (dentry->d_name.len > SWVFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	r = swvfs_req_from_dentry(SWVFS_OP_LOOKUP, dentry);
	if (IS_ERR(r))
		return ERR_CAST(r);

	/* Sample the parent's namespace generation before the upcall; the resolved
	 * dentry (positive or negative) is stamped with it, so an invalidation that
	 * races this lookup makes d_revalidate re-resolve the name. */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		inode = swvfs_iget(dir->i_sb, &r->reply.attr, false);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			inode = NULL;
		}
	}
	swvfs_free_req(r);

	if (err && err != -ENOENT)
		return ERR_PTR(err);
	res = d_splice_alias(inode, dentry); /* inode == NULL on ENOENT → negative */
	if (!IS_ERR(res))
		swvfs_stamp_dentry(res ? res : dentry, gen);
	return res;
}

static int seaweedvfs_getattr(SWVFS_IDMAP idmap, const struct path *path,
			      struct kstat *stat, u32 request_mask,
			      unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	unsigned long last = (unsigned long)inode->i_private;
	bool fresh = last &&
		     time_before(jiffies, last + msecs_to_jiffies(SWVFS_ATTR_TTL_MS));

	/* Skip the upcall if attrs were refreshed within the TTL (e.g. by the
	 * lookup/readdir that just populated this inode). */
	if (inode->i_ino != SEAWEEDVFS_ROOT_INO && !fresh) {
		struct swvfs_request *r =
			swvfs_req_from_dentry(SWVFS_OP_GETATTR, path->dentry);

		if (!IS_ERR(r)) {
			int gen = atomic_read(&SWVFS_I(inode)->cache_gen);
			int err = swvfs_send(r);

			if (err == 0 && r->reply.attr.ino) {
				/* Drop the reply if an invalidation raced this
				 * upcall: it may predate the change, and applying
				 * it would re-stamp stale attrs as fresh. Leaving
				 * i_private clear makes the next getattr re-fetch. */
				if (atomic_read(&SWVFS_I(inode)->cache_gen) == gen)
					swvfs_apply_attr(inode, &r->reply.attr);
			} else if (err == -ENOENT) {
				/* Removed on another client: stop serving the
				 * cached inode. Drop the dentry so it re-resolves
				 * to a negative, and report the entry gone. */
				swvfs_free_req(r);
				d_drop(path->dentry);
				return -ENOENT;
			}
			swvfs_free_req(r);
		}
	}
	SWVFS_FILLATTR(idmap, request_mask, inode, stat);
	return 0;
}

static int swvfs_make(struct inode *dir, struct dentry *dentry, umode_t mode,
		      u32 op)
{
	struct swvfs_request *r;
	struct inode *inode;
	unsigned int gen;
	int err;

	if (dentry->d_name.len > SWVFS_NAME_MAX)
		return -ENAMETOOLONG;
	r = swvfs_req_from_dentry(op, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	r->req.mode = mode;
	r->req.uid = from_kuid(&init_user_ns, current_fsuid());
	r->req.gid = from_kgid(&init_user_ns, current_fsgid());

	/* Parent generation sampled before the RPC (see swvfs_stamp_dentry). */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		inode = swvfs_iget(dir->i_sb, &r->reply.attr, true);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
		} else {
			/*
			 * No inc_nlink(dir) for mkdir: directory link counts are
			 * owned by the daemon (a constant 2, applied to the inode
			 * by swvfs_apply_attr). Maintaining a parallel 2+subdirs
			 * count here races that set_nlink -- a concurrent
			 * lookup/getattr/readdir resets the parent to 2 -- and,
			 * with ino=hash(path) inode reuse, drives the parent nlink
			 * through 0, tripping WARN_ON in inc_nlink/drop_nlink.
			 */
			d_instantiate(dentry, inode);
			swvfs_stamp_dentry(dentry, gen);
		}
	}
	swvfs_free_req(r);
	return err;
}

static int seaweedvfs_create(SWVFS_IDMAP idmap, struct inode *dir,
			     struct dentry *dentry, umode_t mode, bool excl)
{
	return swvfs_make(dir, dentry, mode, SWVFS_OP_CREATE);
}

/* Decline to open the file ourselves, but first resolve the name when the VFS
 * handed us an unresolved (in-lookup) dentry. Because we provide ->atomic_open
 * the VFS does NOT fall back to ->lookup for an open, so without this a plain
 * open of a name not already in our dcache — e.g. a file another client just
 * created — would be reported absent (the in-lookup dentry stays negative).
 *
 * `force` additionally re-resolves a *cached* negative dentry: the caller already
 * learned the name exists on the filer (CREATE returned EEXIST), so the negative
 * is stale even though its invalidation may not have arrived yet — without this,
 * open(O_CREAT) without O_EXCL would wrongly return ENOENT. (lookup_open returns a
 * cached positive before calling ->atomic_open, so the dentry here is only ever
 * in-lookup or negative.) Drop the stale negative so it can be re-spliced. */
static int swvfs_finish_no_open(struct inode *dir, struct dentry *dentry,
				struct file *file, bool force)
{
	struct dentry *res = NULL;

	if (force && !d_in_lookup(dentry))
		d_drop(dentry);
	if (force || d_in_lookup(dentry)) {
		res = seaweedvfs_lookup(dir, dentry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);
	}
	return finish_no_open(file, res);
}

/* Combine create + open into a single upcall for open(O_CREAT). The VFS would
 * otherwise call ->lookup (a negative-LOOKUP upcall) before ->create; here we
 * try an exclusive CREATE directly and only fall back to the normal lookup+open
 * path if the file already exists. */
static int seaweedvfs_atomic_open(struct inode *dir, struct dentry *dentry,
				  struct file *file, unsigned int open_flag,
				  umode_t mode)
{
	struct swvfs_request *r;
	struct inode *inode;
	unsigned int gen;
	int err;

	/* Plain (non-create) open: resolve and open the existing name (or report it
	 * gone) — swvfs_finish_no_open does the lookup the VFS won't. A valid cached
	 * negative is trusted here (no filer evidence to the contrary). */
	if (!(open_flag & O_CREAT))
		return swvfs_finish_no_open(dir, dentry, file, false);
	if (dentry->d_name.len > SWVFS_NAME_MAX)
		return -ENAMETOOLONG;

	r = swvfs_req_from_dentry(SWVFS_OP_CREATE, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	r->req.mode = mode;
	r->req.uid = from_kuid(&init_user_ns, current_fsuid());
	r->req.gid = from_kgid(&init_user_ns, current_fsgid());
	r->req.valid = SWVFS_CREATE_EXCL; /* fail with EEXIST if it already exists */
	/* Parent generation sampled before the RPC (see swvfs_stamp_dentry). */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		struct dentry *alias = NULL;

		inode = swvfs_iget(dir->i_sb, &r->reply.attr, true);
		swvfs_free_req(r);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		/* The dentry may still be mid-lookup (DCACHE_PAR_LOOKUP, unhashed),
		 * since we skipped the VFS's negative lookup; d_instantiate would
		 * BUG on it, so use d_splice_alias which hashes + wakes it. A cached
		 * hashed-negative dentry takes the d_instantiate path. */
		if (d_in_lookup(dentry)) {
			alias = d_splice_alias(inode, dentry);
			if (IS_ERR(alias))
				return PTR_ERR(alias);
			if (alias)
				dentry = alias;
		} else {
			d_instantiate(dentry, inode);
		}
		swvfs_stamp_dentry(dentry, gen);
		file->f_mode |= FMODE_CREATED;
		err = finish_open(file, dentry, NULL);
		dput(alias);
		return err;
	}
	swvfs_free_req(r);

	/* Already exists: O_EXCL must fail; otherwise resolve and open it. Force the
	 * lookup — the filer just told us the name exists, so re-resolve even a cached
	 * negative whose invalidation is still in flight (else we'd return ENOENT). */
	if (err == -EEXIST && !(open_flag & O_EXCL))
		return swvfs_finish_no_open(dir, dentry, file, true);
	return err;
}

static SWVFS_MKDIR_RET seaweedvfs_mkdir(SWVFS_IDMAP idmap, struct inode *dir,
					struct dentry *dentry, umode_t mode)
{
	int err = swvfs_make(dir, dentry, mode | S_IFDIR, SWVFS_OP_MKDIR);

	return SWVFS_MKDIR_RESULT(err);
}

/* Create a special file (device node, fifo, or socket). The full st_mode
 * (type | perm) goes in req.mode; the encoded device number in req.size. */
static int seaweedvfs_mknod(SWVFS_IDMAP idmap, struct inode *dir,
			    struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct swvfs_request *r;
	struct inode *inode;
	unsigned int gen;
	int err;

	if (!S_ISCHR(mode) && !S_ISBLK(mode) && !S_ISFIFO(mode) &&
	    !S_ISSOCK(mode))
		return -EINVAL;
	if (dentry->d_name.len > SWVFS_NAME_MAX)
		return -ENAMETOOLONG;

	r = swvfs_req_from_dentry(SWVFS_OP_MKNOD, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	r->req.mode = mode;
	r->req.size = new_encode_dev(rdev);
	r->req.uid = from_kuid(&init_user_ns, current_fsuid());
	r->req.gid = from_kgid(&init_user_ns, current_fsgid());

	/* Parent generation sampled before the RPC (see swvfs_stamp_dentry). */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		inode = swvfs_iget(dir->i_sb, &r->reply.attr, true);
		if (IS_ERR(inode))
			err = PTR_ERR(inode);
		else {
			d_instantiate(dentry, inode);
			swvfs_stamp_dentry(dentry, gen);
		}
	}
	swvfs_free_req(r);
	return err;
}

static int swvfs_remove(struct dentry *dentry, u32 op)
{
	struct swvfs_request *r;
	struct inode *inode = d_inode(dentry);
	int err;

	r = swvfs_req_from_dentry(op, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	err = swvfs_send(r);
	if (err == 0) {
		/*
		 * Drop the removed entry to nlink 0 so the final iput evicts it
		 * (and, if a later ino=hash(path) create reuses the inode before
		 * eviction, swvfs_apply_attr re-inits the count via set_nlink).
		 * The parent directory's link count is left to the daemon (see
		 * swvfs_make): a drop_nlink(dir) here would underflow through 0
		 * and WARN once a concurrent attr refresh has reset it to 2.
		 */
		if (op == SWVFS_OP_RMDIR)
			clear_nlink(inode);
		else if (inode->i_nlink)
			drop_nlink(inode);
		inode_set_ctime_current(inode);
	}
	swvfs_free_req(r);
	return err;
}

static int seaweedvfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return swvfs_remove(dentry, SWVFS_OP_UNLINK);
}

static int seaweedvfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	return swvfs_remove(dentry, SWVFS_OP_RMDIR);
}

static int seaweedvfs_setattr(SWVFS_IDMAP idmap, struct dentry *dentry,
			      struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct swvfs_request *r;
	unsigned int gen;
	int err;

	err = setattr_prepare(idmap, dentry, iattr);
	if (err)
		return err;

	r = swvfs_req_from_dentry(SWVFS_OP_SETATTR, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	if (iattr->ia_valid & ATTR_MODE) {
		r->req.valid |= SWVFS_SET_MODE;
		r->req.mode = iattr->ia_mode;
	}
	if (iattr->ia_valid & ATTR_UID) {
		r->req.valid |= SWVFS_SET_UID;
		r->req.uid = from_kuid(&init_user_ns, iattr->ia_uid);
	}
	if (iattr->ia_valid & ATTR_GID) {
		r->req.valid |= SWVFS_SET_GID;
		r->req.gid = from_kgid(&init_user_ns, iattr->ia_gid);
	}
	if (iattr->ia_valid & ATTR_SIZE) {
		r->req.valid |= SWVFS_SET_SIZE;
		r->req.size = iattr->ia_size;
	}
	if (iattr->ia_valid & ATTR_MTIME) {
		r->req.valid |= SWVFS_SET_MTIME;
		r->req.mtime_sec = iattr->ia_mtime.tv_sec;
		r->req.mtime_nsec = iattr->ia_mtime.tv_nsec;
	}
	if (iattr->ia_valid & ATTR_ATIME) {
		r->req.valid |= SWVFS_SET_ATIME;
		r->req.atime_sec = iattr->ia_atime.tv_sec;
		r->req.atime_nsec = iattr->ia_atime.tv_nsec;
	}

	/* Snapshot the generation before the RPC. If a remote invalidation races this
	 * setattr, apply NONE of the local state — not truncate_setsize, not the reply
	 * attrs, not setattr_copy. A concurrent remote write may have won on the filer
	 * after our truncate, so the requested size is no longer authoritative;
	 * installing it could make reads return premature EOF. The invalidation already
	 * cleared i_private and dropped the page cache, so the next getattr/read
	 * refreshes from the filer (the request itself still succeeded there). */
	gen = atomic_read(&SWVFS_I(inode)->cache_gen);
	err = swvfs_send(r);
	if (err == 0 && atomic_read(&SWVFS_I(inode)->cache_gen) == gen) {
		if ((iattr->ia_valid & ATTR_SIZE) &&
		    iattr->ia_size != i_size_read(inode))
			truncate_setsize(inode, iattr->ia_size);
		if (r->reply.attr.ino)
			swvfs_apply_attr(inode, &r->reply.attr);
		else
			setattr_copy(idmap, inode, iattr);
		mark_inode_dirty(inode);
	}
	swvfs_free_req(r);
	return err;
}

static int seaweedvfs_symlink(SWVFS_IDMAP idmap, struct inode *dir,
			      struct dentry *dentry, const char *symname)
{
	struct swvfs_request *r;
	struct inode *inode;
	char *buf, *path;
	unsigned int gen;
	int err;

	if (dentry->d_name.len > SWVFS_NAME_MAX)
		return -ENAMETOOLONG;
	buf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = dentry_path_raw(dentry, buf, SWVFS_PATH_MAX);
	if (IS_ERR(path)) {
		kfree(buf);
		return PTR_ERR(path);
	}
	r = swvfs_make_req(SWVFS_OP_SYMLINK, path, strlen(path), symname,
			   strlen(symname), NULL, 0);
	kfree(buf);
	if (!r)
		return -ENOMEM;
	r->req.uid = from_kuid(&init_user_ns, current_fsuid());
	r->req.gid = from_kgid(&init_user_ns, current_fsgid());

	/* Parent generation sampled before the RPC (see swvfs_stamp_dentry). */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		inode = swvfs_iget(dir->i_sb, &r->reply.attr, true);
		if (IS_ERR(inode))
			err = PTR_ERR(inode);
		else {
			d_instantiate(dentry, inode);
			swvfs_stamp_dentry(dentry, gen);
		}
	}
	swvfs_free_req(r);
	return err;
}

static const char *seaweedvfs_get_link(struct dentry *dentry,
				       struct inode *inode,
				       struct delayed_call *done)
{
	struct swvfs_request *r;
	char *target;
	u32 n;
	int err;

	if (!dentry)
		return ERR_PTR(-ECHILD);
	r = swvfs_req_from_dentry(SWVFS_OP_READLINK, dentry);
	if (IS_ERR(r))
		return ERR_CAST(r);
	r->data = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!r->data) {
		swvfs_free_req(r);
		return ERR_PTR(-ENOMEM);
	}
	r->max_data = SWVFS_PATH_MAX - 1;

	err = swvfs_send(r);
	if (err) {
		swvfs_free_req(r);
		return ERR_PTR(err);
	}
	n = min_t(u32, r->reply.datalen, SWVFS_PATH_MAX - 1);
	target = kmalloc(n + 1, GFP_KERNEL);
	if (!target) {
		swvfs_free_req(r);
		return ERR_PTR(-ENOMEM);
	}
	memcpy(target, r->data, n);
	target[n] = '\0';
	swvfs_free_req(r);

	set_delayed_call(done, kfree_link, target);
	return target;
}

static int seaweedvfs_rename(SWVFS_IDMAP idmap, struct inode *old_dir,
			     struct dentry *old_dentry, struct inode *new_dir,
			     struct dentry *new_dentry, unsigned int flags)
{
	struct inode *target = d_inode(new_dentry);
	struct swvfs_request *r;
	char *obuf, *nbuf, *op, *np;
	int err;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	obuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	nbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!obuf || !nbuf) {
		kfree(obuf);
		kfree(nbuf);
		return -ENOMEM;
	}
	op = dentry_path_raw(old_dentry, obuf, SWVFS_PATH_MAX);
	np = dentry_path_raw(new_dentry, nbuf, SWVFS_PATH_MAX);
	if (IS_ERR(op) || IS_ERR(np)) {
		err = IS_ERR(op) ? PTR_ERR(op) : PTR_ERR(np);
		kfree(obuf);
		kfree(nbuf);
		return err;
	}
	r = swvfs_make_req(SWVFS_OP_RENAME, op, strlen(op), np, strlen(np),
			   NULL, 0);
	kfree(obuf);
	kfree(nbuf);
	if (!r)
		return -ENOMEM;

	err = swvfs_send(r);
	swvfs_free_req(r);
	if (err)
		return err;

	if (target) {
		/* Drop the overwritten entry to 0 so its final iput evicts it. */
		if (d_is_dir(new_dentry))
			clear_nlink(target);
		else if (target->i_nlink)
			drop_nlink(target);
		inode_set_ctime_current(target);
	}
	/*
	 * Don't adjust old_dir/new_dir nlink when a directory moves between
	 * parents: directory link counts are owned by the daemon (constant 2,
	 * see swvfs_make). Manual inc/drop here would race set_nlink from a
	 * concurrent attr refresh and underflow to 0 -> WARN.
	 */
	SWVFS_INODE_SET_MTIME_TS(old_dir, inode_set_ctime_current(old_dir));
	if (new_dir != old_dir)
		SWVFS_INODE_SET_MTIME_TS(new_dir, inode_set_ctime_current(new_dir));
	return 0;
}

/* Hard link: path1 = existing target (old_dentry), path2 = new link path.
 * The new dentry is wired to the SAME inode (ihold + d_instantiate). */
static int seaweedvfs_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
{
	struct inode *inode = d_inode(old_dentry);
	struct swvfs_request *r;
	char *obuf, *nbuf, *op, *np;
	unsigned int gen;
	int err;

	if (new_dentry->d_name.len > SWVFS_NAME_MAX)
		return -ENAMETOOLONG;

	obuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	nbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!obuf || !nbuf) {
		kfree(obuf);
		kfree(nbuf);
		return -ENOMEM;
	}
	op = dentry_path_raw(old_dentry, obuf, SWVFS_PATH_MAX);
	np = dentry_path_raw(new_dentry, nbuf, SWVFS_PATH_MAX);
	if (IS_ERR(op) || IS_ERR(np)) {
		err = IS_ERR(op) ? PTR_ERR(op) : PTR_ERR(np);
		kfree(obuf);
		kfree(nbuf);
		return err;
	}
	r = swvfs_make_req(SWVFS_OP_LINK, op, strlen(op), np, strlen(np),
			   NULL, 0);
	kfree(obuf);
	kfree(nbuf);
	if (!r)
		return -ENOMEM;

	/* Parent generation sampled before the RPC (see swvfs_stamp_dentry). */
	gen = atomic_read(&SWVFS_I(dir)->cache_gen);
	err = swvfs_send(r);
	if (err == 0) {
		if (r->reply.attr.nlink)
			set_nlink(inode, r->reply.attr.nlink);
		else
			inc_nlink(inode);
		inode_set_ctime_current(inode);
		ihold(inode);
		d_instantiate(new_dentry, inode);
		swvfs_stamp_dentry(new_dentry, gen);
	}
	swvfs_free_req(r);
	return err;
}

/* Synchronous write-through: each write streams via WRITE upcalls (the daemon
 * buffers and flushes on close/fsync); cached pages for the range are then
 * invalidated so reads see the new data. */
static ssize_t seaweedvfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	char *pbuf, *path;
	size_t plen;
	loff_t start, pos;
	ssize_t written = 0;
	int err = 0;

	pbuf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!pbuf)
		return -ENOMEM;
	path = dentry_path_raw(file->f_path.dentry, pbuf, SWVFS_PATH_MAX);
	if (IS_ERR(path)) {
		kfree(pbuf);
		return PTR_ERR(path);
	}
	plen = strlen(path);

	inode_lock(inode);
	/* POSIX: a write by an unprivileged process clears S_ISUID/S_ISGID. Our
	 * custom write_iter bypasses generic_file_write_iter, so strip them here
	 * (no-op fast path when the file has no set-id bits). */
	err = file_remove_privs(file);
	if (err) {
		inode_unlock(inode);
		kfree(pbuf);
		return err;
	}
	pos = (file->f_flags & O_APPEND) ? i_size_read(inode) : iocb->ki_pos;
	start = pos;

	while (iov_iter_count(from) > 0) {
		size_t chunk = min_t(size_t, iov_iter_count(from), SWVFS_MAX_WRITE);
		struct swvfs_request *r;
		void *tmp = kvmalloc(chunk, GFP_KERNEL);

		if (!tmp) {
			err = -ENOMEM;
			break;
		}
		if (copy_from_iter(tmp, chunk, from) != chunk) {
			kvfree(tmp);
			err = -EFAULT;
			break;
		}
		r = swvfs_make_req(SWVFS_OP_WRITE, path, plen, NULL, 0, tmp,
				   chunk);
		kvfree(tmp);
		if (!r) {
			err = -ENOMEM;
			break;
		}
		r->req.offset = pos;
		err = swvfs_send(r);
		swvfs_free_req(r);
		if (err)
			break;
		pos += chunk;
		written += chunk;
	}

	if (written > 0) {
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		SWVFS_INODE_SET_MTIME_TS(inode, inode_set_ctime_current(inode));
		iocb->ki_pos = pos;
		invalidate_inode_pages2_range(inode->i_mapping,
					      start >> PAGE_SHIFT,
					      (pos - 1) >> PAGE_SHIFT);
	}
	inode_unlock(inode);
	kfree(pbuf);
	return written > 0 ? written : err;
}

static int swvfs_buffer_op(struct file *file, u32 op)
{
	struct swvfs_request *r;
	int err;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	r = swvfs_req_from_dentry(op, file->f_path.dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	err = swvfs_send(r);
	swvfs_free_req(r);
	return err;
}

static int seaweedvfs_flush(struct file *file, fl_owner_t id)
{
	return swvfs_buffer_op(file, SWVFS_OP_FLUSH);
}

static int seaweedvfs_fsync(struct file *file, loff_t start, loff_t end,
			    int datasync)
{
	return swvfs_buffer_op(file, SWVFS_OP_FLUSH);
}

static int seaweedvfs_release_file(struct inode *inode, struct file *file)
{
	swvfs_buffer_op(file, SWVFS_OP_RELEASE); /* close() ignores the result */
	return 0;
}

/* Distributed advisory locks (flock + fcntl POSIX byte-range): route the lock
 * through the daemon to the filer's lock service so it is honoured across
 * mounts, then mirror it into the VFS's local lock state so the kernel releases
 * it on close (which re-enters with F_UNLCK -> a distributed unlock). Blocking
 * acquires poll, since the distributed service has no server-side wait queue.
 * F_GETLK fills `fl` with a conflicting lock (or F_UNLCK if none). Only used
 * when distributed_locks=1. */
static int swvfs_dist_lock(struct file *file, struct file_lock *fl,
			   bool is_flock, bool getlk, bool blocking)
{
	bool unlock = SWVFS_FL_IS_UNLOCK(fl);
	u32 type = unlock ? 3 : (SWVFS_FL_IS_READ(fl) ? 1 : 2);

	for (;;) {
		struct swvfs_request *r;
		char *buf, *path;
		int err;

		buf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		path = dentry_path_raw(file->f_path.dentry, buf, SWVFS_PATH_MAX);
		if (IS_ERR(path)) {
			kfree(buf);
			return PTR_ERR(path);
		}
		r = swvfs_make_req(SWVFS_OP_LOCK, path, strlen(path), NULL, 0, NULL, 0);
		kfree(buf);
		if (!r)
			return -ENOMEM;
		r->req.mode = getlk ? SWVFS_LOCK_GETLK :
			      unlock ? SWVFS_LOCK_UNLOCK : SWVFS_LOCK_TRY;
		r->req.uid = type;
		r->req.gid = SWVFS_FL_PID(fl);
		r->req.offset = fl->fl_start;
		r->req.size = fl->fl_end;
		r->req.mtime_sec = (s64)(unsigned long)SWVFS_FL_OWNER(fl);
		r->req.valid = is_flock ? SWVFS_LOCK_FLOCK : 0;
		err = swvfs_send(r);

		if (getlk) {
			if (err == 0 && r->reply.nentries) {
				/* Map the wire type (1 rd / 2 wr / 3 unlock) back to
				 * the kernel's F_RDLCK / F_WRLCK / F_UNLCK. */
				SWVFS_FL_TYPE(fl) = r->reply.attr.mode == 1 ? F_RDLCK :
						    r->reply.attr.mode == 2 ? F_WRLCK :
									      F_UNLCK;
				fl->fl_start = r->reply.attr.size;
				fl->fl_end = r->reply.attr.mtime_sec;
				SWVFS_FL_PID(fl) = r->reply.attr.uid;
			} else if (err == 0) {
				SWVFS_FL_TYPE(fl) = F_UNLCK;
			}
			swvfs_free_req(r);
			return err;
		}
		swvfs_free_req(r);

		if (unlock) {
			/* Mirror the release locally regardless of the RPC result. */
			locks_lock_file_wait(file, fl);
			return 0;
		}
		if (err == 0)
			return locks_lock_file_wait(file, fl); /* record locally */
		if (err == -EAGAIN && blocking) {
			if (msleep_interruptible(50))
				return -EINTR;
			continue;
		}
		return err; /* -EAGAIN (non-blocking) or a channel/RPC error */
	}
}

static int seaweedvfs_flock(struct file *file, int cmd, struct file_lock *fl)
{
	return swvfs_dist_lock(file, fl, true, false, SWVFS_FL_FLAGS(fl) & FL_SLEEP);
}

static int seaweedvfs_lock(struct file *file, int cmd, struct file_lock *fl)
{
	return swvfs_dist_lock(file, fl, false, cmd == F_GETLK, cmd == F_SETLKW);
}

static int seaweedvfs_xattr_get(const struct xattr_handler *handler,
				struct dentry *dentry, struct inode *inode,
				const char *name, void *value, size_t size)
{
	struct swvfs_request *r;
	char *buf, *path;
	int err;
	u32 n;

	buf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = dentry_path_raw(dentry, buf, SWVFS_PATH_MAX);
	if (IS_ERR(path)) {
		kfree(buf);
		return PTR_ERR(path);
	}
	r = swvfs_make_req(SWVFS_OP_GETXATTR, path, strlen(path), name,
			   strlen(name), NULL, 0);
	kfree(buf);
	if (!r)
		return -ENOMEM;
	r->data = kmalloc(XATTR_SIZE_MAX, GFP_KERNEL);
	if (!r->data) {
		swvfs_free_req(r);
		return -ENOMEM;
	}
	r->max_data = XATTR_SIZE_MAX;

	err = swvfs_send(r);
	if (err) {
		swvfs_free_req(r);
		return err;
	}
	n = r->reply.datalen;
	if (size == 0) {
		swvfs_free_req(r);
		return n;
	}
	if (n > size) {
		swvfs_free_req(r);
		return -ERANGE;
	}
	memcpy(value, r->data, n);
	swvfs_free_req(r);
	return n;
}

static int seaweedvfs_xattr_set(const struct xattr_handler *handler,
				SWVFS_IDMAP idmap, struct dentry *dentry,
				struct inode *inode, const char *name,
				const void *value, size_t size, int flags)
{
	struct swvfs_request *r;
	char *buf, *path;
	bool remove = (value == NULL);
	int err;

	buf = kmalloc(SWVFS_PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = dentry_path_raw(dentry, buf, SWVFS_PATH_MAX);
	if (IS_ERR(path)) {
		kfree(buf);
		return PTR_ERR(path);
	}
	r = swvfs_make_req(SWVFS_OP_SETXATTR, path, strlen(path), name,
			   strlen(name), remove ? NULL : value,
			   remove ? 0 : size);
	kfree(buf);
	if (!r)
		return -ENOMEM;
	r->req.mode = flags;
	r->req.valid = remove ? SWVFS_XATTR_REMOVE : 0;
	err = swvfs_send(r);
	swvfs_free_req(r);
	return err;
}

static ssize_t seaweedvfs_listxattr(struct dentry *dentry, char *buffer,
				    size_t size)
{
	struct swvfs_request *r;
	int err;
	u32 n;

	r = swvfs_req_from_dentry(SWVFS_OP_LISTXATTR, dentry);
	if (IS_ERR(r))
		return PTR_ERR(r);
	r->data = kmalloc(XATTR_LIST_MAX, GFP_KERNEL);
	if (!r->data) {
		swvfs_free_req(r);
		return -ENOMEM;
	}
	r->max_data = XATTR_LIST_MAX;

	err = swvfs_send(r);
	if (err) {
		swvfs_free_req(r);
		return err;
	}
	n = r->reply.datalen;
	if (size == 0) {
		swvfs_free_req(r);
		return n;
	}
	if (n > size) {
		swvfs_free_req(r);
		return -ERANGE;
	}
	memcpy(buffer, r->data, n);
	swvfs_free_req(r);
	return n;
}

static const struct xattr_handler seaweedvfs_xattr_handler = {
	.prefix = "", /* match every namespace; VFS enforces namespace policy */
	.get = seaweedvfs_xattr_get,
	.set = seaweedvfs_xattr_set,
};

static const struct xattr_handler *const seaweedvfs_xattr_handlers[] = {
	&seaweedvfs_xattr_handler,
	NULL,
};

static const struct inode_operations seaweedvfs_dir_inode_ops = {
	.lookup = seaweedvfs_lookup,
	.getattr = seaweedvfs_getattr,
	.listxattr = seaweedvfs_listxattr,
	.create = seaweedvfs_create,
	.atomic_open = seaweedvfs_atomic_open,
	.mkdir = seaweedvfs_mkdir,
	.mknod = seaweedvfs_mknod,
	.unlink = seaweedvfs_unlink,
	.rmdir = seaweedvfs_rmdir,
	.rename = seaweedvfs_rename,
	.symlink = seaweedvfs_symlink,
	.link = seaweedvfs_link,
	.setattr = seaweedvfs_setattr,
};

static const struct inode_operations seaweedvfs_symlink_inode_ops = {
	.get_link = seaweedvfs_get_link,
	.getattr = seaweedvfs_getattr,
	.listxattr = seaweedvfs_listxattr,
	.setattr = seaweedvfs_setattr,
};

static const struct file_operations seaweedvfs_dir_ops = {
	.read = generic_read_dir,
	.iterate_shared = seaweedvfs_readdir,
	.llseek = generic_file_llseek,
};

static const struct inode_operations seaweedvfs_file_inode_ops = {
	.getattr = seaweedvfs_getattr,
	.listxattr = seaweedvfs_listxattr,
	.setattr = seaweedvfs_setattr,
};

static const struct file_operations seaweedvfs_file_ops = {
	.read_iter = generic_file_read_iter,
	.write_iter = seaweedvfs_write_iter,
	.llseek = generic_file_llseek,
	.mmap = generic_file_readonly_mmap,
	.flush = seaweedvfs_flush,
	.fsync = seaweedvfs_fsync,
	.release = seaweedvfs_release_file,
};

/* Same as seaweedvfs_file_ops but with distributed flock; selected per-inode
 * when the module is loaded with distributed_locks=1. */
static const struct file_operations seaweedvfs_file_ops_dlm = {
	.read_iter = generic_file_read_iter,
	.write_iter = seaweedvfs_write_iter,
	.llseek = generic_file_llseek,
	.mmap = generic_file_readonly_mmap,
	.flush = seaweedvfs_flush,
	.fsync = seaweedvfs_fsync,
	.release = seaweedvfs_release_file,
	.flock = seaweedvfs_flock,
	.lock = seaweedvfs_lock,
};

static const struct address_space_operations seaweedvfs_aops = {
	.read_folio = seaweedvfs_read_folio,
	.readahead = seaweedvfs_readahead,
};

/* Filesystem-wide stats from the daemon (filer Statistics RPC). */
static int seaweedvfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct swvfs_request *r;
	struct swvfs_statfs st;
	int err;

	r = swvfs_make_req(SWVFS_OP_STATFS, "/", 1, NULL, 0, NULL, 0);
	if (!r)
		return -ENOMEM;
	r->data = kmalloc(sizeof(struct swvfs_statfs), GFP_KERNEL);
	if (!r->data) {
		swvfs_free_req(r);
		return -ENOMEM;
	}
	r->max_data = sizeof(struct swvfs_statfs);

	err = swvfs_send(r);
	if (err) {
		swvfs_free_req(r);
		return err;
	}
	if (r->reply.datalen < sizeof(struct swvfs_statfs)) {
		swvfs_free_req(r);
		return -EIO;
	}
	memcpy(&st, r->data, sizeof(st));
	swvfs_free_req(r);

	buf->f_type = SEAWEEDVFS_MAGIC;
	buf->f_bsize = st.bsize;
	buf->f_blocks = st.blocks;
	buf->f_bfree = st.bfree;
	buf->f_bavail = st.bavail;
	buf->f_files = st.files;
	buf->f_ffree = st.ffree;
	buf->f_namelen = st.namelen;
	return 0;
}

/* Always evict on last unref (no on-disk inode cache); same as the
 * generic_delete_inode helper, which 7.0 removed. */
static int seaweedvfs_drop_inode(struct inode *inode)
{
	return 1;
}

static struct inode *swvfs_alloc_inode(struct super_block *sb)
{
	struct swvfs_inode *si =
		alloc_inode_sb(sb, swvfs_inode_cachep, GFP_KERNEL);

	if (!si)
		return NULL;
	atomic_set(&si->cache_gen, 0);
	return &si->vfs_inode;
}

/* RCU-deferred by the VFS; just return the object to its slab. */
static void swvfs_free_inode(struct inode *inode)
{
	kmem_cache_free(swvfs_inode_cachep, SWVFS_I(inode));
}

/* Slab constructor: init only the embedded VFS inode (runs once per object, and
 * must survive reuse); cache_gen is (re)set per allocation in swvfs_alloc_inode. */
static void swvfs_inode_init_once(void *p)
{
	inode_init_once(&((struct swvfs_inode *)p)->vfs_inode);
}

static const struct super_operations seaweedvfs_super_ops = {
	.alloc_inode = swvfs_alloc_inode,
	.free_inode = swvfs_free_inode,
	.statfs = seaweedvfs_statfs,
	.drop_inode = seaweedvfs_drop_inode,
};

static struct inode *swvfs_make_root(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);

	if (!inode)
		return NULL;
	inode->i_ino = SEAWEEDVFS_ROOT_INO;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	SWVFS_INODE_INIT_TS(inode);
	inode->i_op = &seaweedvfs_dir_inode_ops;
	inode->i_fop = &seaweedvfs_dir_ops;
	set_nlink(inode, 2);
	/* Hash the root like every other inode so a daemon-pushed invalidation for a
	 * root-level namespace change (ino == SEAWEEDVFS_ROOT_INO) can ilookup it;
	 * new_inode() alone leaves it unhashed, so ilookup would miss it and a remote
	 * create/delete/rename directly under "/" would never reach the cache. */
	insert_inode_hash(inode);
	return inode;
}

static int seaweedvfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct swvfs_mount *m;
	struct inode *root;
	int err;

	sb->s_magic = SEAWEEDVFS_MAGIC;
	sb->s_op = &seaweedvfs_super_ops;
	SWVFS_SET_DEFAULT_D_OP(sb, &seaweedvfs_dentry_ops); /* keys on parent gen */
	/* s_xattr lost an inner const across versions; cast to its actual type. */
	sb->s_xattr = (typeof(sb->s_xattr))seaweedvfs_xattr_handlers;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_flags |= SB_NOSEC; /* allow S_NOSEC caching (see swvfs_apply_attr) */

	/* get_tree_nodev leaves s_bdi as the noop bdi (ra_pages = 0), which disables
	 * read-ahead entirely — cold reads would then fault one folio at a time,
	 * one daemon upcall + one tiny range read per 4 KiB. Set up a real bdi so
	 * the page cache batches reads into our SWVFS_READAHEAD_MAX upcalls. */
	err = super_setup_bdi(sb);
	if (err)
		return err;
	sb->s_bdi->ra_pages = SWVFS_RA_PAGES;
	sb->s_bdi->io_pages = SWVFS_RA_PAGES;

	root = swvfs_make_root(sb);
	if (!root)
		return -ENOMEM;
	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->sb = sb;
	sb->s_fs_info = m;
	down_write(&swvfs_sb_sem);
	list_add(&m->node, &swvfs_mounts);
	up_write(&swvfs_sb_sem);
	pr_info("seaweedvfs: mounted\n");
	return 0;
}

/* fs_context mount path (the legacy ->mount/mount_nodev hook was removed in
 * 7.0). We parse no options, so the context just wires get_tree_nodev. */
static int seaweedvfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, seaweedvfs_fill_super);
}

static const struct fs_context_operations seaweedvfs_context_ops = {
	.get_tree = seaweedvfs_get_tree,
};

static int seaweedvfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &seaweedvfs_context_ops;
	return 0;
}

static void seaweedvfs_kill_sb(struct super_block *sb)
{
	struct swvfs_mount *m = sb->s_fs_info;

	/* Unlink under the write lock: it blocks until in-flight invalidations
	 * (sem readers) finish, so none still references this sb when
	 * kill_anon_super frees it below. */
	down_write(&swvfs_sb_sem);
	if (m)
		list_del(&m->node);
	up_write(&swvfs_sb_sem);
	kfree(m);
	sb->s_fs_info = NULL;
	pr_info("seaweedvfs: unmounted\n");
	kill_anon_super(sb);
}

static struct file_system_type seaweedvfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "seaweedvfs",
	.init_fs_context = seaweedvfs_init_fs_context,
	.kill_sb = seaweedvfs_kill_sb,
	.fs_flags = 0,
};

static int __init seaweedvfs_init(void)
{
	int err;

	swvfs_inode_cachep = kmem_cache_create(
		"seaweedvfs_inode", sizeof(struct swvfs_inode), 0,
		SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT, swvfs_inode_init_once);
	if (!swvfs_inode_cachep) {
		pr_err("seaweedvfs: inode cache create failed\n");
		return -ENOMEM;
	}

	/* Unbound so read-ahead fetches run concurrently (matching the daemon). */
	swvfs_ra_wq = alloc_workqueue("swvfs_ra", WQ_UNBOUND, 0);
	if (!swvfs_ra_wq) {
		pr_err("seaweedvfs: alloc_workqueue failed\n");
		kmem_cache_destroy(swvfs_inode_cachep);
		return -ENOMEM;
	}
	err = misc_register(&swvfs_miscdev);
	if (err) {
		pr_err("seaweedvfs: misc_register failed: %d\n", err);
		destroy_workqueue(swvfs_ra_wq);
		kmem_cache_destroy(swvfs_inode_cachep);
		return err;
	}
	err = register_filesystem(&seaweedvfs_fs_type);
	if (err) {
		pr_err("seaweedvfs: register_filesystem failed: %d\n", err);
		misc_deregister(&swvfs_miscdev);
		destroy_workqueue(swvfs_ra_wq);
		kmem_cache_destroy(swvfs_inode_cachep);
		return err;
	}
	pr_info("seaweedvfs: loaded (v%s); /dev/seaweedvfs ready\n",
		SEAWEEDVFS_VERSION);
	return 0;
}

static void __exit seaweedvfs_exit(void)
{
	unregister_filesystem(&seaweedvfs_fs_type);
	misc_deregister(&swvfs_miscdev);
	destroy_workqueue(swvfs_ra_wq); /* drains any in-flight read-ahead */
	/* free_inode returns inodes to the slab via RCU; wait for those callbacks
	 * before destroying the cache they free into. */
	rcu_barrier();
	kmem_cache_destroy(swvfs_inode_cachep);
	pr_info("seaweedvfs: unloaded\n");
}

module_init(seaweedvfs_init);
module_exit(seaweedvfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SeaweedFS");
MODULE_DESCRIPTION("SeaweedFS kernel VFS client");
MODULE_VERSION(SEAWEEDVFS_VERSION);

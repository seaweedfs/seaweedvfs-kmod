/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wire protocol for the seaweedvfs kernel <-> userspace daemon channel
 * (the /dev/seaweedvfs character device).
 *
 * Path-based / stateless: every request carries the FS-relative path(s) of its
 * target (the kernel reconstructs them from dentries), so the daemon keeps no
 * inode map and a daemon restart is transparent. Inode numbers are a stable
 * hash of the path (computed by the daemon, returned in replies).
 *
 * A request is a fixed header followed by a variable payload:
 *     path1[plen1] path2[plen2] data[dlen]
 * (path2 only for RENAME; data only for WRITE.) A reply is a fixed header
 * followed, for READDIR, by nentries*swvfs_dirent, or for READ by datalen bytes.
 *
 * Structs use fixed-width fields with manual padding so the Rust daemon mirrors
 * the layout with #[repr(C)].
 */
#ifndef SWVFS_PROTO_H
#define SWVFS_PROTO_H

#ifdef __KERNEL__
#include <linux/types.h>
#endif

#define SWVFS_OP_LOOKUP 1
#define SWVFS_OP_READDIR 2
#define SWVFS_OP_READ 3
#define SWVFS_OP_CREATE 4
#define SWVFS_OP_MKDIR 5
#define SWVFS_OP_UNLINK 6
#define SWVFS_OP_RMDIR 7
#define SWVFS_OP_SETATTR 8
#define SWVFS_OP_WRITE 9
#define SWVFS_OP_FLUSH 10
#define SWVFS_OP_RELEASE 11
#define SWVFS_OP_RENAME 12
#define SWVFS_OP_GETATTR 13
#define SWVFS_OP_SYMLINK 14 /* path1=link path, path2=target */
#define SWVFS_OP_READLINK 15 /* path1=link path; target returned as reply data */
#define SWVFS_OP_GETXATTR 16 /* path1=file, path2=name; value -> reply data */
#define SWVFS_OP_SETXATTR 17 /* path1=file, path2=name, data=value; mode=flags */
#define SWVFS_OP_LISTXATTR 18 /* path1=file; NUL-separated names -> reply data */
#define SWVFS_OP_LINK 19 /* path1=existing target, path2=new link path */
#define SWVFS_OP_MKNOD 20 /* path1=node; mode=full st_mode; size=encoded rdev */
#define SWVFS_OP_STATFS 21 /* path1="/"; swvfs_statfs returned as reply data */
#define SWVFS_OP_LOCK 22 /* path1=file; advisory lock via the filer (distributed).
			  * mode=op (0 TRY_LOCK, 1 UNLOCK), uid=type (1 read, 2 write,
			  * 3 unlock), gid=holder pid, offset=range start, size=range
			  * end (inclusive; ~0 = EOF), mtime_sec=owner id, valid bit
			  * SWVFS_LOCK_FLOCK set for flock. reply.error: 0 granted/ok,
			  * -EAGAIN on conflict. */

#define SWVFS_XATTR_REMOVE 1 /* req.valid bit: removexattr (value absent) */
#define SWVFS_CREATE_EXCL 1 /* req.valid bit on CREATE: fail (EEXIST) if present */
#define SWVFS_LOCK_FLOCK 1 /* req.valid bit on LOCK: flock-style (vs fcntl) */
#define SWVFS_LOCK_TRY 0 /* req.mode on LOCK: try to acquire (non-blocking) */
#define SWVFS_LOCK_UNLOCK 1 /* req.mode on LOCK: release */
#define SWVFS_LOCK_GETLK 2 /* req.mode on LOCK: report a conflict, if any.
			    * reply: nentries=1 + attr{mode=type(1rd/2wr/3unlock),
			    * size=start, mtime_sec=end, uid=pid} if a conflict
			    * exists, else nentries=0. */

/* SETATTR field mask (req.valid) */
#define SWVFS_SET_MODE (1u << 0)
#define SWVFS_SET_UID (1u << 1)
#define SWVFS_SET_GID (1u << 2)
#define SWVFS_SET_SIZE (1u << 3)
#define SWVFS_SET_MTIME (1u << 4)
#define SWVFS_SET_ATIME (1u << 5)

/* Big enough to hold the FS-relative path the kernel reconstructs from a
 * dentry. This must exceed POSIX PATH_MAX (4096): a syscall path argument is
 * itself capped at PATH_MAX *relative to cwd*, but our reconstructed absolute
 * (in-mount) path is cwd-depth + that argument, so it can approach 2*PATH_MAX.
 * The +1-over-PATH_MAX case is still rejected by the VFS getname() before it
 * reaches us, so this only needs to be large enough not to false-fail. */
#define SWVFS_PATH_MAX 8192
#define SWVFS_NAME_MAX 255
#define SWVFS_NAME_BUF 256
#define SWVFS_MAX_DIRENTS 32
#define SWVFS_MAX_WRITE (1u << 20)

/*
 * Optional io_uring_cmd transport (a ublk-style ring). The daemon drives the
 * channel with IORING_OP_URING_CMD SQEs (IORING_SETUP_SQE128) instead of
 * read()/write() syscalls; the read()/write() fops remain as a fallback and the
 * transport is latched per open(). See kernel/IOURING_RING.md.
 *
 * cmd_op values (the io_uring_cmd cmd_op field):
 *   FETCH            - park to receive one request into buf_addr.
 *   COMMIT_AND_FETCH - ingest the reply in buf_addr, then re-park for the next.
 *
 * The inline SQE cmd[] payload is struct swvfs_uring_cmd (24 B; fits the 80 B
 * SQE128 cmd area). One slot buffer per slot index holds the request (kernel
 * writes it) and later the reply (kernel reads it); it must be >= SWVFS_RING_BUF
 * bytes so it holds the largest request or reply.
 *
 * CQE result (io_uring_cmd_done ret): > 0 a request of that many bytes was
 * delivered into buf_addr; -ENODEV the channel is shutting down (exit); other
 * < 0 the fetch failed, re-submit FETCH for the slot.
 */
#define SWVFS_URING_FETCH 1
#define SWVFS_URING_COMMIT_AND_FETCH 2
#define SWVFS_RING_QD 256 /* slots = max concurrent in-flight upcalls */

/* Per-slot buffer floor: holds the largest request (88 B header + two paths +
 * a full WRITE payload) or the largest reply (96 B header + 1 MiB READ data). */
#define SWVFS_RING_BUF \
	(88u + 2u * SWVFS_PATH_MAX + SWVFS_MAX_WRITE)

struct swvfs_uring_cmd {
	__u64 buf_addr; /* slot buffer; request written here, reply read from here */
	__u32 buf_len; /* must be >= SWVFS_RING_BUF */
	__u32 slot; /* 0..SWVFS_RING_QD-1, daemon-owned slot index */
	__u32 reply_len; /* COMMIT: total reply bytes in buf_addr (96 + data) */
	__u32 _pad;
}; /* 24 bytes */

struct swvfs_attr {
	__u64 ino;
	__u64 size;
	__s64 mtime_sec;
	__s64 ctime_sec;
	__s64 atime_sec;
	__u32 mode; /* Linux st_mode (type | perm) */
	__u32 uid;
	__u32 gid;
	__u32 nlink;
	__u32 rdev;
	__u32 mtime_nsec;
	__u32 ctime_nsec;
	__u32 atime_nsec;
}; /* 72 bytes */

struct swvfs_dirent {
	struct swvfs_attr attr; /* full attrs so readdir can prime the dcache */
	__u32 type; /* DT_* */
	__u32 namelen;
	char name[SWVFS_NAME_BUF];
}; /* 336 bytes */

struct swvfs_req {
	__u64 tag;
	__u64 offset; /* READDIR cookie / READ|WRITE byte offset */
	__u64 size; /* READ count / SETATTR new size */
	__s64 mtime_sec; /* SETATTR */
	__s64 atime_sec; /* SETATTR */
	__u32 op;
	__u32 plen1; /* bytes of path1 after the header (the target/old path) */
	__u32 plen2; /* bytes of path2 (RENAME new path), else 0 */
	__u32 dlen; /* bytes of WRITE data, else 0 */
	__u32 valid; /* SETATTR field mask (SWVFS_SET_*) */
	__u32 mode; /* CREATE/MKDIR/SETATTR mode */
	__u32 uid; /* CREATE/MKDIR/SETATTR */
	__u32 gid; /* CREATE/MKDIR/SETATTR */
	__u32 mtime_nsec; /* SETATTR */
	__u32 atime_nsec; /* SETATTR */
	__u32 _pad0;
	__u32 _pad1;
	/* followed by: path1[plen1], path2[plen2], data[dlen] */
}; /* 88 bytes header */

struct swvfs_statfs {
	__u64 blocks; /* f_blocks (in bsize units) */
	__u64 bfree; /* f_bfree */
	__u64 bavail; /* f_bavail */
	__u64 files; /* f_files */
	__u64 ffree; /* f_ffree */
	__u32 bsize; /* f_bsize */
	__u32 namelen; /* f_namelen */
}; /* 48 bytes; STATFS returns this as the reply data payload */

struct swvfs_reply {
	__u64 tag;
	struct swvfs_attr attr; /* LOOKUP/GETATTR result */
	__s32 error; /* 0 ok, else -errno */
	__u32 nentries; /* READDIR: entries that follow this header */
	__u32 eof; /* READDIR: 1 if this batch reaches end of dir */
	__u32 datalen; /* READ: data bytes that follow this header */
}; /* 96 bytes */

#endif /* SWVFS_PROTO_H */

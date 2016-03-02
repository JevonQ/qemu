/*
 * 9p cephfs callback
 *
 * Copyright UnitedStack, Corp. 2016
 *
 * Authors:
 *    Jevon Qiao <scaleqiao@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "9p.h"
#include "9p-xattr.h"
#include "trace.h"
#include <cephfs/libcephfs.h>
#include "fsdev/qemu-fsdev.h"   /* cephfs_ops */
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "qemu/xattr.h"
#include "qemu/error-report.h"
#include <libgen.h>
#include <unistd.h>
#include <linux/fs.h>
#ifdef CONFIG_LINUX_MAGIC_H
#include <linux/magic.h>
#endif
#include <sys/ioctl.h>

#define CEPH_VER_LEN        32
#define MON_NAME_LEN        32
#define MON_SECRET_LEN      64

#ifndef LIBCEPHFS_VERSION
#define LIBCEPHFS_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)
#define LIBCEPHFS_VERSION_CODE LIBCEPHFS_VERSION(0, 0, 0)
#endif

#if defined(LIBCEPHFS_VERSION) && LIBCEPHFS_VERSION_CODE >= \
LIBCEPHFS_VERSION(10, 0, 2)
#define HAVE_CEPH_READV 1
#endif

struct cephfs_data {
    int major, minor, patch;
    char ceph_version[CEPH_VER_LEN];
    struct  ceph_mount_info *cmount;
};

static int cephfs_update_file_cred(struct ceph_mount_info *cmount,
                                   const char *name, FsCred *credp)
{
    int fd, ret;
    fd = ceph_open(cmount, name, O_NONBLOCK | O_NOFOLLOW, credp->fc_mode);
    if (fd < 0) {
        return fd;
    }
    ret = ceph_fchown(cmount, fd, credp->fc_uid, credp->fc_gid);
    if (ret < 0) {
        goto err_out;
    }
    ret = ceph_fchmod(cmount, fd, credp->fc_mode & 07777);
err_out:
    close(fd);
    return ret;
}

static int cephfs_lstat(FsContext *fs_ctx, V9fsPath *fs_path,
                        struct stat *stbuf)
{
    int ret;
    char *path = fs_path->data;
    struct cephfs_data *cfsdata = fs_ctx->private;

    ret = ceph_lstat(cfsdata->cmount, path, stbuf);
    trace_cephfs_lstat_return(path, stbuf->st_mode, stbuf->st_uid,
                              stbuf->st_gid, stbuf->st_size, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static ssize_t cephfs_readlink(FsContext *fs_ctx, V9fsPath *fs_path,
                               char *buf, size_t bufsz)
{
    int ret;
    char *path = fs_path->data;
    struct cephfs_data *cfsdata = fs_ctx->private;

    ret = ceph_readlink(cfsdata->cmount, path, buf, bufsz);
    trace_cephfs_readlink_return(path, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_close(FsContext *ctx, V9fsFidOpenState *fs)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_close(cfsdata->cmount, fs->fd);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static int cephfs_closedir(FsContext *ctx, V9fsFidOpenState *fs)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_closedir(cfsdata->cmount, (struct ceph_dir_result *)fs->dir);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static int cephfs_open(FsContext *ctx, V9fsPath *fs_path,
                       int flags, V9fsFidOpenState *fs)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_open(cfsdata->cmount, fs_path->data, flags, 0777);
    trace_cephfs_open_return(fs_path->data, flags, 0777, fs->fd);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    fs->fd = ret;
    return ret;
}

static int cephfs_opendir(FsContext *ctx,
                          V9fsPath *fs_path, V9fsFidOpenState *fs)
{
    int ret;
    struct ceph_dir_result *result;
    struct cephfs_data *cfsdata = ctx->private;
    char *path = fs_path->data;

    ret = ceph_opendir(cfsdata->cmount, path, &result);
    trace_cephfs_opendir_return(path, ret);
    if (ret < 0) {
        errno = -ret;
        error_report("failed to open %s, %s", path, strerror(errno));
        return -1;
    }
    fs->dir = (DIR *)result;
    return 0;
}

static void cephfs_rewinddir(FsContext *ctx, V9fsFidOpenState *fs)
{
    struct cephfs_data *cfsdata = ctx->private;

    trace_cephfs_rewinddir(fs->dir);
    ceph_rewinddir(cfsdata->cmount, (struct ceph_dir_result *)fs->dir);
}

static off_t cephfs_telldir(FsContext *ctx, V9fsFidOpenState *fs)
{
    off_t ret;
    struct cephfs_data *cfsdata = ctx->private;

    trace_cephfs_telldir(fs->dir);
    ret = ceph_telldir(cfsdata->cmount, (struct ceph_dir_result *)fs->dir);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_readdir_r(FsContext *ctx, V9fsFidOpenState *fs,
                            struct dirent *entry,
                            struct dirent **result)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_readdir_r(cfsdata->cmount, (struct ceph_dir_result *)fs->dir,
                         entry);
    if (ret > 0) {
        *result = entry;
        return 0;
    } else if (ret == 0) {
        *result = NULL;
        return 0;
    }
    errno = -ret;
    return -ret;
}

static void cephfs_seekdir(FsContext *ctx, V9fsFidOpenState *fs, off_t off)
{
    struct cephfs_data *cfsdata = ctx->private;

    trace_cephfs_seekdir(fs->dir, off);
    ceph_seekdir(cfsdata->cmount, (struct ceph_dir_result *)fs->dir, off);
}

#ifndef HAVE_CEPH_READV
static ssize_t ceph_preadv(struct ceph_mount_info *cmount, int fd,
                           const struct iovec *iov, int iov_cnt,
                           off_t offset)
{
    ssize_t ret;
    size_t i;
    size_t len, tmp;
    void *buf;
    size_t bufoffset = 0;

    len = iov_size(iov, iov_cnt);
    buf = g_new0(uint8_t, len);
    ret = ceph_read(cmount, fd, buf, len, offset);
    if (ret < 0) {
        return ret;
    } else {
        tmp = ret;
        for (i = 0; (i < iov_cnt && tmp > 0); i++) {
            if (tmp < iov[i].iov_len) {
                memcpy(iov[i].iov_base, (buf + bufoffset), tmp);
            } else {
                memcpy(iov[i].iov_base, (buf + bufoffset), iov[i].iov_len);
                bufoffset += iov[i].iov_len;
            }
            tmp -= iov[i].iov_len;
        }
    }

    free(buf);
    return ret;
}

static ssize_t ceph_pwritev(struct ceph_mount_info *cmount, int fd,
                            const struct iovec *iov, int iov_cnt,
                            off_t offset)
{
    ssize_t ret;
    size_t i;
    size_t len;
    void *buf;
    size_t bufoffset = 0;

    len = iov_size(iov, iov_cnt);
    buf = g_new0(uint8_t, len);
    for (i = 0; i < iov_cnt; i++) {
        memcpy((buf + bufoffset), iov[i].iov_base, iov[i].iov_len);
        bufoffset += iov[i].iov_len;
    }
    ret = ceph_write(cmount, fd, buf, len, offset);

    free(buf);
    return ret;
}
#endif

static ssize_t cephfs_preadv(FsContext *ctx, V9fsFidOpenState *fs,
                             const struct iovec *iov,
                             int iovcnt, off_t offset)
{
    ssize_t ret = 0;
    struct cephfs_data *cfsdata = ctx->private;

    trace_cephfs_preadv(iovcnt, iov_size(iov, iovcnt));
    if (iovcnt < 0) {
        errno = EINVAL;
        return -1;
    }
    ret = ceph_preadv(cfsdata->cmount, fs->fd, iov, iovcnt, offset);
    trace_cephfs_preadv_return(iovcnt, iov_size(iov, iovcnt), ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static ssize_t cephfs_pwritev(FsContext *ctx, V9fsFidOpenState *fs,
                              const struct iovec *iov,
                              int iovcnt, off_t offset)
{
    ssize_t ret = 0;
    struct cephfs_data *cfsdata = ctx->private;

    trace_cephfs_pwritev(iovcnt, iov_size(iov, iovcnt), offset);
    if (iovcnt < 0) {
        errno = EINVAL;
        return -1;
    }
    ret = ceph_pwritev(cfsdata->cmount, fs->fd, iov, iovcnt, offset);
    trace_cephfs_pwritev_return(iovcnt, iov_size(iov, iovcnt), offset, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

#ifdef CONFIG_SYNC_FILE_RANGE
    if (ret > 0 && ctx->export_flags & V9FS_IMMEDIATE_WRITEOUT) {
        /*
         * Initiate a writeback. This is not a data integrity sync.
         * We want to ensure that we don't leave dirty pages in the cache
         * after write when writeout=immediate is sepcified.
         */
        sync_file_range(fs->fd, offset, ret,
                        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE);
    }
#endif
    return ret;
}

static int cephfs_chmod(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    int  ret;
    struct cephfs_data *cfsdata = fs_ctx->private;

    ret = ceph_chmod(cfsdata->cmount, fs_path->data, credp->fc_mode);
    trace_cephfs_chmod_return(fs_path->data, credp->fc_mode, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_mknod(FsContext *fs_ctx, V9fsPath *dir_path,
                        const char *name, FsCred *credp)
{
    int ret;
    V9fsString fullname;
    struct cephfs_data *cfsdata = fs_ctx->private;

    v9fs_string_init(&fullname);
    v9fs_string_sprintf(&fullname, "%s/%s", dir_path->data, name);
    ret = ceph_mknod(cfsdata->cmount, fullname.data, credp->fc_mode,
                     credp->fc_rdev);
    trace_cephfs_mknod_return(fullname.data, credp->fc_mode,
                              credp->fc_rdev, ret);
    v9fs_string_free(&fullname);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_mkdir(FsContext *fs_ctx, V9fsPath *dir_path,
                       const char *name, FsCred *credp)
{
    int ret;
    V9fsString fullname;
    struct cephfs_data *cfsdata = fs_ctx->private;

    v9fs_string_init(&fullname);
    v9fs_string_sprintf(&fullname, "%s/%s", dir_path->data, name);
    ret = ceph_mkdir(cfsdata->cmount, fullname.data, credp->fc_mode);
    trace_cephfs_mkdir_return(fullname.data, credp->fc_mode, ret);
    v9fs_string_free(&fullname);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_fstat(FsContext *fs_ctx, int fid_type,
                        V9fsFidOpenState *fs, struct stat *stbuf)
{
    int fd;
    int ret;
    struct cephfs_data *cfsdata = fs_ctx->private;

    if (fid_type == P9_FID_DIR) {
        fd = dirfd(fs->dir);
    } else {
        fd = fs->fd;
    }
    ret = ceph_fstat(cfsdata->cmount, fd, stbuf);
    trace_cephfs_fstat_return(fid_type, fd, stbuf->st_uid, stbuf->st_gid,
                              stbuf->st_size, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_open2(FsContext *fs_ctx, V9fsPath *dir_path, const char *name,
                        int flags, FsCred *credp, V9fsFidOpenState *fs)
{
    int fd, ret;
    V9fsString fullname;
    struct cephfs_data *cfsdata = fs_ctx->private;

    v9fs_string_init(&fullname);
    v9fs_string_sprintf(&fullname, "%s/%s", dir_path->data, name);
    fd = ceph_open(cfsdata->cmount, fullname.data, flags, credp->fc_mode);
    trace_cephfs_open2_return(fullname.data, flags, credp->fc_mode);
    v9fs_string_free(&fullname);
    if (fd >= 0) {
        /* After creating the file, need to set the cred */
        ret = cephfs_update_file_cred(cfsdata->cmount, name, credp);
        if (ret < 0) {
            ceph_close(cfsdata->cmount, fd);
            errno = -ret;
            fd = -1;
        } else {
            fs->fd = fd;
        }
    } else {
       errno = -fd;
       return -1;
    }

    return fd;
}

static int cephfs_symlink(FsContext *fs_ctx, const char *oldpath,
                          V9fsPath *dir_path, const char *name, FsCred *credp)
{
    int ret;
    V9fsString fullname;
    struct cephfs_data *cfsdata = fs_ctx->private;

    v9fs_string_init(&fullname);
    v9fs_string_sprintf(&fullname, "%s/%s", dir_path->data, name);
    ret = ceph_symlink(cfsdata->cmount, oldpath, fullname.data);
    trace_cephfs_symlink_return(oldpath, fullname.data, ret);
    v9fs_string_free(&fullname);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_link(FsContext *ctx, V9fsPath *oldpath,
                       V9fsPath *dirpath, const char *name)
{
    int ret;
    V9fsString newpath;
    struct cephfs_data *cfsdata = ctx->private;

    v9fs_string_init(&newpath);
    v9fs_string_sprintf(&newpath, "%s/%s", dirpath->data, name);
    ret = ceph_link(cfsdata->cmount, oldpath->data, newpath.data);
    trace_cephfs_link_return(oldpath->data, newpath.data, ret);
    v9fs_string_free(&newpath);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_truncate(FsContext *ctx, V9fsPath *fs_path, off_t size)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_truncate(cfsdata->cmount, fs_path->data, size);
    trace_cephfs_truncate_return(fs_path->data, size, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_rename(FsContext *ctx, const char *oldpath,
                         const char *newpath)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_rename(cfsdata->cmount, oldpath, newpath);
    trace_cephfs_rename_return(oldpath, newpath, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_chown(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    int ret;
    struct cephfs_data *cfsdata = fs_ctx->private;

    ret = ceph_chown(cfsdata->cmount, fs_path->data, credp->fc_uid,
                     credp->fc_gid);
    trace_cephfs_chown_return(fs_path->data, credp->fc_uid, credp->fc_gid, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_utimensat(FsContext *ctx, V9fsPath *fs_path,
                            const struct timespec *buf)
{
    int ret;

#ifdef CONFIG_UTIMENSAT
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_utime(cfsdata->cmount, fs_path->data, (struct utimbuf *)buf);
    trace_cephfs_utimensat_return(fs_path->data, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
#else
    ret = -1;
    errno = ENOSYS;
#endif

    return ret;
}

static int cephfs_remove(FsContext *ctx, const char *path)
{
    errno = EOPNOTSUPP;
    return -1;
}

static int cephfs_fsync(FsContext *ctx, int fid_type,
                        V9fsFidOpenState *fs, int datasync)
{
    int ret, fd;
    struct cephfs_data *cfsdata = ctx->private;

    if (fid_type == P9_FID_DIR) {
        fd = dirfd(fs->dir);
    } else {
        fd = fs->fd;
    }
    ret = ceph_fsync(cfsdata->cmount, fd, datasync);
    trace_cephfs_fsync_return(fd, datasync, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_statfs(FsContext *ctx, V9fsPath *fs_path,
                         struct statfs *stbuf)
{
    int ret;
    char *path = fs_path->data;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_statfs(cfsdata->cmount, path, (struct statvfs *)stbuf);
    if (ret < 0) {
        error_report("cephfs_statfs failed for %s, %s", path, strerror(errno));
        errno = -ret;
        return -1;
    }
    return ret;
}

/*
 * Get the extended attribute of normal file, if the path refer to a symbolic
 * link, just return the extended attributes of the syslink rather than the
 * attributes of the link itself.
 */
static ssize_t cephfs_lgetxattr(FsContext *ctx, V9fsPath *fs_path,
                                const char *name, void *value, size_t size)
{
    int ret;
    char *path = fs_path->data;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_lgetxattr(cfsdata->cmount, path, name, value, size);
    trace_cephfs_lgetxattr_return(path, name, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static ssize_t cephfs_llistxattr(FsContext *ctx, V9fsPath *fs_path,
                                 void *value, size_t size)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_llistxattr(cfsdata->cmount, fs_path->data, value, size);
    trace_cephfs_llistxattr_return(fs_path->data, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_lsetxattr(FsContext *ctx, V9fsPath *fs_path, const char *name,
                            void *value, size_t size, int flags)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_lsetxattr(cfsdata->cmount, fs_path->data, name, value, size,
                         flags);
    trace_cephfs_lsetxattr_return(fs_path->data, name, flags, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_lremovexattr(FsContext *ctx, V9fsPath *fs_path,
                               const char *name)
{
    int ret;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_lremovexattr(cfsdata->cmount, fs_path->data, name);
    trace_cephfs_lremovexattr_return(fs_path->data, name, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_name_to_path(FsContext *ctx, V9fsPath *dir_path,
                              const char *name, V9fsPath *target)
{
    if (dir_path) {
        v9fs_string_sprintf((V9fsString *)target, "%s/%s",
                            dir_path->data, name);
    } else {
        /* if the path does not start from '/' */
        v9fs_string_sprintf((V9fsString *)target, "%s", name);
    }

    /* Bump the size for including terminating NULL */
    target->size++;
    return 0;
}

static int cephfs_renameat(FsContext *ctx, V9fsPath *olddir,
                           const char *old_name, V9fsPath *newdir,
                           const char *new_name)
{
    int ret = -1;
    struct cephfs_data *cfsdata = ctx->private;

    ret = ceph_rename(cfsdata->cmount, old_name, new_name);
    trace_cephfs_renameat_return(old_name, new_name, ret);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int cephfs_unlinkat(FsContext *ctx, V9fsPath *dir,
                           const char *name, int flags)
{
    int ret = 0;
    char *path = dir->data;
    struct stat fstat;
    V9fsString fullname;
    struct cephfs_data *cfsdata = ctx->private;

    v9fs_string_init(&fullname);
    v9fs_string_sprintf(&fullname, "%s/%s", dir->data, name);
    path = fullname.data;
    /* determine which kind of file is being destroyed */
    ret = ceph_lstat(cfsdata->cmount, path, &fstat);
    if (!ret) {
        switch (fstat.st_mode & S_IFMT) {
        case S_IFDIR:
            ret = ceph_rmdir(cfsdata->cmount, path);
            break;

        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
        case S_IFLNK:
        case S_IFREG:
        case S_IFSOCK:
            ret = ceph_unlink(cfsdata->cmount, path);
            break;

        default:
            error_report("ceph_lstat unknown stmode %s, %s", path,
                         strerror(errno));
            break;
        }
        if (ret < 0) {
            errno = -ret;
            ret = -1;
        }
    } else {
        errno = -ret;
        ret = -1;
    }
    trace_cephfs_unlinkat_return(path, fstat.st_mode, ret);

    v9fs_string_free(&fullname);
    return ret;
}

/*
 * Do two things in the init function:
 * 1) Create a mount handle used by all cephfs interfaces.
 * 2) Invoke ceph_mount() to initialize a link between the client and
 * ceph monitor
 */
static int cephfs_init(FsContext *ctx)
{
    int ret;
    const char *ver = NULL;
    struct cephfs_data *data = g_malloc(sizeof(struct cephfs_data));

    if (data == NULL) {
        errno = ENOMEM;
        return -1;
    }
    trace_cephfs_init(ctx->fs_root);
    memset(data, 0, sizeof(struct cephfs_data));
    ret = ceph_create(&data->cmount, NULL);
    if (ret < 0) {
        errno = -ret;
        error_report("ceph_create failed %s", strerror(errno));
        goto err_out;
    }

    ret = ceph_conf_read_file(data->cmount, NULL);
    if (ret) {
        errno = -ret;
        error_report("ceph_conf_read_file failed %s", strerror(errno));
        goto err_out;
    }

    ret = ceph_mount(data->cmount, ctx->fs_root);
    if (ret) {
        errno = -ret;
        error_report("ceph_mount failed %s", strerror(errno));
        goto err_out;
    } else {
        ctx->private = data;
        /* CephFS does not support FS_IOC_GETVERSION */
        ctx->exops.get_st_gen = NULL;
        goto out;
    }

    ver = ceph_version(&data->major, &data->minor, &data->patch);
    memcpy(data->ceph_version, ver, strlen(ver) + 1);

err_out:
    g_free(data);
out:
    return ret;
}

static int cephfs_parse_opts(QemuOpts *opts, struct FsDriverEntry *fse)
{
    const char *sec_model = qemu_opt_get(opts, "security_model");
    const char *path = qemu_opt_get(opts, "path");

    if (!sec_model) {
        error_report("Invalid argument security_model specified "
                     "with cephfs fsdriver");
        return -1;
    }

    if (!path) {
        error_report("fsdev: No path specified.");
        return -1;
    }

    fse->path = g_strdup(path);
    return 0;
}

FileOperations cephfs_ops = {
    .parse_opts   = cephfs_parse_opts,
    .init         = cephfs_init,
    .lstat        = cephfs_lstat,
    .readlink     = cephfs_readlink,
    .close        = cephfs_close,
    .closedir     = cephfs_closedir,
    .open         = cephfs_open,
    .opendir      = cephfs_opendir,
    .rewinddir    = cephfs_rewinddir,
    .telldir      = cephfs_telldir,
    .readdir_r    = cephfs_readdir_r,
    .seekdir      = cephfs_seekdir,
    .preadv       = cephfs_preadv,
    .pwritev      = cephfs_pwritev,
    .chmod        = cephfs_chmod,
    .mknod        = cephfs_mknod,
    .mkdir        = cephfs_mkdir,
    .fstat        = cephfs_fstat,
    .open2        = cephfs_open2,
    .symlink      = cephfs_symlink,
    .link         = cephfs_link,
    .truncate     = cephfs_truncate,
    .rename       = cephfs_rename,
    .chown        = cephfs_chown,
    .utimensat    = cephfs_utimensat,
    .remove       = cephfs_remove,
    .fsync        = cephfs_fsync,
    .statfs       = cephfs_statfs,
    .lgetxattr    = cephfs_lgetxattr,
    .llistxattr   = cephfs_llistxattr,
    .lsetxattr    = cephfs_lsetxattr,
    .lremovexattr = cephfs_lremovexattr,
    .name_to_path = cephfs_name_to_path,
    .renameat     = cephfs_renameat,
    .unlinkat     = cephfs_unlinkat,
};

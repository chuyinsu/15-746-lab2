/**
 * @file cloudfs.c
 * @brief 15-746 Spring 2014 Project 2 - Hybrid Cloud Storage System
 *        Reference: Writing a FUSE Filesystem: a Tutorial
 *        (http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial)
 * @author Yinsu Chu (yinsuc)
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include "cloudapi.h"
#include "cloudfs.h"
#include "dedup.h"

#define UNUSED __attribute__((unused))

/* a simple debugging utility,
 * uncomment the next line to display debugging information */
#define DEBUG
#ifdef DEBUG
# define dbg_print(...) printf(__VA_ARGS__)
#else
# define dbg_print(...) 
#endif

/* to check error return of many function calls in a row,
 * such as in cloudfs_getattr(). */
#define CK_ERR(f, m) \
  if ((f) < 0) { \
    retval = cloudfs_error(m); \
  }

/* extended attributes in the user namespace */
#define U_DEV ("user.st_dev")
#define U_INO ("user.st_ino")
#define U_MODE ("user.st_mode")
#define U_NLINK ("user.st_nlink")
#define U_UID ("user.st_uid")
#define U_GID ("user.st_gid")
#define U_RDEV ("user.st_rdev")
#define U_SIZE ("user.st_size")
#define U_BLKSIZE ("user.st_blksize")
#define U_BLOCKS ("user.st_blocks")
#define U_ATIME ("user.st_atime")
#define U_MTIME ("user.st_mtime")
#define U_CTIME ("user.st_ctime")
#define U_REMOTE ("user.remote")
#define U_DIRTY ("user.dirty")

/* temporary path to store downloaded files from the cloud */
#define TEMP_PATH ("/.tmp")

/* bucket name in the cloud */
#define BUCKET ("yinsuc")

/* flags used when updating file attributes */
typedef enum {
  CREATE,
  UPDATE
} attr_flag_t;

static struct cloudfs_state State_;

static int cloudfs_error(char *);
void cloudfs_get_key(const char *, char *);

/**
 * @brief Update the attributes of a proxy file.
 * @param sp Pointer to the real attribute values.
 * @param fpath Pathname of the proxy file.
 * @param flag To control which attributes need to be updated.
 *             Some attributes, such as st_ino, should only be updated
 *             the first time when the file is migrated to the cloud;
 *             which others, such as st_size, always need to be updated.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_upgrade_attr(struct stat *sp, char *fpath, attr_flag_t flag)
{
  int retval = 0;
  char *fn = "cloudfs_upgrade_attr";

  if (flag == CREATE) {
    CK_ERR(lsetxattr(fpath, U_DEV, &sp->st_dev, sizeof(dev_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_INO, &sp->st_ino, sizeof(ino_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_MODE, &sp->st_mode, sizeof(mode_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_NLINK, &sp->st_nlink, sizeof(nlink_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_UID, &sp->st_uid, sizeof(uid_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_GID, &sp->st_gid, sizeof(gid_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_RDEV, &sp->st_rdev, sizeof(dev_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_BLKSIZE, &sp->st_blksize, sizeof(blksize_t), 0),
        fn);
    CK_ERR(lsetxattr(fpath, U_ATIME, &sp->st_atime, sizeof(time_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_MTIME, &sp->st_mtime, sizeof(time_t), 0), fn);
    CK_ERR(lsetxattr(fpath, U_CTIME, &sp->st_ctime, sizeof(time_t), 0), fn);
  }

  CK_ERR(lsetxattr(fpath, U_SIZE, &sp->st_size, sizeof(off_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_BLOCKS , &sp->st_blocks, sizeof(blkcnt_t), 0), fn);

  int remote = 1;
  CK_ERR(lsetxattr(fpath, U_REMOTE, &remote, sizeof(int), 0), fn);
  int dirty = 0;
  CK_ERR(lsetxattr(fpath, U_DIRTY, &dirty, sizeof(int), 0), fn);

  return retval;
}

/**
 * @brief Get the full path to store temporary file downloaded from the cloud.
 * @param fpath The full path of the proxy file.
 * @param tpath The generated pathname of the temporary file on SSD.
 * @return Void.
 */
void cloudfs_get_temppath(const char *fpath, char *tpath)
{
  char key[MAX_PATH_LEN] = "";
  cloudfs_get_key(fpath, key);
  snprintf(tpath, MAX_PATH_LEN, "%s/%s", TEMP_PATH, key);

  dbg_print("cloudfs_get_temppath(fpath=\"%s\", tpath=\"%s\")", fpath, tpath);
}

/**
 * @brief Convert full path on SSD to key for the cloud storage.
 *        This key also serves as the temporary file name when the
 *        file is downloaded from the cloud to SSD.
 *        Simple strategy: use the full path, replace all illegal characters.
 * @param fpath Pathname of the file.
 * @param key The key for the file to store in the cloud. It should have
 *            at least MAX_PATH_LEN byte space.
 * @return Void.
 */
void cloudfs_get_key(const char *fpath, char *key)
{
  /* copy the full path to key */
  strncpy(key, fpath, MAX_PATH_LEN);
  key[MAX_PATH_LEN - 1] = '\0';

  /* replace illegal characters in key */
  size_t i = 0;
  for (i = 0; i < strlen(key); i++) {
    if (key[i] == '/') {
      key[i] = '+';
    }
  }

  dbg_print("cloudfs_get_key(fpath=\"%s\", key=\"%s\")", fpath, key);
}

/* callback function for downloading from the cloud */
static FILE *Tfile; /* temporary file */
int get_buffer(const char *buf, int len) {
  return fwrite(buf, 1, len, Tfile);
}

/* callback function for uploading to the cloud */
static FILE *Cfile; /* cloud file */
int put_buffer(char *buf, int len) {
  return fread(buf, 1, len, Cfile);
}

/**
 * @brief Check whether a file is stored in the cloud.
 *        This is marked by extended attribute "user.remote".
 * @param fpath Full path of the file on SSD. 
 * @return 1 if is in the cloud, 0 otherwise.
 */
static int cloudfs_is_in_cloud(char *fpath)
{
  int retval = 0;
  lgetxattr(fpath, U_REMOTE, &retval, sizeof(int));
  dbg_print("[DBG] cloudfs_is_in_cloud(fpath=\"%s\")=%d\n", fpath, retval);
  return retval;
}

/**
 * @brief Get the fullpath in the underlying filesystem (SSD)
 *        of a given CloudFS path.
 * @param path A CloudFS path.
 * @param fullpath The "real" path in SSD is returned here. It should
 *                 have at least MAX_PATH_LEN byte space.
 * @return Void.
 */
void cloudfs_get_fullpath(const char *path, char *fullpath)
{
  snprintf(fullpath, MAX_PATH_LEN, "%s%s", State_.ssd_path, path);
  dbg_print("[DBG] cloudfs_get_fullpath(path=\"%s\", fullpath=\"%s\")",
      path, fullpath);
}

/**
 * @brief Translate errno to FUSE error return value by negating it.
 * @param error_str The error message passed from the caller.
 * @return FUSE error return value (-errno).
 */
static int cloudfs_error(char *error_str)
{
  int retval = -errno;
  dbg_print("[ERR] %s : %s\n", error_str, strerror(errno));
  return retval;
}

/**
 * @brief Get file attributes.
 *        For files stored on SSD, just retrieve the attributes directly;
 *        for files in the cloud, refer to the extended attributes
 *        of the proxy file.
 * @param path Pathname of the file.
 * @param sb Buffer for struct stat. The returned information is placed here.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_getattr(const char *path, struct stat *sb)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char *fn = "cloudfs_getattr";

  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath)) {
    CK_ERR(lstat(fpath, sb), fn);
    CK_ERR(lgetxattr(fpath, U_DEV, &sb->st_dev, sizeof(dev_t)), fn);
    CK_ERR(lgetxattr(fpath, U_INO, &sb->st_ino, sizeof(ino_t)), fn);
    CK_ERR(lgetxattr(fpath, U_MODE, &sb->st_mode, sizeof(mode_t)), fn);
    CK_ERR(lgetxattr(fpath, U_NLINK, &sb->st_nlink, sizeof(nlink_t)), fn);
    CK_ERR(lgetxattr(fpath, U_UID, &sb->st_uid, sizeof(uid_t)), fn);
    CK_ERR(lgetxattr(fpath, U_GID, &sb->st_gid, sizeof(gid_t)), fn);
    CK_ERR(lgetxattr(fpath, U_RDEV, &sb->st_rdev, sizeof(dev_t)), fn);
    CK_ERR(lgetxattr(fpath, U_SIZE, &sb->st_size, sizeof(off_t)), fn);
    CK_ERR(lgetxattr(fpath, U_BLKSIZE, &sb->st_blksize, sizeof(blksize_t)), fn);
    CK_ERR(lgetxattr(fpath, U_BLOCKS, &sb->st_blocks, sizeof(blkcnt_t)), fn);
    CK_ERR(lgetxattr(fpath, U_ATIME, &sb->st_atime, sizeof(time_t)), fn);
    CK_ERR(lgetxattr(fpath, U_MTIME, &sb->st_mtime, sizeof(time_t)), fn);
    CK_ERR(lgetxattr(fpath, U_CTIME, &sb->st_ctime, sizeof(time_t)), fn);
  } else {
    retval = lstat(fpath, sb);
    if (retval < 0) {
      retval = cloudfs_error(fn);
    }
  }

  dbg_print("[DBG] cloudfs_getattr(path=\"%s\", sb=0x%08x)=%d\n",
      path, (unsigned int) sb, retval);

  return retval;
}

/**
 * @brief Get extended attributes.
 *        Since all file attributes are stored locally on SSD, for files on SSD
 *        or in the cloud, we can read the extended attribute directly from
 *        files or proxy files.
 * @param path Pathname of the file.
 * @param name Name of the extended attribute.
 * @param value The returned information is placed here.
 * @param size Size of the "value" buffer.
 * @return Size of the extended attribute value, -errno on failure.
 */
int cloudfs_getxattr(const char *path, const char *name, char *value,
    size_t size)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = lgetxattr(path, name, value, size);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_getxattr");
  }

  dbg_print("[DBG] cloudfs_getxattr(path=\"%s\", name=\"%s\", value=\"%s\","
      " size=%d)=%d", path, name, value, size, retval);

  return retval;
}

/**
 * @brief Set extended attributes.
 *        Since all file attributes are stored locally on SSD, for files on SSD
 *        or in the cloud, we can write the extended attribute directly to
 *        files or proxy files.
 * @param path Pathname of the file.
 * @param name Name of the extended attribute.
 * @param value Value of the extended attribute.
 * @param size Size of the "value" buffer.
 * @param flags "Create" or "Replace" semantics.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_setxattr(const char *path, const char *name, const char *value,
    size_t size, int flags)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = lsetxattr(path, name, value, size, flags);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_setxattr");
  }

  dbg_print("[DBG] cloudfs_setxattr(path=\"%s\", name=\"%s\", value=\"%s\","
      "size=%d, flags=%d)=%d", path, name, value, size, flags, retval);

  return retval;
}

/**
 * @brief Create a directory.
 *        The entire directory tree is maintained locally on SSD,
 *        so just go ahead and create the directory.
 * @param path Path of the directory to create.
 * @param mode Controls the semantics of the function call,
 *             Such as permissions, etc.
 * @return 0 on success, -errno otherwise (and no directory shall be created).
 */
int cloudfs_mkdir(const char *path, mode_t mode)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = mkdir(fpath, mode);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_mkdir");
  }

  dbg_print("[DBG] cloudfs_mkdir(path=\"%s\", mode=%d)=%d", path, mode, retval);

  return retval;
}

/**
 * @brief Create a file node.
 *        This is used to create a non-directory file. A file is created on
 *        the local SSD initially; migration to the cloud might happen,
 *        depending on the size of the file when it is closed.
 * @param path Pathname of the file to create.
 * @param mode To set the properties of the file, such as permissions, etc.
 * @param dev Along with "mode", setting properties of the file.
 * @return 0 on success, -errno otherwise (and no file shall be created).
 */
int cloudfs_mknod(const char *path, mode_t mode, dev_t dev)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = mknod(fpath, mode, dev);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_mknod");
  }

  /* every new file is marked as local and not dirty initially */
  int remote = 0;
  int dirty = 0;
  lsetxattr(fpath, U_REMOTE, &remote, sizeof(int), 0);
  lsetxattr(fpath, U_DIRTY, &dirty, sizeof(int), 0);

  dbg_print("[DBG] cloudfs_mknod(path=\"%s\", mode=%d, dev=%llu)=%d",
      path, mode, dev, retval);

  return retval;
}

/**
 * @brief Open a file.
 *        If the file is in local SSD, open it directly;
 *        Otherwise, download the file from the cloud and
 *        store it locally for access. Any changes will be
 *        synchronized when the file is closed.
 * @param path Pathname of the file to open.
 * @param fi Information about the opened file is returned here.
 * @return 0 on success, -errno on failure.
 */
int cloudfs_open(const char *path, struct fuse_file_info *fi)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char tpath[MAX_PATH_LEN] = "";
  char key[MAX_PATH_LEN] = "";
  int fd = 0;

  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath)) {
    cloudfs_get_key(fpath, key);
    cloudfs_get_temppath(fpath, tpath);
    Tfile = fopen(tpath, "wb");
    cloud_get_object(BUCKET, key, get_buffer);
    cloud_print_error();
    fclose(Tfile);
    fd = open(tpath, O_RDWR);
  } else {
    fd = open(fpath, O_RDWR);
  }

  fi->fh = fd;
  if (fd < 0) {
    retval = cloudfs_error("cloudfs_open");
  }

  dbg_print("[DBG] cloudfs_open(path=\"%s\", fi=0x%08x)=%d",
      path, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Read data from an opened file.
 *        The underlying file descriptor has already been saved in "fi",
 *        so here we can directly use it.
 * @param path Pathname of the file.
 * @param buf Returned data is placed here.
 * @param size Size of the buffer.
 * @param offset The beginning place to start reading.
 * @param fi The information about the opened file.
 * @return Number of bytes read on success, -errno otherwise.
 */
int cloudfs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  int retval = 0;

  retval = pread(fi->fh, buf, size, offset);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_read");
  }

  dbg_print("[DBG] cloudfs_read(path=\"%s\", buf=\"%s\", size=%d, offset=%llu,"
      " fi=0x%08x)=%d", path, buf, size, offset, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Write data to an opened file.
 *        The underlying file descriptor has already been saved in "fi",
 *        so here we can directly use it. Also, we need to set "user.dirty"
 *        if this file is stored in the cloud.
 * @param path Pathname of the file to write.
 * @param buf The content to write.
 * @param size Size of the content buffer.
 * @param offset The beginning place to start writing.
 * @param fi The information about the opened file.
 * @return Number of bytes written on success, -errno otherwise.
 */
int cloudfs_write(const char *path, const char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath)) {
    int dirty = 1;
    lsetxattr(fpath, U_DIRTY, &dirty, sizeof(int), 0);
  }

  retval = pwrite(fi->fh, buf, size, offset);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_write");
  }

  dbg_print("[DBG] cloudfs_write(path=\"%s\", buf=\"%s\", size=%d, offset=%llu,"
      " fi=0x%08x)=%d", path, buf, size, offset, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Release an opened file.
 *        For files stored on SSD:
 *          - If its size does not exceed the threshold, just close it;
 *          - If its size has exceeded the threshold, move it to the cloud;
 *        For files stored in the cloud:
 *          - If its dirty attribute is not set, just delete the temporary file.
 *          - If its dirty attribute is set:
 *            1) If its size shrinks below the threshold, move it back to SSD;
 *            2) Otherwise, upload the new version to the cloud;
 * @param path Pathname of the file to release.
 * @param fi The information about the opened file.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_release(const char *path, struct fuse_file_info *fi)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char tpath[MAX_PATH_LEN] = "";
  char key[MAX_PATH_LEN] = "";
  struct stat sb;

  retval = close(fi->fh);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_release");
    return retval;
  }

  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath)) {
    /* cloud file */

    cloudfs_get_temppath(fpath, tpath);
    cloudfs_get_key(fpath, key);

    /* read the latest attributes from the temporary file */
    retval = stat(tpath, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_release");
      return retval;
    }

    /* read dirty attribute */
    int dirty = 0;
    retval = lgetxattr(fpath, U_DIRTY, &dirty, sizeof(int));
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_release");
      return retval;
    }

    if (dirty) {
      /* file content changed */

      if (sb.st_size < State_.threshold) {
        /* move back to SSD */

        /* delete the proxy file */
        retval = remove(fpath);
        if (retval < 0) {
          retval = cloudfs_error("cloudfs_release");
          return retval;
        }

        /* move the temporary file to the original location on SSD */
        retval = rename(tpath, fpath);
        if (retval < 0) {
          retval = cloudfs_error("cloudfs_release");
          return retval;
        }

        /* update attributes */
        int remote_attr = 0;
        int dirty_attr = 0;
        lsetxattr(fpath, U_REMOTE, &remote_attr, sizeof(int), 0);
        lsetxattr(fpath, U_DIRTY, &dirty_attr, sizeof(int), 0);

        /* delete the file in the cloud */
        cloud_delete_object(BUCKET, key);
        cloud_print_error();
      } else {
        /* synchronize to the cloud */

        /* delete the file in the cloud */
        cloud_delete_object(BUCKET, key);
        cloud_print_error();

        /* upload the new version */
        Cfile = fopen(tpath, "rb");
        cloud_put_object(BUCKET, key, sb.st_size, put_buffer);
        cloud_print_error();
        fclose(Cfile);

        /* update attributes */
        cloudfs_upgrade_attr(&sb, fpath, UPDATE);

        /* remove the temporary file on SSD */
        retval = remove(tpath);
        if (retval < 0) {
          retval = cloudfs_error("cloudfs_release");
          return retval;
        }
      }
    } else {
      /* file content not changed */

      /* remove the temporary file on SSD */
      retval = remove(tpath);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_release");
        return retval;
      }
    }
  } else {
    /* local file */

    /* read the latest file attributes */
    retval = stat(fpath, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_release");
      return retval;
    }

    if (sb.st_size > State_.threshold) {
      /* move to the cloud */

      /* upload */
      Cfile = fopen(fpath, "rb");
      cloud_put_object(BUCKET, key, sb.st_size, put_buffer);
      cloud_print_error();
      fclose(Cfile);

      /* clear the file content */
      FILE *fp = fopen(fpath, "wb");
      fclose(fp);

      /* update attributes */
      cloudfs_upgrade_attr(&sb, fpath, CREATE);
    }
  }

  dbg_print("[DBG] cloudfs_release(path=\"%s\", fi=0x%08x)=%d", path,
      (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Open a directory.
 * @param path The path of the directory.
 * @param fi Information about the opened directory is returned here.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_opendir(const char *path, struct fuse_file_info *fi)
{
  int retval = 0;
  DIR *dp = NULL;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  dp = opendir(fpath);
  if (dp == NULL) {
    retval = cloudfs_error("cloudfs_opendir");
  }

  fi->fh = (intptr_t) dp;

  dbg_print("[DBG] cloudfs_opendir(path=\"%s\", fi=0x%08x)=%d", path,
      (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Read directory.
 *        The strategy used here is to ignore the offset passed in,
 *        each time the whole directory is read into the buffer.
 * @param path Path of the directory.
 * @param buf Buffer to store returned information.
 * @param filler Function to add an entry into the buffer.
 * @param offset The offset to start reading.
 * @param fi Information about the opened directory.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi)
{
  int retval = 0;
  DIR *dp = NULL;
  struct dirent *de = NULL;

  dp = (DIR *) (uintptr_t) fi->fh;

  de = readdir(dp);
  if (de == NULL) {
    retval = cloudfs_error("cloudfs_readdir");
    return retval;
  }

  struct stat sb;
  do {
    memset(&sb, '\0', sizeof(struct stat));
    sb.st_ino = de->d_ino;
    sb.st_mode = DTTOIF(de->d_type);
    if (filler(buf, de->d_name, &sb, 0) != 0) {
      retval = -ENOMEM;
      return retval;
    }
  } while ((de = readdir(dp)) != NULL);

  dbg_print("[DBG] cloudfs_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x,"
      " offset=%llu, fi=0x%08x)=%d", path, (unsigned int) buf,
      (unsigned int) filler, offset, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Initializes the FUSE file system.
 *        Currently its job is to create the bucket in the cloud.
 * @param conn Unused parameter.
 * @return NULL.
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
  cloud_init(State_.hostname);
  cloud_print_error();
  cloud_create_bucket(BUCKET);
  cloud_print_error();

  dbg_print("[DBG] cloudfs_init()");

  return NULL;
}

/**
 * @brief Clean up CloudFS.
 *        This is called on CloudFS exit.
 * @param data Unused parameter.
 * @return Void.
 */
void cloudfs_destroy(void *data UNUSED) {
  cloud_destroy();
  cloud_print_error();

  dbg_print("[DBG] cloudfs_destroy()");
}

/**
 * @brief Check file access permissions.
 *        Currently only implemented for files on SSD.
 * @param path Pathname of the file.
 * @param mask The permissions to check.
 * @return 0 on permitted, -errno otherwise.
 */
int cloudfs_access(const char *path, int mask)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = access(fpath, mask);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_access");
  }

  dbg_print("[DBG] cloudfs_access(path=\"%s\", mask=%d)=%d", path, mask,
      retval);

  return retval;
}

/**
 * @brief Change the access and modification times of a file.
 *        Currently only implemented for files on SSD.
 * @param path Pathname of the file.
 * @param tv The new times are specified here.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_utimens(const char *path, const struct timespec tv[2])
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = utimensat(0, fpath, tv, AT_SYMLINK_NOFOLLOW);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_utimens");
  }

  dbg_print("[DBG] cloudfs_utimens(path=\"%s\", tv=0x%08x)=%d", path,
      (unsigned int) tv, retval);

  return retval;
}

/**
 * @brief Change the permission bits of a file.
 *        Currently only implemented for files on SSD.
 * @param path Pathname of the file.
 * @param mode The new permission bits.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_chmod(const char *path, mode_t mode)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = chmod(fpath, mode);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_chmod");
  }

  dbg_print("[DBG] cloudfs_chmod(path=\"%s\", mode=%d)=%d", path, mode, retval);

  return retval;
}

/**
 * @brief Remove a file.
 *        For files in the cloud, need to delete both proxy file on SSD
 *        and the actual file content stored in the cloud.
 * @param path Pathname of the file.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_unlink(const char *path)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char key[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath)) {
    cloudfs_get_key(fpath, key);
    cloud_delete_object(BUCKET, key);
    cloud_print_error();
  }

  retval = unlink(fpath);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_unlink");
  }

  return retval;
}

/* functions supported by CloudFS */
static struct fuse_operations Cloudfs_operations = {
  .getattr        = cloudfs_getattr,
  .getxattr       = cloudfs_getxattr,
  .setxattr       = cloudfs_setxattr,
  .mkdir          = cloudfs_mkdir,
  .mknod          = cloudfs_mknod,
  .open           = cloudfs_open,
  .read           = cloudfs_read,
  .write          = cloudfs_write,
  .release        = cloudfs_release,
  .opendir        = cloudfs_opendir,
  .readdir        = cloudfs_readdir,
  .init           = cloudfs_init,
  .destroy        = cloudfs_destroy,
  .access         = cloudfs_access,
  .utimens        = cloudfs_utimens,
  .chmod          = cloudfs_chmod,
  .unlink         = cloudfs_unlink
};

int cloudfs_start(struct cloudfs_state *state, const char* fuse_runtime_name) {
  int argc = 0;
  char *argv[10];

  argv[argc] = (char *) malloc(128 * sizeof(char));
  strcpy(argv[argc++], fuse_runtime_name);
  argv[argc] = (char *) malloc(1024 * sizeof(char));
  strcpy(argv[argc++], state->fuse_path);

  /* set the fuse mode to single thread */
  argv[argc++] = "-s";

  /* run fuse in foreground */
  //argv[argc++] = "-f";

  State_ = *state;
  int fuse_stat = fuse_main(argc, argv, &Cloudfs_operations, NULL);

  return fuse_stat;
}


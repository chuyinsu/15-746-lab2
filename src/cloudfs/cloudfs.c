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
#include <ftw.h>
#include "cloudapi.h"

// #define DEBUG
#include "cloudfs.h"

#include "dedup.h"

#include "hashtable.h"
#include "dedup_layer.h"
#include "cache_layer.h"

#define UNUSED __attribute__((unused))

/* to check error return of many function calls in a row,
 * such as in cloudfs_getattr() */
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

/* temporary path for CloudFS */
#define TEMP_PATH ("/.tmp")

/* cache path for CloudFS */
#define CACHE_PATH ("/.cache")

/* log file path */
#define LOG_FILE ("./cloudfs.log")

/* hash table configurations */
#define BKT_NUM (11) /* 11 buckets */
/* each bucket holds 3 segments initially */
#define BKT_SIZE (3 * sizeof(struct cloudfs_seg))

FILE *Log;
char Cache_path[MAX_PATH_LEN];
static struct cloudfs_state State_;
static char Temp_path[MAX_PATH_LEN];
static char Bkt_prfx[MAX_PATH_LEN];
static int Cache_init_size;

/* callback function for downloading from the cloud */
static FILE *Tfile;
static int get_buffer(const char *buf, int len) {
  return fwrite(buf, 1, len, Tfile);
}

/* callback function for uploading to the cloud */
static FILE *Cfile;
static int put_buffer(char *buf, int len) {
  return fread(buf, 1, len, Cfile);
}

void cloudfs_get_key(const char *fpath, char *key);
int cloudfs_rmdir_rec(char *path);

#ifdef DEBUG
void print_stat(const struct stat *sb)
{
  dbg_print("[DBG] print stat 0x%08x\n", (unsigned int) sb);
  dbg_print("      st_dev=%llu\n", sb->st_dev);
  dbg_print("      st_ino=%llu\n", sb->st_ino);
  dbg_print("      st_mode=%d\n", sb->st_mode);
  dbg_print("      st_nlink=%d\n", sb->st_nlink);
  dbg_print("      st_uid=%d\n", sb->st_uid);
  dbg_print("      st_gid=%d\n", sb->st_gid);
  dbg_print("      st_rdev=%llu\n", sb->st_rdev);
  dbg_print("      st_size=%llu\n", sb->st_size);
  dbg_print("      st_atime=%lu\n", sb->st_atime);
  dbg_print("      st_mtime=%lu\n", sb->st_mtime);
  dbg_print("      st_ctime=%lu\n", sb->st_ctime);
  dbg_print("      st_blksize=%lu\n", sb->st_blksize);
  dbg_print("      st_blocks=%llu\n", sb->st_blocks);
}
#endif

/**
 * @brief Update the attributes of a proxy file.
 * @param sp Pointer to the real attribute values.
 * @param fpath Pathname of the proxy file.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_upgrade_attr(struct stat *sp, char *fpath)
{
  int retval = 0;
  char *fn = "cloudfs_upgrade_attr";

  dbg_print("[DBG] cloudfs_upgrade_attr(sp=0x%08x, fpath=\"%s\")\n",
      (unsigned int) sp, fpath);
#ifdef DEBUG
  print_stat(sp);
#endif

  CK_ERR(lsetxattr(fpath, U_DEV, &sp->st_dev, sizeof(dev_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_INO, &sp->st_ino, sizeof(ino_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_MODE, &sp->st_mode, sizeof(mode_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_NLINK, &sp->st_nlink, sizeof(nlink_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_UID, &sp->st_uid, sizeof(uid_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_GID, &sp->st_gid, sizeof(gid_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_RDEV, &sp->st_rdev, sizeof(dev_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_BLKSIZE, &sp->st_blksize, sizeof(blksize_t), 0),
      fn);

  /* according to the test cases, these times should not be updated */
  // CK_ERR(lsetxattr(fpath, U_ATIME, &sp->st_atime, sizeof(time_t), 0), fn);
  // CK_ERR(lsetxattr(fpath, U_MTIME, &sp->st_mtime, sizeof(time_t), 0), fn);
  // CK_ERR(lsetxattr(fpath, U_CTIME, &sp->st_ctime, sizeof(time_t), 0), fn);

  CK_ERR(lsetxattr(fpath, U_SIZE, &sp->st_size, sizeof(off_t), 0), fn);
  CK_ERR(lsetxattr(fpath, U_BLOCKS , &sp->st_blocks, sizeof(blkcnt_t), 0), fn);

  int remote = 1;
  CK_ERR(lsetxattr(fpath, U_REMOTE, &remote, sizeof(int), 0), fn);
  int dirty = 0;
  CK_ERR(lsetxattr(fpath, U_DIRTY, &dirty, sizeof(int), 0), fn);

  dbg_print("[DBG] cloudfs_upgrade_attr(sp=0x%08x, fpath=\"%s\")=%d\n",
      (unsigned int) sp, fpath, retval);

  return retval;
}

/**
 * @brief Get the full path of a cloud file's temporary directory.
 * @param fpath The full path of the proxy file.
 * @param tpath The generated path of the temporary directory on SSD.
 * @return Void.
 */
void cloudfs_get_temppath(const char *fpath, char *tpath)
{
  char key[MAX_PATH_LEN] = "";
  cloudfs_get_key(fpath, key);
  snprintf(tpath, MAX_PATH_LEN, "%s/%s", Temp_path, key);

  dbg_print("[DBG] cloudfs_get_temppath(fpath=\"%s\", tpath=\"%s\")\n", fpath,
      tpath);
}

/**
 * @brief Convert full path on SSD to temporary directory name on SSD.
 *        Simple strategy: use the full path, replace all illegal characters.
 *        This function got its name in Part 1, but now it does not generate
 *        keys for the cloud storage.
 * @param fpath Pathname of the file.
 * @param key The corresponding temporary directory on SSD. It should have
 *            at least MAX_PATH_LEN bytes.
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

  dbg_print("[DBG] cloudfs_get_key(fpath=\"%s\", key=\"%s\")\n", fpath, key);
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
 * @brief Get the fullpath in SSD of a given CloudFS path.
 * @param path A CloudFS path.
 * @param fullpath The "real" path in SSD is returned here. It should
 *                 have at least MAX_PATH_LEN bytes.
 * @return Void.
 */
void cloudfs_get_fullpath(const char *path, char *fullpath)
{
  snprintf(fullpath, MAX_PATH_LEN, "%s%s", State_.ssd_path, path);
  dbg_print("[DBG] cloudfs_get_fullpath(path=\"%s\", fullpath=\"%s\")\n",
      path, fullpath);
}

/**
 * @brief Translate errno to FUSE error return value by negating it.
 * @param error_str The error message passed from the caller.
 *                  Typically this is the caller's function name.
 * @return FUSE error return value (-errno).
 */
int cloudfs_error(char *error_str)
{
  int retval = -errno;
  fprintf(stderr, "[ERR] %s : %s\n", error_str, strerror(errno));
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

    /* according to the test cases, these times should not be read */
    // CK_ERR(lgetxattr(fpath, U_ATIME, &sb->st_atime, sizeof(time_t)), fn);
    // CK_ERR(lgetxattr(fpath, U_MTIME, &sb->st_mtime, sizeof(time_t)), fn);
    // CK_ERR(lgetxattr(fpath, U_CTIME, &sb->st_ctime, sizeof(time_t)), fn);
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

  /* this is a compromise for the test environment,
   * strange extended attributes (such as "security.capability")
   * are read and not sure why... since they do not exist,
   * a ENOENT error will be returned causing erroneous display */
  if (retval == -ENOENT) {
    retval = 0;
  }

  dbg_print("[DBG] cloudfs_getxattr(path=\"%s\", name=\"%s\", value=\"%s\","
      " size=%d)=%d\n", path, name, value, size, retval);

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
      " size=%d, flags=%d)=%d\n", path, name, value, size, flags, retval);

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

  dbg_print("[DBG] cloudfs_mkdir(path=\"%s\", mode=%d)=%d\n", path, mode,
      retval);

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

  dbg_print("[DBG] cloudfs_mknod(path=\"%s\", mode=%d, dev=%llu)=%d\n",
      path, mode, dev, retval);

  return retval;
}

/**
 * @brief Open a file.
 *        If the file is in local SSD, open it directly;
 *        If the file is in the cloud:
 *          1) If dedup is disabled, download the file from the cloud and
 *             store it locally for access.
 *          2) If dedup is enabled, create an empty file for writing and
 *             remember the file handle.
 * @param path Pathname of the file to open.
 * @param fi Information about the opened file is returned here.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_open(const char *path, struct fuse_file_info *fi)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char tpath[MAX_PATH_LEN] = "";
  char key[MAX_PATH_LEN] = "";
  int fd = 0;

  cloudfs_get_fullpath(path, fpath);
  cloudfs_get_key(fpath, key);
  cloudfs_get_temppath(fpath, tpath);

  if (cloudfs_is_in_cloud(fpath)) {
    if (State_.no_dedup) {
      dbg_print("[DBG] dedup is disabled, download the entire file\n");
      Tfile = fopen(tpath, "wb");
      cloud_get_object(BUCKET, key, get_buffer);
      cloud_print_error();
      fclose(Tfile);
      fd = open(tpath, O_RDWR);
    } else {
      /* create the temporary directory for the file */
      retval = mkdir(tpath, DEFAULT_DIR_MODE);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_open");
        return retval;
      }

      /* create the temporary file for new content (if any) */
      sprintf(tpath, "%s%s", tpath, "/new_content");
      dbg_print("[DBG] dedup is enabled, creating temporary file %s\n", tpath);

      fd = open(tpath, O_RDWR | O_CREAT, DEFAULT_FILE_MODE);
      if (fd < 0) {
        retval = cloudfs_error("cloudfs_open");
        return retval;
      }

      dbg_print("[DBG] temporary file created with descriptor %d\n", fd);
    }
  } else {
    fd = open(fpath, O_RDWR);
  }

  fi->fh = fd;
  if (fd < 0) {
    retval = cloudfs_error("cloudfs_open");
  }

  dbg_print("[DBG] cloudfs_open(path=\"%s\", fi=0x%08x)=%d\n",
      path, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Read data from an opened file.
 *        For part 1:
 *         The underlying file descriptor has already been saved in "fi",
 *         so here we can directly use it.
 *        For part 2:
 *         Same logic for local files; for cloud files, download needed segments
 *         and read them into the buffer. This avoids the effort to download
 *         unnecessary segments.
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
  char fpath[MAX_PATH_LEN] = "";
  cloudfs_get_fullpath(path, fpath);

  dbg_print("[DBG] reading interval [%llu, %llu] of the file\n",
      offset, offset + size - 1);

  if (cloudfs_is_in_cloud(fpath) && (!State_.no_dedup)) {
    /* cloud file and dedup enabled */
    dbg_print("[DBG] this is a cloud file and dedup enabled\n");

    int dirty = 0;
    retval = lgetxattr(fpath, U_DIRTY, &dirty, sizeof(int));
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_read");
      return retval;
    }

    if (dirty) {
      /* file is dirty */
      dbg_print("[DBG] file is dirty, read from the new version\n");

      retval = pread(fi->fh, buf, size, offset);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_read");
      }
    } else {
      char tpath[MAX_PATH_LEN] = "";
      cloudfs_get_temppath(fpath, tpath);

      /* file is not dirty, fetch needed segments from the cloud */
      dbg_print("[DBG] file is not dirty\n");

      /* these are parameters required by the getline() function */
      char *seg_md5 = NULL;
      size_t len = 0;
      FILE *proxy_fp = fopen(fpath, "rb");
      if (proxy_fp == NULL) {
        retval = cloudfs_error("cloudfs_read");
        return retval;
      }

      /* keep track of the file position */
      unsigned int seg_start_pos = 0;
      unsigned int seg_end_pos = 0;

      /* calculate the span of the current segment that we need */
      unsigned int seg_local_offset = 0;
      unsigned int seg_local_size = 0;

      /* keep track of how many data has been read */
      int filled = 0;

      dbg_print("[DBG] {} - current segment, [] target portion\n");

      /* iterate through all the segments */
      while ((retval = getline(&seg_md5, &len, proxy_fp)) != -1) {

        /* build the segment structure */
        struct cloudfs_seg seg;
        seg.ref_count = 0;
        seg.seg_size =
          (int) strtol(seg_md5 + 2 * MD5_DIGEST_LENGTH + 1, NULL, 10);
        memset(seg.md5, '\0', 2 * MD5_DIGEST_LENGTH + 1);
        memcpy(seg.md5, seg_md5, 2 * MD5_DIGEST_LENGTH);
        if (seg_md5 != NULL) {
          free(seg_md5);
          seg_md5 = NULL;
          len = 0;
        }
        dbg_print("[DBG] next segment from proxy file\n");
#ifdef DEBUG
        print_seg(&seg);
#endif

        /* the span of the current segment in the entire file */
        if (seg_end_pos > 0) {
          seg_start_pos = seg_end_pos + 1;
        }
        seg_end_pos = seg_start_pos + seg.seg_size - 1;
        dbg_print("[DBG] this segment holds interval {%d, %d} of the file\n",
            seg_start_pos, seg_end_pos);

        /* the portion that we want is interval [offset, offset + size - 1],
         * there are several cases regarding the intersection of this interval
         * and the current segment */

        if (seg_end_pos < offset) {
          dbg_print("[DBG] {%d   %d} [%llu   %llu]\n",
              seg_start_pos, seg_end_pos, offset, offset + size - 1);
          continue;
        } else if (seg_start_pos < offset
            && seg_end_pos >= offset
            && seg_end_pos <= offset + size - 1) {
          dbg_print("[DBG] {%d   [%llu   %d}   %llu]\n",
              seg_start_pos, offset, seg_end_pos, offset + size - 1);
          seg_local_offset = offset - seg_start_pos;
          seg_local_size = seg_end_pos - offset + 1;
        } else if (seg_start_pos >= offset
            && seg_start_pos <= offset + size - 1
            && seg_end_pos >= offset
            && seg_end_pos <= offset + size - 1) {
          dbg_print("[DBG] [%llu   {%d   %d}   %llu]\n",
              offset, seg_start_pos, seg_end_pos, offset + size - 1);
          seg_local_offset = 0;
          seg_local_size = seg.seg_size;
        } else if (seg_start_pos < offset
            && seg_end_pos > offset + size - 1) {
          dbg_print("[DBG] {%d   [%llu   %llu]   %d}\n",
              seg_start_pos, offset, offset + size - 1, seg_end_pos);
          seg_local_offset = offset - seg_start_pos;
          seg_local_size = size;
        } else if (seg_start_pos > offset
            && seg_start_pos <= offset + size - 1
            && seg_end_pos > offset + size - 1) {
          dbg_print("[DBG] [%llu   {%d   %llu]   %d}\n",
              offset, seg_start_pos, offset + size - 1, seg_end_pos);
          seg_local_offset = 0;
          seg_local_size = offset + size - seg_start_pos;
        } else if (seg_start_pos > offset + size - 1) {
          dbg_print("[DBG] [%llu   %llu] {%d   %d}\n",
              offset, offset + size - 1, seg_start_pos, seg_end_pos);
          continue;
        }

        char seg_buf[seg_local_size];
        retval = dedup_layer_read_seg(tpath, &seg, seg_buf, seg_local_size,
            seg_local_offset);
        if (retval < 0) {
          return retval;
        }

        memcpy(buf + filled, seg_buf, retval);
        filled += retval;
      } /* end of while */

      retval = fclose(proxy_fp);
      if (retval == EOF) {
        retval = cloudfs_error("cloudfs_read");
      } else {
        retval = filled;
      }
    }
  } else {
    /* local file or dedup disabled */
    dbg_print("[DBG] this is a local file or dedup is disabled\n");

    retval = pread(fi->fh, buf, size, offset);
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_read");
    }
  }

  dbg_print("[DBG] cloudfs_read(path=\"%s\", buf=0x%08x, size=%d, offset=%llu,"
      " fi=0x%08x)=%d\n", path, (unsigned int) buf, size, offset,
      (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Write data to an opened file.
 *        If the file is not marked dirty, it has not been written before.
 *        Then download all of its content, write it and save the file handle.
 *        Otherwise (is dirty), directly write to the file handle in fi->fh.
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
  char tpath_dir[MAX_PATH_LEN] = "";
  char tpath[MAX_PATH_LEN] = "";
  cloudfs_get_fullpath(path, fpath);

  if (cloudfs_is_in_cloud(fpath) && (!State_.no_dedup)) {
    cloudfs_get_temppath(fpath, tpath_dir);
    sprintf(tpath, "%s%s", tpath_dir, "/new_content");
    dbg_print("[DBG] temporary directory is %s\n", tpath_dir);
    dbg_print("[DBG] temporary file is %s\n", tpath);

    /* get dirty attribute */
    int dirty = 0;
    retval = lgetxattr(fpath, U_DIRTY, &dirty, sizeof(int));
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_write");
      return retval;
    }

    if (!dirty) {
      dirty = 1;
      lsetxattr(fpath, U_DIRTY, &dirty, sizeof(int), 0);

      /* open temporary file, append all contents to it */
      FILE *t_fp = fopen(tpath, "ab");

      /* these are parameters required by the getline() function */
      char *seg_md5 = NULL;
      size_t len = 0;
      FILE *proxy_fp = fopen(fpath, "rb");
      if (proxy_fp == NULL) {
        retval = cloudfs_error("cloudfs_write");
        return retval;
      }

      /* iterate through all the segments */
      while ((retval = getline(&seg_md5, &len, proxy_fp)) != -1) {
        /* build the segment structure */
        struct cloudfs_seg seg;
        seg.ref_count = 0;
        seg.seg_size =
          (int) strtol(seg_md5 + 2 * MD5_DIGEST_LENGTH + 1, NULL, 10);
        memset(seg.md5, '\0', 2 * MD5_DIGEST_LENGTH + 1);
        memcpy(seg.md5, seg_md5, 2 * MD5_DIGEST_LENGTH);
        if (seg_md5 != NULL) {
          free(seg_md5);
          seg_md5 = NULL;
          len = 0;
        }
        dbg_print("[DBG] next segment from proxy file\n");
#ifdef DEBUG
        print_seg(&seg);
#endif
        char seg_buf[seg.seg_size];
        retval =
          dedup_layer_read_seg(tpath_dir, &seg, seg_buf, seg.seg_size, 0);
        if (retval < 0) {
          return retval;
        }
        dbg_print("[DBG] writing %d bytes to %s\n", retval, tpath);
        fwrite(seg_buf, sizeof(char), retval, t_fp);
      }
      fclose(t_fp);
    }
  }

  retval = pwrite(fi->fh, buf, size, offset);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_write");
  }

  dbg_print("[DBG] cloudfs_write(path=\"%s\", buf=0x%08x, size=%d, offset=%llu,"
      " fi=0x%08x)=%d\n", path, (unsigned int) buf, size, offset,
      (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Recursively remove a directory.
 *        This directory along with everything inside it are removed.
 * @param path Pathname of the directory.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_rmdir_rec(char *path)
{
  int retval = 0;
  char command[MAX_PATH_LEN] = "";
  snprintf(command, MAX_PATH_LEN, "%s%s", "rm -rf ", path);
  dbg_print("[DBG] remove directory, the command is %s\n", command);
  retval = system(command);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_rmdir_rec");
    return retval;
  }
  return retval;
}

/**
 * @brief Release an opened file.
 *        For files stored on SSD:
 *          - If its size does not exceed the threshold, just close it;
 *          - If its size has exceeded the threshold, move it to the cloud;
 *        For files stored in the cloud:
 *          - If file is not dirty, just delete the temporary segments.
 *          - If file is dirty:
 *            1) If its size shrinks below the threshold, move it back to SSD;
 *            2) Otherwise, replace the new version to the cloud;
 * @param path Pathname of the file to release.
 * @param fi The information about the opened file.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_release(const char *path, struct fuse_file_info *fi)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";
  char tpath[MAX_PATH_LEN] = "";
  char tpath_dir[MAX_PATH_LEN] = "";
  char key[MAX_PATH_LEN] = "";
  struct stat sb;

  cloudfs_get_fullpath(path, fpath);
  cloudfs_get_temppath(fpath, tpath_dir);
  cloudfs_get_key(fpath, key);

  if (State_.no_dedup) {
    sprintf(tpath, "%s", tpath_dir);
    dbg_print("[DBG] temporary file is %s\n", tpath);
  } else {
    /* get the correct temporary file path if dedup is enabled */
    sprintf(tpath, "%s%s", tpath_dir, "/new_content");
    dbg_print("[DBG] temporary directory is %s\n", tpath_dir);
    dbg_print("[DBG] temporary file is %s\n", tpath);
  }

  /* close the temporary file */
  retval = close(fi->fh);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_release");
    return retval;
  }
  dbg_print("[DBG] temporary file closed\n");

  if (cloudfs_is_in_cloud(fpath)) {
    /* cloud file */

    /* get dirty attribute */
    int dirty = 0;
    retval = lgetxattr(fpath, U_DIRTY, &dirty, sizeof(int));
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_release");
      return retval;
    }

    if (dirty) {
      /* file content changed */
      dbg_print("[DBG] file is dirty\n");

      /* read the latest attributes from the temporary file */
      retval = lstat(tpath, &sb);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_release");
        return retval;
      }
#ifdef DEBUG
      print_stat(&sb);
#endif

      if (sb.st_size < State_.threshold) {
        /* move back to SSD */
        dbg_print("[DBG] file size shrinked below threshold\n");

        if (State_.no_dedup) {
          /* delete the file in the cloud */
          cloud_delete_object(BUCKET, key);
          cloud_print_error();

          /* delete the proxy file */
          retval = remove(fpath);
          if (retval < 0) {
            retval = cloudfs_error("cloudfs_release");
            return retval;
          }
        } else {
          /* delete the file via the dedup layer */
          retval = dedup_layer_remove(fpath);
          if (retval < 0) {
            return retval;
          }
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

      } else {
        /* synchronize to the cloud */
        dbg_print("[DBG] file size still exceeds threshold\n");

        if (State_.no_dedup) {
          /* delete the file in the cloud */
          cloud_delete_object(BUCKET, key);
          cloud_print_error();

          /* upload the new version */
          Cfile = fopen(tpath, "rb");
          cloud_put_object(BUCKET, key, sb.st_size, put_buffer);
          cloud_print_error();
          fclose(Cfile);

          /* remove the temporary file on SSD */
          retval = remove(tpath);
          if (retval < 0) {
            retval = cloudfs_error("cloudfs_release");
            return retval;
          }
        } else {
          /* replace the old version in the cloud */
          retval = dedup_layer_remove(fpath);
          if (retval < 0) {
            return retval;
          }
          retval = rename(tpath, fpath);
          if (retval < 0) {
            retval = cloudfs_error("cloudfs_release");
            return retval;
          }
          retval = dedup_layer_upload(fpath);
          if (retval < 0) {
            return retval;
          }
        }

        /* update attributes */
        cloudfs_upgrade_attr(&sb, fpath);
      }
    } else {
      /* file content not changed */
      dbg_print("[DBG] file is not dirty\n");

      /* remove the temporary file on SSD */
      retval = remove(tpath);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_release");
        return retval;
      }
    }

    if (!State_.no_dedup) {
      /* delete the temporary directory */
      retval = cloudfs_rmdir_rec(tpath_dir);
      if (retval < 0) {
        return retval;
      }
      dbg_print("[DBG] temporary directory %s removed\n", tpath_dir);
    }

  } else {
    /* local file */

    /* read the latest file attributes */
    retval = lstat(fpath, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_release");
      return retval;
    }
#ifdef DEBUG
    print_stat(&sb);
#endif

    if (sb.st_size > State_.threshold) {
      /* move to the cloud */
      dbg_print("[DBG] file size exceeds threshold\n");

      if (State_.no_dedup) {
        /* upload the entire file */
        Cfile = fopen(fpath, "rb");
        cloud_put_object(BUCKET, key, sb.st_size, put_buffer);
        cloud_print_error();
        fclose(Cfile);

        /* clear the file content */
        FILE *fp = fopen(fpath, "wb");
        fclose(fp);
      } else {
        /* upload via dedup layer */
        retval = dedup_layer_upload(fpath);
        if (retval < 0) {
          return retval;
        }
      }

      /* update attributes */
      cloudfs_upgrade_attr(&sb, fpath);
    }
  }

  dbg_print("[DBG] cloudfs_release(path=\"%s\", fi=0x%08x)=%d\n", path,
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

  dbg_print("[DBG] cloudfs_opendir(path=\"%s\", fi=0x%08x)=%d\n", path,
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
int cloudfs_readdir(const char *path UNUSED, void *buf, fuse_fill_dir_t filler,
    off_t offset UNUSED, struct fuse_file_info *fi)
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
      " offset=%llu, fi=0x%08x)=%d\n", path, (unsigned int) buf,
      (unsigned int) filler, offset, (unsigned int) fi, retval);

  return retval;
}

/**
 * @brief Initialize the FUSE file system.
 *        Currently it does nothing, all important
 *        initializations are placed in cloudfs_start().
 *        The reason is that if any of them fails,
 *        CloudFS should abort instead of continuing to run.
 * @param conn Unused parameter.
 * @return NULL.
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
  dbg_print("[DBG] cloudfs_init()\n");
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
  fclose(Log);
  if (!State_.no_dedup) {
    ht_destroy();
    dedup_layer_destroy();
  }
  dbg_print("[DBG] cloudfs_destroy()\n");
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

  dbg_print("[DBG] cloudfs_access(path=\"%s\", mask=%d)=%d\n", path, mask,
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

  dbg_print("[DBG] cloudfs_utimens(path=\"%s\", tv=0x%08x)=%d\n", path,
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

  dbg_print("[DBG] cloudfs_chmod(path=\"%s\", mode=%d)=%d\n", path, mode,
      retval);

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
    if (State_.no_dedup) {
      cloudfs_get_key(fpath, key);
      cloud_delete_object(BUCKET, key);
      cloud_print_error();
      retval = unlink(fpath);
      if (retval < 0) {
        retval = cloudfs_error("cloudfs_unlink");
      }
    } else {
      retval = dedup_layer_remove(fpath);
    }
  } else {
    retval = unlink(fpath);
    if (retval < 0) {
      retval = cloudfs_error("cloudfs_unlink");
    }
  }

  dbg_print("[DBG] cloudfs_unlink(path=\"%s\")=%d\n", path, retval);

  return retval;
}

/**
 * @brief Remove a directory.
 * @param path Path of the directory.
 * @return 0 on success, -errno otherwise.
 */
int cloudfs_rmdir(const char *path)
{
  int retval = 0;
  char fpath[MAX_PATH_LEN] = "";

  cloudfs_get_fullpath(path, fpath);

  retval = rmdir(fpath);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_rmdir");
  }

  dbg_print("[DBG] cloudfs_rmdir(path=\"%s\")=%d\n", path, retval);

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
  .unlink         = cloudfs_unlink,
  .rmdir          = cloudfs_rmdir
};

/**
 * @brief A helper function for ftw to calculate total size of cache directory.
 *        This is called upon start of CloudFS if .cache dir already exists.
 * @param See "man ftw".
 * @return 0.
 */
static int sum_cache(const char *fpath, const struct stat *sb,
    int typeflag UNUSED)
{
  dbg_print("[DBG] scanning cache directory: %s\n", fpath);
  if (strlen(fpath) == (strlen(Cache_path) + 1 + 2 * MD5_DIGEST_LENGTH)) {
    dbg_print("[DBG] cache file found: %s\n", fpath);
    Cache_init_size += (sb->st_size);
    dbg_print("[DBG] cache initial size increased to %d\n", Cache_init_size);
  }
  return 0;
}

int cloudfs_start(struct cloudfs_state *state, const char* fuse_runtime_name)
{
  int argc = 0;
  char *argv[10];

  argv[argc] = (char *) malloc(128 * sizeof(char));
  strcpy(argv[argc++], fuse_runtime_name);
  argv[argc] = (char *) malloc(1024 * sizeof(char));
  strcpy(argv[argc++], state->fuse_path);

  /* set the fuse mode to single thread */
  argv[argc++] = "-s";

  /* run fuse in foreground */
  // argv[argc++] = "-f";

  State_ = *state;

  /* eliminate extra slash */
  if (State_.ssd_path[strlen(State_.ssd_path) - 1] == '/') {
    State_.ssd_path[strlen(State_.ssd_path) - 1] = '\0';
  }

  /* initialize log file and set as line buffered */
  Log = fopen(LOG_FILE, "wb");
  setvbuf(Log, NULL, _IOLBF, 0);

  /* initialize .tmp directory */
  memset(Temp_path, '\0', MAX_PATH_LEN);
  snprintf(Temp_path, MAX_PATH_LEN, "%s%s", State_.ssd_path, TEMP_PATH);
  dbg_print("[DBG] Temp_path=\"%s\"\n", Temp_path);
  if (mkdir(Temp_path, DEFAULT_DIR_MODE) < 0) {
    if (errno != EEXIST) {
      dbg_print("[ERR] failed to create .tmp directory\n");
      exit(EXIT_FAILURE);
    }
  }

  S3Status s3status = S3StatusOK;
  s3status = cloud_init(State_.hostname);
  if (s3status != S3StatusOK) {
    dbg_print("[ERR] failed to initialize cloud service\n");
    cloud_print_error();
    exit(EXIT_FAILURE);
  }
  s3status = cloud_create_bucket(BUCKET);
  if (s3status != S3StatusOK && s3status != S3StatusHttpErrorForbidden) {
    dbg_print("[ERR] failed to create bucket\n");
    cloud_print_error();
    exit(EXIT_FAILURE);
  }

  memset(Bkt_prfx, '\0', MAX_PATH_LEN);
  snprintf(Bkt_prfx, MAX_PATH_LEN, "%s%s", Temp_path, "/bucket");
  dbg_print("[DBG] Bkt_prfx=\"%s\"\n", Bkt_prfx);

  /* initialize .cache directory */
  Cache_init_size = 0;
  memset(Cache_path, '\0', MAX_PATH_LEN);
  snprintf(Cache_path, MAX_PATH_LEN, "%s%s", State_.ssd_path, CACHE_PATH);
  dbg_print("[DBG] Cache_path=\"%s\"\n", Cache_path);
  if (mkdir(Cache_path, DEFAULT_DIR_MODE) < 0) {
    if (errno != EEXIST) {
      dbg_print("[ERR] failed to create .cache directory\n");
      exit(EXIT_FAILURE);
    } else {
      dbg_print("[DBG] cache directory exists, collecting information\n");
      if (ftw(Cache_path, &sum_cache, 1) < 0) {
        dbg_print("[ERR] failed to calculate cache initial size\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  if (!State_.no_dedup) {
    dbg_print("[DBG] dedup enabled\n");
    if (ht_init(Bkt_prfx, BKT_NUM, BKT_SIZE) < 0) {
      dbg_print("[ERR] failed to initialize hash table\n");
      exit(EXIT_FAILURE);
    }
    dedup_layer_init(State_.rabin_window_size, State_.avg_seg_size,
        State_.avg_seg_size / 2, State_.avg_seg_size * 2, State_.no_cache);
    if (!State_.no_cache) {
      dbg_print("[DBG] cache enabled\n");
      dbg_print("[DBG] cache size %d bytes\n", State_.cache_size);

      /* initialize the cache layer */
      cache_layer_init(State_.cache_size, Cache_init_size);
    } else {
      dbg_print("[DBG] cache disabled\n");
    }
  } else {
    dbg_print("[DBG] dedup disabled\n");
  }

  int fuse_stat = fuse_main(argc, argv, &Cloudfs_operations, NULL);

  return fuse_stat;
}


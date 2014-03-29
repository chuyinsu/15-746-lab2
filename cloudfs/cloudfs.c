/**
 * @file cloudfs.c
 * @brief 15-746 Spring 2014 Project 2 - Hybrid Cloud Storage System
 * @author Yinsu Chu (yinsuc)
 */

#define _XOPEN_SOURCE 500 /* for blksize_t */

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

static struct cloudfs_state state_;

/**
 * @brief Check whether a file is stored in the cloud.
 *        This is marked by extended attribute "user.remote".
 * @param fpath Full path of the file on SSD. 
 * @return 1 if is in the cloud, 0 otherwise.
 */
static int cloudfs_is_in_cloud(char *fpath)
{
  int retval = 0;
  lgetxattr(fpath, "user.remote", &retval, sizeof(int));
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
  snprintf(fullpath, MAX_PATH_LEN, "%s%s", state_.ssd_path, path);
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
 * @brief Initializes the FUSE file system (cloudfs) by checking
 *        if the mount points are valid, and if all is well,
 *        it mounts the file system ready for usage.
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
  cloud_init(state_.hostname);
  return NULL;
}

void cloudfs_destroy(void *data UNUSED) {
  cloud_destroy();
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
    if (lstat(fpath, sb) < 0) {
      retval = cloudfs_error(fn);
    }
  }

  dbg_print("[DBG] cloudfs_getattr(path=\"%s\", sb=0x%08x)=%d\n",
      path, (unsigned int)sb, retval);


  return retval;
}

/**
 * @brief Get extended attributes.
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
      "size=%d)=%d", path, name, value, size, retval);

  return retval;
}

/**
 * @brief Set extended attributes.
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

/*
 * Functions supported by cloudfs 
 */
static 
struct fuse_operations cloudfs_operations = {
  .init           = cloudfs_init,
  //
  // TODO
  //
  // This is where you add the VFS functions that your implementation of
  // MelangsFS will support, i.e. replace 'NULL' with 'melange_operation'
  // --- melange_getattr() and melange_init() show you what to do ...
  //
  // Different operations take different types of parameters. This list can
  // be found at the following URL:
  // --- http://fuse.sourceforge.net/doxygen/structfuse__operations.html
  //
  //
  .getattr        = cloudfs_getattr,
  .getxattr       = cloudfs_getxattr,
  .setxattr       = cloudfs_setxattr,
  .mkdir          = NULL,
  .readdir        = NULL,
  .destroy        = cloudfs_destroy
};

int cloudfs_start(struct cloudfs_state *state,
    const char* fuse_runtime_name) {

  int argc = 0;
  char* argv[10];
  argv[argc] = (char *) malloc(128 * sizeof(char));
  strcpy(argv[argc++], fuse_runtime_name);
  argv[argc] = (char *) malloc(1024 * sizeof(char));
  strcpy(argv[argc++], state->fuse_path);
  argv[argc++] = "-s"; // set the fuse mode to single thread
  //argv[argc++] = "-f"; // run fuse in foreground 

  state_  = *state;

  int fuse_stat = fuse_main(argc, argv, &cloudfs_operations, NULL);

  return fuse_stat;
}

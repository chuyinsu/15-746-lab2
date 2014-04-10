#define _GNU_SOURCE

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "cloudapi.h"
#include "cloudfs.h"
#include "hashtable.h"
#include "dedup.h"

extern FILE *Log;
static rabinpoly_t *rp;

/* callback function for downloading from the cloud */
static FILE *Tfile; /* temporary file */
static int get_buffer(const char *buf, int len) {
  return fwrite(buf, 1, len, Tfile);
}

/* callback function for uploading to the cloud */
static FILE *Cfile; /* cloud file */
static int put_buffer(char *buf, int len) {
  return fread(buf, 1, len, Cfile);
}

/**
 * @brief Initialize the dedup layer.
 * @param Parameters required to initialize Rabin Fingerprinting library.
 * @return 0 on success, -1 otherwise.
 */
int dedup_layer_init(int window_size, int avg_seg_size, int min_seg_size,
    int max_seg_size)
{
  rp = rabin_init(window_size, avg_seg_size, min_seg_size, max_seg_size);
  if (rp == NULL) {
    return -1;
  } else {
    return 0;
  }
}

/**
 * @brief Read part of a segment from a cache directory.
 *        For now it's part 2, so this "cache" has nothing to
 *        do with part 3. In part 2 design, each cloud file has
 *        its own cache directory to save segments downloaded
 *        from the cloud. This function first searches in the
 *        cache directory to see whether the segment has already
 *        been downloaded; if not, it downloads the segment;
 *        then it reads the segment.
 * @param cache_dir The temporary directory to save segments. Its
 *                  size should be MAX_PATH_LEN.
 * @param segp The segment to read.
 * @param buf The buffer to hold the returned data.
 * @param size Size of the buffer.
 * @param offset The offset into the segment to start reading.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_read_seg(char *cache_dir, struct cloudfs_seg *segp, char *buf,
    int size, int offset)
{
  int retval = 0;
  DIR *dir = NULL;
  struct dirent *ent = NULL;
  int found = 0;

  char key[MD5_DIGEST_LENGTH + 1] = "";
  memcpy(key, segp->md5, MD5_DIGEST_LENGTH);
  dbg_print("[DBG] cloud key is %s\n", key);

  char tpath[MAX_PATH_LEN] = "";
  snprintf(tpath, MAX_PATH_LEN, "%s/%s", cache_dir, key);
  dbg_print("[DBG] local file path %s\n", tpath);

  dbg_print("[DBG] scanning cache directory %s\n", cache_dir);
  if ((dir = opendir(cache_dir)) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      dbg_print("[DBG] file name %s\n", ent->d_name);
      if (memcmp(segp->md5, ent->d_name, MD5_DIGEST_LENGTH) == 0) {
        dbg_print("[DBG] match found\n");
        found = 1;
        break;
      }
    }
    retval = closedir(dir);
    if (retval < 0) {
      retval = cloudfs_error("dedup_layer_read_seg");
      return retval;
    }
  } else {
    retval = cloudfs_error("dedup_layer_read_seg");
    return retval;
  }

  if (!found) {
    dbg_print("[DBG] match not found\n");

    Tfile = fopen(tpath, "wb");
    cloud_get_object(BUCKET, key, get_buffer);
    cloud_print_error();
    fclose(Tfile);
  }

  int fd = open(tpath, O_RDONLY);
  if (fd < 0) {
    retval = cloudfs_error("dedup_layer_read_seg");
    return retval;
  }

  retval = pread(fd, buf, size, offset);
  if (retval < 0) {
    retval = cloudfs_error("cloudfs_read");
  }

  dbg_print("[DBG] dedup_layer_read_seg(cache_dir=\"%s\","
      " segp=0x%08x, buf=0x%08x, size=%d, offset=%d)=%d\n",
      cache_dir, (unsigned int) segp, (unsigned int) buf, size, offset, retval);

  return retval;
}

/**
 * @brief Delete a file stored in the cloud.
 *        This function iterates through all the segments
 *        in the proxy file and "deletes" them. It also removes
 *        the proxy file.
 * @param fpath Pathname of the file (which should be a proxy file). Its
 *              size should be MAX_PATH_LEN.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_remove(char *fpath)
{
  int retval = 0;

  /* these are parameters required by the getline() function */
  char *seg_md5 = NULL;
  size_t len = 0;
  FILE *proxy_fp = fopen(fpath, "rb");
  if (proxy_fp == NULL) {
    retval = cloudfs_error("dedup_layer_remove");
    return retval;
  }

  /* iterate through all the segments */
  while ((retval = getline(&seg_md5, &len, proxy_fp)) != -1) {
    /* build the segment structure */
    struct cloudfs_seg seg;
    seg.ref_count = 0;
    seg.seg_size = (int) strtol(seg_md5 + MD5_DIGEST_LENGTH + 1, NULL, 10);
    memcpy(seg.md5, seg_md5, MD5_DIGEST_LENGTH);
    if (seg_md5 != NULL) {
      free(seg_md5);
    }
    dbg_print("[DBG] deleting segment\n");
#ifdef DEBUG
    print_seg(&seg);
#endif

    struct cloudfs_seg *found = NULL;
    retval = ht_search(&seg, &found);
    if (retval < 0) {
      return retval;
    }
    dbg_print("[DBG] segment in hash table\n");
#ifdef DEBUG
    print_seg(found);
#endif
    (found->ref_count)--;
    ht_sync(found);
    if (found->ref_count < 0) {
      dbg_print("[ERR] reference counter less than 0\n");
      retval = -EINVAL;
      return retval;
    }
    if (found->ref_count == 0) {
      char key[MD5_DIGEST_LENGTH + 1] = "";
      memcpy(key, seg_md5, MD5_DIGEST_LENGTH);
      cloud_delete_object(BUCKET, key);
      cloud_print_error();
    }
  }

  retval = fclose(proxy_fp);
  if (retval == EOF) {
    retval = cloudfs_error("dedup_layer_remove");
    return retval;
  }

  retval = unlink(fpath);
  if (retval < 0) {
    retval = cloudfs_error("dedup_layer_remove");
    return retval;
  }
  dbg_print("[DBG] proxy file deleted\n");

  dbg_print("[DBG] dedup_layer_remove(fpath=\"%s\")=%d\n", fpath, retval);

  return retval;
}

/**
 * @brief Replace a cloud file with a new version.
 *        To reduce cloud service cost, first calculate the
 *        intersection of segments between the new version and
 *        the old one, then add/delete segments correspondingly.
 *        It also updates the segment list in the proxy file (fpath).
 * @param new_version Pathname of the new version of the file. Its size
 *                    should be MAX_PATH_LEN.
 * @param fpath Pathname of the file (which should be a proxy file). Its
 *              size should be MAX_PATH_LEN.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_replace(char *new_version, char *fpath)
{
  (void) new_version;
  (void) fpath;
  return 0;
}

/**
 * @brief Upload a big file into the cloud.
 *        This function uses the provided Rabin Fingerprinting library
 *        to calculate segments of a file and then upload them. It also
 *        updates the original file to be a proxy file.
 * @param fpath Pathname of the file.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_upload(char *fpath)
{
  (void) fpath;
  return 0;
}


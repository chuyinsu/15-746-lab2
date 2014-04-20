/**
 * @file dedup_layer.c
 * @brief Dedup layer of CloudFS.
 * @author Yinsu Chu (yinsuc)
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "cloudfs.h"
#include "cloudapi.h"
#include "hashtable.h"
#include "dedup.h"
#include "compress_layer.h"
#include "cache_layer.h"

#define BUF_LEN (1024)

extern FILE *Log;
static rabinpoly_t *Rp;
static unsigned int Window_size;
static unsigned int Avg_seg_size;
static unsigned int Min_seg_size;
static unsigned int Max_seg_size;
static int Cache_disabled;

void dedup_layer_get_key(unsigned char *md5, char *key);

/**
 * @brief A helper function to dedup_layer_segmentation.
 *        It allocates memory for newly found segments.
 * @param num_seg Number of segments is updated here.
 * @param segs Segments are updated here.
 * @param segment_len The length of the new segment.
 * @param md5 The MD5 of the new segment.
 * @return 0 on success, -errno otherwise.
 */
static int dedup_layer_update_segments(int *num_seg, struct cloudfs_seg **segs,
    int segment_len, char *md5)
{
  int retval = 0;
  dbg_print("[DBG] new segment found\n");

  int old_size = (*num_seg) * sizeof(struct cloudfs_seg);
  dbg_print("[DBG] old size is %d * %d = %d\n",
      *num_seg, sizeof(struct cloudfs_seg), old_size);

  (*num_seg)++;
  int new_size = (*num_seg) * sizeof(struct cloudfs_seg);
  dbg_print("[DBG] new size is %d * %d = %d\n",
      *num_seg, sizeof(struct cloudfs_seg), new_size);

  struct cloudfs_seg *enlarge =
    (struct cloudfs_seg *) realloc((*segs), new_size);
  if (enlarge == NULL) {
    retval = cloudfs_error("dedup_layer_update_segments");
    return retval;
  } else {
    (*segs) = enlarge;
  }
  dbg_print("[DBG] memory (re-)allocated\n");

  struct cloudfs_seg *new_seg = (struct cloudfs_seg *)
    ((char *) (*segs) + old_size);
  new_seg->ref_count = 0;
  new_seg->seg_size = segment_len;
  memset(new_seg->md5, '\0', 2 * MD5_DIGEST_LENGTH + 1);
  memcpy(new_seg->md5, md5, 2 * MD5_DIGEST_LENGTH);
#ifdef DEBUG
  print_seg(new_seg);
#endif

  return retval;
}

/**
 * @brief Cut a file into segments.
 *        Reference: dedup-lib/rabin-example.c in the provided code.
 * @param fpath Pathname of the file. It should have MAX_PATH_LEN bytes.
 * @param num_seg Return the number of segments here.
 * @param segs Return the array of segments here. It must be freed
 *             by the caller of this function.
 * @return 0 on success, -1 otherwise.
 */
static int dedup_layer_segmentation(char *fpath, int *num_seg,
    struct cloudfs_seg **segs)
{
  int retval = 0;

  int fd = open(fpath, O_RDONLY);
  if (fd < 0) {
    retval = cloudfs_error("dedup_layer_segmentation");
    return retval;
  }
  dbg_print("[DBG] segmenting file %s\n", fpath);

  Rp = rabin_init(Window_size, Avg_seg_size, Min_seg_size, Max_seg_size);
  if (Rp == NULL) {
    return -1;
  }

  MD5_CTX ctx;
  unsigned char md5[MD5_DIGEST_LENGTH] = "";
  int new_segment = 0;
  int len = 0;
  int segment_len = 0;
  char buf[BUF_LEN] = "";
  int bytes = 0;

  MD5_Init(&ctx);
  while ((bytes = read(fd, buf, BUF_LEN)) > 0) {
    char *buftoread = (char *) buf;
    while ((len = rabin_segment_next(Rp, buftoread, bytes,
            &new_segment)) > 0) {

      MD5_Update(&ctx, buftoread, len);
      segment_len += len;

      if (new_segment) {
        MD5_Final(md5, &ctx);

        char ch_md5[2 * MD5_DIGEST_LENGTH + 1] = "";
        dedup_layer_get_key(md5, ch_md5);
        retval = dedup_layer_update_segments(num_seg, segs, segment_len,
            ch_md5);
        if (retval < 0) {
          return retval;
        }

        MD5_Init(&ctx);
        segment_len = 0;
      }

      buftoread += len;
      bytes -= len;

      if (bytes <= 0) {
        break;
      }
    }
    if (len == -1) {
      dbg_print("[ERR] failed to process the segment\n");
      return -1;
    }
  }
  MD5_Final(md5, &ctx);

  char ch_md5[2 * MD5_DIGEST_LENGTH + 1] = "";
  dedup_layer_get_key(md5, ch_md5);
  retval = dedup_layer_update_segments(num_seg, segs, segment_len, ch_md5);
  if (retval < 0) {
    return retval;
  }

  rabin_free(&Rp);

  retval = close(fd);
  if (retval < 0) {
    retval = cloudfs_error("dedup_layer_segmentation");
  }

  return retval;
}

/**
 * @brief Initialize the dedup layer.
 * @param Parameters required to initialize Rabin Fingerprinting library.
 * @return 0 on success, -1 otherwise.
 */
void dedup_layer_init(unsigned int window_size, unsigned int avg_seg_size,
    unsigned int min_seg_size, unsigned int max_seg_size, int no_cache)
{
  Window_size = window_size;
  Avg_seg_size = avg_seg_size;
  Min_seg_size = min_seg_size;
  Max_seg_size = max_seg_size;
  Cache_disabled = no_cache;
  dbg_print("[DBG] dedup_layer_init()\n");
}

/**
 * @brief This function should be called when CloudFS exits.
 * @return Void.
 */
void dedup_layer_destroy(void)
{
  dbg_print("[DBG] dedup_layer_destroy()\n");
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
 * @param temp_dir The temporary directory to save segments. Its
 *                  size should be MAX_PATH_LEN.
 * @param segp The segment to read.
 * @param buf The buffer to hold the returned data.
 * @param size Size of the buffer.
 * @param offset The offset into the segment to start reading.
 * @return Size read on success, -errno otherwise.
 */
int dedup_layer_read_seg(char *temp_dir, struct cloudfs_seg *segp, char *buf,
    int size, long offset)
{
  int retval = 0;

  dbg_print("[DBG] cloud key is %s\n", segp->md5);

  char tpath[MAX_PATH_LEN] = "";
  snprintf(tpath, MAX_PATH_LEN, "%s/%s", temp_dir, segp->md5);
  dbg_print("[DBG] local file path %s\n", tpath);

  if (access(tpath, F_OK) < 0) {
    dbg_print("[DBG] segment not found in cache directory\n");
    if (Cache_disabled) {
      retval = compress_layer_download_seg(tpath, segp->md5);
    } else {
      retval = cache_layer_download_seg(tpath, segp->md5);
    }
    if (retval < 0) {
      return retval;
    }
    dbg_print("[DBG] segment downloaded from the cloud\n");
  }

  int fd = open(tpath, O_RDONLY);
  if (fd < 0) {
    retval = cloudfs_error("dedup_layer_read_seg");
    return retval;
  }

  retval = pread(fd, buf, size, offset);
  if (retval < 0) {
    retval = cloudfs_error("dedup_layer_read_seg");
  }

  close(fd);

  dbg_print("[DBG] dedup_layer_read_seg(temp_dir=\"%s\","
      " segp=0x%08x, buf=0x%08x, size=%d, offset=%ld)=%d\n",
      temp_dir, (unsigned int) segp, (unsigned int) buf, size, offset, retval);

  return retval;
}

/**
 * @brief A helper function to convert the numeric MD5 representation
 *        to character MD5 representation.
 * @param md5 The numeric MD5.
 * @param key The character MD5 is returned here. It should have at least
 *            2 * MD5_DIGEST_LENGTH + 1 bytes.
 * @return Void.
 */
void dedup_layer_get_key(unsigned char *md5, char *key)
{
  int i = 0;
  for (i = 0; i < 2 * MD5_DIGEST_LENGTH; i = i + 2) {
    sprintf(key + i, "%02x", md5[i / 2]);
  }
}

/**
 * @brief Add a segment to the cloud.
 *        If the segment is found in hash table, increase ref_count by 1;
 *        Otherwise, upload to cloud and insert into hash table.
 * @param segp The segment to add.
 * @param fpath Pathname of the file. It should have MAX_PATH_LEN bytes.
 * @param offset Offset of the segment in the file.
 * @return 0 on success, -errno otherwise.
 */
static int dedup_layer_add_seg(struct cloudfs_seg *segp, char *fpath,
    long offset)
{
  int retval = 0;

  dbg_print("[DBG] adding segment - offset %ld in file %s\n", offset, fpath);
#ifdef DEBUG
  print_seg(segp);
#endif

  struct cloudfs_seg *found = NULL;
  retval = ht_search(segp, &found);
  if (retval < 0) {
    return retval;
  }

  if (found != NULL) {
    dbg_print("[DBG] segment to add found in hash table\n");
#ifdef DEBUG
    print_seg(found);
#endif
    (found->ref_count)++;
    ht_sync(found);
  } else {
    dbg_print("[DBG] segment to add not found in hash table\n");

    dbg_print("[DBG] cloud key is %s\n", segp->md5);

    /* upload the segment */
    if (Cache_disabled) {
      retval =
        compress_layer_upload_seg(fpath, offset, segp->md5, segp->seg_size);
    } else {
      retval = cache_layer_upload_seg(fpath, offset, segp->md5, segp->seg_size);
    }
    if (retval < 0) {
      return retval;
    }
    dbg_print("[DBG] uploaded to the cloud\n");

    retval = ht_insert(segp);
    if (retval < 0) {
      return retval;
    }
  }

  return retval;
}

/**
 * @brief Remove a segment from the cloud.
 *        If not found in hash table, return;
 *        If found in hash table:
 *          1) Decrease its ref_count by 1;
 *          2) If ref_count becomes 0, delete from cloud.
 * @param segp The segment to remove.
 * @return 0 on success, -errno otherwise.
 */
static int dedup_layer_remove_seg(struct cloudfs_seg *segp)
{
  int retval = 0;

  struct cloudfs_seg *found = NULL;
  retval = ht_search(segp, &found);
  if (retval < 0) {
    return retval;
  }

  if (found != NULL) {
    dbg_print("[DBG] segment to remove found in hash table\n");
#ifdef DEBUG
    print_seg(found);
#endif
    (found->ref_count)--;
    ht_sync(found);
    if (found->ref_count == 0) {
      if (Cache_disabled) {
        cloud_delete_object(BUCKET, segp->md5);
        cloud_print_error();
      } else {
        cache_layer_remove_seg(segp->md5);
      }
    }
  } else {
    dbg_print("[DBG] segment to remove not found in hash table\n");
  }

  dbg_print("[DBG] dedup_layer_remove_seg(segp=0x%08x)=%d\n",
      (unsigned int) segp, retval);

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
    seg.seg_size = (int) strtol(seg_md5 + 2 * MD5_DIGEST_LENGTH + 1, NULL, 10);
    memset(seg.md5, '\0', 2 * MD5_DIGEST_LENGTH + 1);
    memcpy(seg.md5, seg_md5, 2 * MD5_DIGEST_LENGTH);
    if (seg_md5 != NULL) {
      free(seg_md5);
      seg_md5 = NULL;
      len = 0;
    }
    dbg_print("[DBG] next segment in proxy file\n");
#ifdef DEBUG
    print_seg(&seg);
#endif

    retval = dedup_layer_remove_seg(&seg);
    if (retval < 0) {
      return retval;
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
 * @brief Upload a big file into the cloud.
 *        It also updates the original file to be a proxy file.
 * @param fpath Pathname of the file.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_upload(char *fpath)
{
  int retval = 0;

  /* segment the file */
  int num_seg = 0;
  struct cloudfs_seg *segs = NULL;

  retval = dedup_layer_segmentation(fpath, &num_seg, &segs);
  dbg_print("[DBG] file %s segmented to %d segments\n", fpath, num_seg);

  /* create a temporary proxy file to record the segments */
  char proxy_tmp[MAX_PATH_LEN] = "";
  snprintf(proxy_tmp, MAX_PATH_LEN, "%s.tmp", fpath);

  FILE *proxy_fp = fopen(proxy_tmp, "wb");
  if (proxy_fp == NULL) {
    retval = cloudfs_error("dedup_layer_upload");
    return retval;
  }
  dbg_print("[DBG] temporary proxy file is %s\n", proxy_tmp);

  int i = 0;
  long offset = 0;
  for (i = 0; i < num_seg; i++) {
    dbg_print("[DBG] segment offset %ld\n", offset);
    fprintf(proxy_fp, "%s-%ld\n", segs[i].md5, segs[i].seg_size);
    dbg_print("[DBG] segment added to proxy file\n");
#ifdef DEBUG
    print_seg(&(segs[i]));
#endif
    segs[i].ref_count = 1;
    retval = dedup_layer_add_seg(&(segs[i]), fpath, offset);
    if (retval < 0) {
      return retval;
    }
    offset += segs[i].seg_size;
  }
  fclose(proxy_fp);
  free(segs);

  /* delete the original file */
  retval = unlink(fpath);
  if (retval < 0) {
    retval = cloudfs_error("dedup_layer_upload");
    return retval;
  }
  dbg_print("[DBG] old proxy file removed\n");

  /* rename the proxy file to the original file's name */
  retval = rename(proxy_tmp, fpath);
  if (retval < 0) {
    retval = cloudfs_error("dedup_layer_upload");
    return retval;
  }
  dbg_print("[DBG] temporary proxy file renamed\n");

  dbg_print("[DBG] dedup_layer_upload(fpath=\"%s\")=%d\n", fpath, retval);

  return retval;
}


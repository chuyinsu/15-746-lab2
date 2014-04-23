/**
 * @file cache_layer.c
 * @brief Cache layer of CloudFS.
 * @author Yinsu Chu (yinsuc)
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "cloudfs.h"
#include "cloudapi.h"
#include "compress_layer.h"
#include "hashtable.h"

#define U_TIMESTAMP ("user.timestamp")

#define CANNOT_EVICT (100)
#define NO_MORE_SEGS (200)

extern FILE *Log;
extern char Cache_path[MAX_PATH_LEN];

static long Total_space;
static long Remaining_space;

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
 * @brief CloudFS should call this function upon starting.
 * @param no_cache The --no-cache argument passed to CloudFS.
 * @param space The --cache-size argument passed to CloudFS.
 * @return 0 on success (always 0 for now).
 */
int cache_layer_init(int total_space, int init_space)
{
  Total_space = total_space;
  Remaining_space = total_space - init_space;

  dbg_print("[DBG] cache_layer_init(), total %ld bytes, used %d bytes,"
      " remaining %ld bytes\n", Total_space, init_space, Remaining_space);

  return 0;
}

/**
 * @brief Update a cache file with current timestamp.
 *        The timestamp is saved as an extended attribute.
 * @param cache_file Pathname of the cache file. It should have
 *        MAX_PATH_LEN bytes.
 * @return 0 on success, negative otherwise.
 */
int update_timestamp(char *cache_file)
{
  int retval = 0;

  struct timespec ts;
  retval = clock_gettime(CLOCK_REALTIME, &ts);
  if (retval < 0) {
    retval = cloudfs_error("update_timestamp");
    return retval;
  }
  retval = lsetxattr(cache_file, U_TIMESTAMP, &ts, sizeof(struct timespec), 0);
  if (retval < 0) {
    retval = cloudfs_error("update_timestamp");
    return retval;
  }

  dbg_print("cache file %s timestamp updated to %ld sec %ld nsec\n",
      cache_file, ts.tv_sec, ts.tv_nsec);

  dbg_print("[DBG] update_timestamp(cache_file=\"%s\")=%d\n",
      cache_file, retval);

  return retval;
}

/**
 * @brief Traverse the cache directory, find the least ref_count value.
 *        "num_evicted" number of segments in "evicted" and the
 *        "found" segment are ignored.
 * @param num_evicted Number of segments in "evicted".
 * @param evicted Array of segments to ignore.
 * @param found Segment to ignore.
 * @param least_ref_count Return the result here.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_find_least_ref_count(int num_evicted,
    struct cloudfs_seg *evicted, struct cloudfs_seg *found,
    int *least_ref_count)
{
  (void) num_evicted;
  (void) evicted;
  (void) found;
  (void) least_ref_count;
  return 0;
}

/**
 * @brief Traverse the cache directory, get the oldest seg with given ref_count.
 *        "num_evicted" number of segments in "evicted" and the
 *        "found" segment are ignored.
 * @param num_evicted Number of segments in "evicted".
 * @param evicted Array of segments to ignore.
 * @param found Segment to ignore.
 * @param least_ref_count Target ref_count to match.
 * @param next_evict Copy and return the qualified segment here.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_find_oldest_seg(int num_evicted, struct cloudfs_seg *evicted,
    struct cloudfs_seg *found, int least_ref_count,
    struct cloudfs_seg *next_evict)
{
  (void) num_evicted;
  (void) evicted;
  (void) found;
  (void) least_ref_count;
  (void) next_evict;
  return 0;
}

/**
 * @brief Evict segments according to the cache eviction algorithm.
 *        This is called when Remaining_space is less than zero and its purpose
 *        is to evict segments to make Remaining_space above or equal to zero.
 *        The algorithm works like this:
 *          1) First evict the least referenced segments (less than ref_count of
 *             "keep"). Use timestamp to break ties (LRU).
 *          2) If "keep" has a least referenced count,
 *             evict based on timestamp (LRU).
 *          3) If "keep" is the ONLY segment with the least referenced count,
 *             return CANNOT_EVICT to indicate no segments can be evicted.
 *        Upon successful evition, this function should upload all
 *        evicted segments to the cloud, delete the copies in the cache and
 *        updates the global Remaining_space variable.
 * @param keep The segment struct of the segment causing the eviction.
 *             This segment should not be evicted.
 * @return 0 on success, CANNOT_EVICT if not segments can be evicted,
 *         negative otherwise.
 */
int cache_layer_evict_segments(struct cloudfs_seg *keep)
{
  int retval = 0;
  long remaining_space = Remaining_space;

  dbg_print("[DBG] making space for this segment:\n");
#ifdef DEBUG
  print_seg(keep);
#endif

  /* search for "keep" in the hash table,
   * save the result in "found" */
  struct cloudfs_seg *found = NULL;
  retval = ht_search(keep, &found);
  if (retval < 0) {
    return retval;
  }
  if (found != NULL) {
    dbg_print("[DBG] segment found in hash table\n");
  } else {
    dbg_print("[ERR] segment not found in hash table\n");
  }

  int num_evicted = 0;
  struct cloudfs_seg *evicted = NULL;
  struct cloudfs_seg next_evict;

  while (remaining_space < 0) {

    /* traverse the cache directory, find the least ref_count value,
     * excluding segments in "evicted" and the "found" segment */
    int least_ref_count = 0;
    retval = cache_layer_find_least_ref_count(num_evicted, evicted, found,
        &least_ref_count);
    if (retval < 0) {
      return retval;
    }
    dbg_print("[DBG] least reference count value is %d\n", least_ref_count);

    if (least_ref_count == NO_MORE_SEGS
        || (least_ref_count > (found->ref_count))) {

      /* failed to evict */
      if (evicted != NULL) {
        free(evicted);
      }
      return CANNOT_EVICT;

    } else {

      /* traverse the cache directory,
       * find the oldest segment with least_ref_count,
       * excluding segments in "evicted" and the "found" segment */
      retval = cache_layer_find_oldest_seg(num_evicted, evicted, found,
          least_ref_count, &next_evict);
      if (retval < 0) {
        return retval;
      }
      dbg_print("[DBG] next segment to evict is:\n");
#ifdef DEBUG
      print_seg(&next_evict);
#endif
    }

    /* add the newly found segment to "evicted" */
    int old_size = num_evicted * sizeof(struct cloudfs_seg);
    dbg_print("[DBG] old size is %d * %d = %d\n",
        num_evicted, sizeof(struct cloudfs_seg), old_size);

    num_evicted++;

    int new_size = num_evicted * sizeof(struct cloudfs_seg);
    dbg_print("[DBG] new size is %d * %d = %d\n",
        num_evicted, sizeof(struct cloudfs_seg), new_size);

    struct cloudfs_seg *enlarge =
      (struct cloudfs_seg *) realloc(evicted, new_size);
    if (enlarge == NULL) {
      retval = cloudfs_error("cache_layer_evict_segments");
      return retval;
    } else {
      evicted = enlarge;
    }
    dbg_print("[DBG] memory (re-)allocated\n");

    struct cloudfs_seg *new_evicted = (struct cloudfs_seg *)
      ((char *) evicted + old_size);
    new_evicted->ref_count = next_evict.ref_count;
    new_evicted->seg_size = next_evict.seg_size;
    memset(new_evicted->md5, '\0', 2 * MD5_DIGEST_LENGTH + 1);
    memcpy(new_evicted->md5, next_evict.md5, 2 * MD5_DIGEST_LENGTH);
    dbg_print("[DBG] next segment to evict added to array\n");

    remaining_space += (next_evict.seg_size);
    dbg_print("[DBG] remaining space increased to %ld\n", remaining_space);
  }

  /* evict selected segments to the cloud */
  int i = 0;
  for (i = 0; i < num_evicted; i++) {

    char cache_file[MAX_PATH_LEN] = "";
    sprintf(cache_file, "%s/%s", Cache_path, evicted[i].md5);

    /* get compressed segment length */
    struct stat sb;
    retval = lstat(cache_file, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_evict_segments");
      return retval;
    }
    dbg_print("[DBG] length of compressed segment is %llu\n", sb.st_size);

    /* upload the segment */
    Cfile = fopen(cache_file, "rb");
    cloud_put_object(BUCKET, evicted[i].md5, sb.st_size, put_buffer);
    cloud_print_error();
    fclose(Cfile);
    dbg_print("[DBG] segment %s uploaded\n", cache_file);

    /* delete the segment in cache */
    retval = remove(cache_file);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_evict_segments");
      return retval;
    }
    dbg_print("[DBG] cache file %s deleted\n", cache_file);
  }

  if (evicted != NULL) {
    free(evicted);
  }

  Remaining_space = remaining_space;
  dbg_print("[DBG] global Remaining_space increased to %ld\n", Remaining_space);

  return retval;
}

/**
 * @brief Download a segment through the cache layer.
 *        This function will first search for the segment in the cache.
 *        If found, decompress directly from the cache directory.
 *        If not found:
 *          1) If cache directory has enough space, download it to cache.
 *          2) Otherwise, start cache eviction algorithm.
 * @param target_file Local pathname of the file to download/decompress to.
 * @param segp Pointer to the segment struct of the segment to download.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_download_seg(char *target_file, struct cloudfs_seg *segp)
{
  int retval = 0;
  int evict_failed = 0;

  char cache_file[MAX_PATH_LEN] = "";
  sprintf(cache_file, "%s/%s", Cache_path, segp->md5);
  dbg_print("[DBG] download segment through the cache layer: %s\n", cache_file);
#ifdef DEBUG
  print_seg(segp);
#endif

  if (access(cache_file, F_OK) < 0) {
    dbg_print("[DBG] segment not found in cache\n");

    /* download to cache directory */
    Tfile = fopen(cache_file, "wb");
    cloud_get_object(BUCKET, segp->md5, get_buffer);
    cloud_print_error();
    fclose(Tfile);
    dbg_print("[DBG] segment downloaded as %s\n", cache_file);

    /* update remaining space */
    struct stat sb;
    retval = lstat(cache_file, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_download_seg");
      return retval;
    }
    Remaining_space -= (sb.st_size);
    dbg_print("[DBG] segment size is %llu\n", sb.st_size);
    dbg_print("[DBG] remaining space decreases to %ld\n", Remaining_space);

    /* start cache eviction algorithm if needed */
    if (Remaining_space < 0) {
      dbg_print("[DBG] remaining space less than zero, starting eviction\n");
      retval = cache_layer_evict_segments(segp);
      if (retval == CANNOT_EVICT) {
        dbg_print("[DBG] cannot evict any segments\n");
        Remaining_space += (sb.st_size);
        dbg_print("[DBG] remaining space restored to %ld\n", Remaining_space);
        evict_failed = 1;
      } else if (retval < 0) {
        return retval;
      } else {
        dbg_print("[DBG] eviction succeeded\n");

        /* delete from cloud */
        cloud_delete_object(BUCKET, segp->md5);
        cloud_print_error();
      }
    } else {
      /* Remaining space is enough, no need of eviction */
      dbg_print("[DBG] remaining space is enough\n");

      /* delete from cloud */
      cloud_delete_object(BUCKET, segp->md5);
      cloud_print_error();
    }
  } else {
    dbg_print("[DBG] segment found in cache\n");
  }

  retval = compress_layer_decompress(cache_file, target_file);
  if (retval < 0) {
    return retval;
  }

  if (evict_failed) {
    retval = remove(cache_file);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_download_seg");
      return retval;
    }
  } else {
    retval = update_timestamp(cache_file);
    if (retval < 0) {
      return retval;
    }
  }

  dbg_print("[DBG] cache_layer_download_seg(target_file=\"%s\","
      " segp=0x%08x)=%d\n", target_file, (unsigned int) segp, retval);

  return retval;
}

/**
 * @brief Upload a segment through the cache layer.
 *        If there is enough cache space, this function will not actually
 *        upload the segment to the cloud. This saves cost when later we need
 *        to download this segment (just get it from the cache directory).
 *        Otherwise (not enough space in the cache directory), upload to cloud.
 * @param fpath Pathname of the entire file.
 * @param offset Offset of the segment into the file.
 * @param key Cloud key of the segment.
 * @param len Length of the segment.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_upload_seg(char *fpath, long offset, char *key, long len)
{
  int retval = 0;

  char cache_file[MAX_PATH_LEN] = "";
  sprintf(cache_file, "%s/%s", Cache_path, key);
  dbg_print("[DBG] upload segment through the cache layer: %s\n", cache_file);

  long len_compressed_file =
    compress_layer_compress(fpath, offset, len, cache_file);
  if (len_compressed_file < 0) {
    return len_compressed_file;
  }

  if (Remaining_space < len_compressed_file) {
    dbg_print("[DBG] remaining space is %ld, not enough to hold the segment,"
        " uploading to the cloud\n", Remaining_space);

    Cfile = fopen(cache_file, "rb");
    cloud_put_object(BUCKET, key, len_compressed_file, put_buffer);
    cloud_print_error();
    fclose(Cfile);

    retval = remove(cache_file);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_upload_seg");
      return retval;
    }
  } else {
    dbg_print("[DBG] remaining space is %ld, enough to hold the segment\n",
        Remaining_space);
    retval = update_timestamp(cache_file);
    if (retval < 0) {
      return retval;
    }
    Remaining_space -= len_compressed_file;
    dbg_print("[DBG] remaining space decreased to %ld\n", Remaining_space);
  }

  dbg_print("[DBG] cache_layer_upload_seg(fpath=\"%s\", offset=%ld, key=\"%s\","
      " len=%ld)=%d", fpath, offset, key, len, retval);

  return retval;
}

/**
 * @brief Remove a segment through the cache layer.
 *        This function will first search for the segment in the cache,
 *        if exist, remove from the cache; otherwise remove from the cloud.
 * @param key Cloud key of the segment.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_remove_seg(char *key)
{
  int retval = 0;

  char cache_file[MAX_PATH_LEN] = "";
  sprintf(cache_file, "%s/%s", Cache_path, key);
  dbg_print("[DBG] remove segment through the cache layer: %s\n", cache_file);

  if (access(cache_file, F_OK) < 0) {
    dbg_print("[DBG] segment not found in cache\n");
    cloud_delete_object(BUCKET, key);
    cloud_print_error();
  } else {
    dbg_print("[DBG] segment found in cache\n");
    struct stat sb;
    retval = lstat(cache_file, &sb);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_remove_seg");
      return retval;
    }
    retval = remove(cache_file);
    if (retval < 0) {
      retval = cloudfs_error("cache_layer_remove_seg");
      return retval;
    }
    Remaining_space += sb.st_size;
    dbg_print("[DBG] remaining space increased to %ld\n", Remaining_space);
  }

  dbg_print("[DBG] cache_layer_remove_seg(key=\"%s\")=%d", key, retval);

  return retval;
}


/**
 * @file cache_layer.c
 * @brief Cache layer of CloudFS.
 * @author Yinsu Chu (yinsuc)
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "cloudfs.h"
#include "cloudapi.h"
#include "compress_layer.h"

extern FILE *Log;
extern char Cache_path[MAX_PATH_LEN];

static long Total_space;
static long Remaining_space;

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
 * @brief Download a segment through the cache layer.
 *        This function will first search for the segment in the cache.
 *        If found, copy directly from the cache directory.
 *        If not found:
 *          1) If cache directory has enough space, download to cache.
 *          2) Otherwise, start cache eviction algorithm.
 * @param target_file Local pathname of the file to download to.
 * @param key The key of the cloud file. It should have
 *            MD5_DIGEST_LENGTH bytes.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_download_seg(char *target_file, char *key)
{
  int retval = 0;

  char cache_file[MAX_PATH_LEN] = "";
  sprintf(cache_file, "%s/%s", Cache_path, key);
  dbg_print("[DBG] download segment through the cache layer: %s\n", cache_file);

  if (access(cache_file, F_OK) < 0) {
    dbg_print("[DBG] segment not found in cache\n");
    retval = compress_layer_download_seg(target_file, key);
  } else {
    dbg_print("[DBG] segment found in cache\n");
    retval = compress_layer_decompress(cache_file, target_file);
  }

  dbg_print("[DBG] cache_layer_download_seg(target_file=\"%s\","
      " key=\"%s\")=%d\n", target_file, key, retval);

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


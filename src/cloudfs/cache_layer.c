/**
 * @file cache_layer.c
 * @brief Cache layer of CloudFS.
 * @author Yinsu Chu (yinsuc)
 */

#include "cloudfs.h"
#include "cloudapi.h"
#include "compress_layer.h"

/**
 * @brief Download a segment through the cache layer.
 *        This function will first search for the segment in the cache,
 *        if not found, download it from the cloud.
 * @param target_file Local pathname of the file to download to.
 * @param key The key of the cloud file. It should have
 *            MD5_DIGEST_LENGTH bytes.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_download_seg(char *target_file, char *key)
{
  return compress_layer_download_seg(target_file, key);
}

/**
 * @brief Upload a segment through the cache layer.
 *        If there is enough cache space, this function will not actually
 *        upload the segment to the cloud. This saves cost when later we need
 *        to download this segment (just get it from the cache directory).
 *        Otherwise (not enough space in the cache directory),
 *        employ the cache eviction policy.
 * @param fpath Pathname of the entire file.
 * @param offset Offset of the segment into the file.
 * @param key Cloud key of the segment.
 * @param len Length of the segment.
 * @return 0 on success, negative otherwise.
 */
int cache_layer_upload_seg(char *fpath, long offset, char *key, long len)
{
  return compress_layer_upload_seg(fpath, offset, key, len);
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
  cloud_delete_object(BUCKET, key);
  cloud_print_error();
  return 0;
}


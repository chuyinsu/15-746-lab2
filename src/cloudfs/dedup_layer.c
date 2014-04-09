#include "cloudfs.h"

/**
 * @brief Read part of a segment from a cache directory.
 *        For now it's part 2, so this "cache" has nothing to
 *        do with part 3. In part 2 design, each cloud file has
 *        its own cache directory to save segments downloaded
 *        from the cloud.
 *        This function first search in the cache directory to see
 *        whether the segment has already been downloaded; if not,
 *        it downloads the segment; then it reads the segment.
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
  (void) cache_dir;
  (void) segp;
  (void) buf;
  (void) size;
  (void) offset;
  return 0;
}

/**
 * @brief Delete a file stored in the cloud.
 *        This function iterates through all the segments
 *        in the proxy file and deletes them. It also removes
 *        the proxy file.
 * @param fpath Pathname of the file (which should be a proxy file). Its
 *              size should be MAX_PATH_LEN.
 * @return 0 on success, -errno otherwise.
 */
int dedup_layer_remove(char *fpath)
{
  (void) fpath;
  return 0;
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


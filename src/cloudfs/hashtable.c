/**
 * @file hashtable.c
 * @brief A persistent hash table implementation. Each bucket in the hash table
 *        is a file, and all buckets are mmap-ed upon file system starting.
 *        Any changes to the hash table is made first in the memory region
 *        of the file and then msync-ed to disk. Inside each bucket, there are
 *        multiple slots where one slot can hold one cloudfs_seg structure.
 *        When all slots in a bucket are used up, this bucket will be enlarged
 *        to be twice the previous size.
 * @author Yinsu Chu (yinsuc)
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "cloudfs.h"

static char Bkt_prfx[MAX_PATH_LEN];
static int Bkt_num;
static int Bkt_size;

extern FILE *Log;

/* store the mmap addresses of each bucket file */
static void **Buckets;

#ifdef DEBUG
void print_seg(struct cloudfs_seg *segp)
{
  int i = 0;
  dbg_print("[DBG] print segment 0x%08x\n", (unsigned int) segp);
  dbg_print("      ref_count=%d\n", segp->ref_count);
  dbg_print("      seg_size=%d\n", segp->seg_size);
  dbg_print("      md5=");
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    dbg_print("%02x", segp->md5[i]);
  }
  dbg_print("\n");
}
#endif

/**
 * @brief Enlarge the size of a bucket file.
 *        This is done when the bucket file is initially created,
 *        or when there is not enough room to insert segments.
 * @param bucket Pathname of the bucket file.
 * @param create If set, this file will be newly created.
 * @return 0 on success, -errno otherwise.
 */
static int stretch_bucket(char *bucket, int create)
{
  int retval = 0;

  /* create or open the bucket file */
  int fd = 0;
  if (create) {
    fd = open(bucket, O_RDWR | O_CREAT | O_EXCL, DEFAULT_MODE);
  } else {
    fd = open(bucket, O_RDWR);
  }
  if (fd < 0) {
    retval = cloudfs_error("stretch_bucket - open");
    return retval;
  }

  /* read the file size */
  struct stat sb;
  retval = fstat(fd, &sb);
  if (retval < 0) {
    retval = cloudfs_error("stretch_bucket - fstat");
    return retval;
  }
  dbg_print("[DBG] size of the file to stretch is %llu\n", sb.st_size);

  /* calculate the target size to stretch to */
  int target_size = sb.st_size * 2;
  if (target_size <= 0) {
    target_size = Bkt_size;
  }
  dbg_print("[DBG] stretch target size is %d\n", target_size);

  /* stretch the file */
  if (lseek(fd, target_size - 1, SEEK_SET) < 0) {
    retval = cloudfs_error("stretch_bucket - lseek");
    return retval;
  }

  /* mark the end of the file to make the stretch effective */
  if (write(fd, "\0", 1) < 0) {
    retval = cloudfs_error("stretch_bucket - write");
    return retval;
  }

  /* close the file */
  retval = close(fd);
  if (retval < 0) {
    retval = cloudfs_error("add_slots - close");
    return retval;
  }

  dbg_print("[DBG] stretch_bucket(fd=%d)=%d\n", fd, retval);

  return retval;
}

/**
 * @brief Fill empty segment slots to the second half of a bucket or all bucket.
 * @param bucket Pathname of the bucket file.
 * @param all If set, fill the entire file instead of the second half.
 * @return 0 on success, -errno otherwise.
 */
static int add_slots(char *bucket, int all)
{
  int retval = 0;

  /* open the bucket file */
  int fd = 0;
  fd = open(bucket, O_RDWR);
  if (fd < 0) {
    retval = cloudfs_error("add_slots - open");
    return retval;
  }

  /* read the file size */
  struct stat sb;
  retval = fstat(fd, &sb);
  if (retval < 0) {
    retval = cloudfs_error("add_slots - fstat");
    return retval;
  }
  dbg_print("[DBG] size of the file to add slots is %llu\n", sb.st_size);

  /* starting point to fill */
  int start_size = all ? 0 : (sb.st_size / 2);

  /* how many slots to fill */
  int num_slots = sb.st_size / sizeof(struct cloudfs_seg);
  if (!all) {
    num_slots /= 2;
  }
  dbg_print("[DBG] number of slots to fill is %d\n", num_slots);

  void *mstart = NULL;
  mstart = mmap(NULL, sb.st_size, PROT_WRITE, MAP_SHARED, fd, 0);
  if (mstart == MAP_FAILED) {
    retval = cloudfs_error("add_slots - mmap");
    return retval;
  }

  /* no more need of the file descriptor */
  retval = close(fd);
  if (retval < 0) {
    retval = cloudfs_error("add_slots - close");
    return retval;
  }

  /* fill in empty slots */
  int i = 0;
  for (i = 0; i < num_slots; i++) {
    struct cloudfs_seg *slotp = (struct cloudfs_seg *)
      (mstart + start_size + i * sizeof(struct cloudfs_seg));
    slotp->ref_count = 0;
    slotp->seg_size = 0;
    memcpy(slotp->md5, "fakefakefakefake", MD5_DIGEST_LENGTH);
  }

  /* unmap the bucket, sync to disk */
  retval = munmap(mstart, sb.st_size);
  if (retval < 0) {
    retval = cloudfs_error("add_slots - munmap");
    return retval;
  }

  return retval;
}

/**
 * @brief Initialize the hash table.
 *        This function creates bucket files if the hash table is empty.
 *        Also it mmaps all bucket files to memory for future use.
 * @param bkt_prfx Path of the bucket files, except the bucket number.
 *                 E.g. the prefix is /mnt/ssd/tmp/bucket, and there are
 *                 10 buckets, then bucket files are /mnt/ssd/tmp/bucket0
 *                 to /mnt/ssd/tmp/bucket9.
 * @param bkt_num Number of bucket files.
 * @param bkt_size Default size of each bucket file in bytes.
 * @param log The log file passed from CloudFS.
 * @return 0 on success, -errno otherwise.
 */
int ht_init(char *bkt_prfx, int bkt_num, int bkt_size)
{
  int retval = 0;
  int fd = 0;
  int i = 0;
  char bkt_file[MAX_PATH_LEN] = "";

  /* initialize static global variables */
  memset(Bkt_prfx, '\0', MAX_PATH_LEN);
  strncpy(Bkt_prfx, bkt_prfx, MAX_PATH_LEN - 1);
  Bkt_num = bkt_num;
  Bkt_size = bkt_size;
  Buckets = (void **) malloc(bkt_num * sizeof(void *));
  if (Buckets == NULL) {
    retval = cloudfs_error("ht_init - malloc");
    return retval;
  }
  for (i = 0; i < bkt_num; i++) {
    Buckets[i] = NULL;
  }

  /* for each bucket file, create it if needed,
   * and then mmap that file, save the pointers to Buckets */
  for (i = 0; i < bkt_num; i++) {
    snprintf(bkt_file, MAX_PATH_LEN, "%s%d", bkt_prfx, i);
    if (access(bkt_file, F_OK) < 0) {
      dbg_print("[DBG] bucket file %s does not exist\n", bkt_file);
      retval = stretch_bucket(bkt_file, 1);
      if (retval < 0) {
        return retval;
      }
      retval = add_slots(bkt_file, 1);
      if (retval < 0) {
        return retval;
      }
    } else {
      dbg_print("[DBG] bucket file %s exists\n", bkt_file);
    }

    fd = open(bkt_file, O_RDWR);
    if (fd < 0) {
      retval = cloudfs_error("ht_init - open");
      return retval;
    }
    struct stat sb;
    retval = fstat(fd, &sb);
    if (retval < 0) {
      retval = cloudfs_error("ht_init - fstat");
      return retval;
    }

    Buckets[i] = mmap(NULL, sb.st_size, PROT_WRITE, MAP_SHARED, fd, 0);
    if (Buckets[i] == MAP_FAILED) {
      retval = cloudfs_error("ht_init - mmap");
      return retval;
    }

    if (close(fd) < 0) {
      retval = cloudfs_error("ht_init - close");
      return retval;
    }
  }

  dbg_print("[DBG] ht_init(bkt_prfx=\"%s\", bkt_num=%d,"
      " bkt_size=%d)=%d\n", bkt_prfx, bkt_num, bkt_size, retval);

  return retval;
}

/**
 * @brief Calculate hash value based on MD5 of a segment.
 *        The current implementation is just sum over the
 *        characters in the MD5 array.
 * @param md5 MD5 of a segment.
 * @return The calculated hash value for the hash table.
 */
static int hash_value(unsigned char *md5)
{
  int i = 0;
  int sum = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sum += (int) md5[i];
  }
  dbg_print("[DBG] hash value is %d\n", sum);
  return sum;
}

/**
 * @brief Inserts a segment into the hash table.
 *        Insertion is done by iterating each slot
 *        in the bucket. If some slot's "ref_count"
 *        field is zero, insert there; if all slots
 *        are occupied, stretch the bucket.
 * @param segp Pointer to the segment to insert.
 * @return 0 on success, -1 otherwise.
 */
int ht_insert(struct cloudfs_seg *segp)
{
  int retval = 0;
  int bucket_id = 0;
  int i = 0;
  char bucket[MAX_PATH_LEN] = "";

  bucket_id = hash_value(segp->md5) % Bkt_num;
  snprintf(bucket , MAX_PATH_LEN, "%s%d", Bkt_prfx, bucket_id);
  dbg_print("[DBG] target bucket file is %s\n", bucket);

  struct stat sb;
  retval = lstat(bucket, &sb);
  if (retval < 0) {
    retval = cloudfs_error("ht_insert - lstat");
    return retval;
  }
  dbg_print("[DBG] file size is %llu\n", sb.st_size);

  dbg_print("[DBG] inserting segment\n");
#ifdef DEBUG
  print_seg(segp);
#endif

  int success = 0;
  for (i = 0; i < sb.st_size / sizeof(struct cloudfs_seg); i++) {
    struct cloudfs_seg *slotp = (struct cloudfs_seg *)
      (Buckets[bucket_id] + i * sizeof(struct cloudfs_seg));
    if (slotp->ref_count == 0) {
      dbg_print("[DBG] slot %d is available\n", i);
      slotp->ref_count = segp->ref_count;
      slotp->seg_size = segp->seg_size;
      memcpy(slotp->md5, segp->md5, MD5_DIGEST_LENGTH);
      msync(slotp, sizeof(struct cloudfs_seg), MS_SYNC);
      success = 1;
      break;
    }
  }

  if (!success) {
    dbg_print("[DBG] bucket is full\n");
    if (munmap(Buckets[bucket_id], sb.st_size) < 0) {
      retval = cloudfs_error("ht_insert - munmap");
      return retval;
    }
    retval = stretch_bucket(bucket, 0);
    if (retval < 0) {
      return retval;
    }
    retval = add_slots(bucket, 0);
    if (retval < 0) {
      return retval;
    }
    int fd = open(bucket, O_RDWR);
    if (fd < 0) {
      retval = cloudfs_error("ht_insert - open");
      return retval;
    }
    retval = fstat(fd, &sb);
    if (retval < 0) {
      retval = cloudfs_error("ht_insert - fstat");
      return retval;
    }
    Buckets[bucket_id] =
      mmap(NULL, sb.st_size, PROT_WRITE, MAP_SHARED, fd, 0);
    if (Buckets[bucket_id] == MAP_FAILED) {
      retval = cloudfs_error("ht_insert - mmap");
      return retval;
    }
    retval = close(fd);
    if (retval < 0) {
      retval = cloudfs_error("ht_insert - close");
      return retval;
    }
    struct cloudfs_seg *slotp = (struct cloudfs_seg *)
      (Buckets[bucket_id] + sb.st_size / 2);
    slotp->ref_count = segp->seg_size;
    slotp->seg_size = segp->seg_size;
    memcpy(slotp->md5, segp->md5, MD5_DIGEST_LENGTH);
    msync(slotp, sizeof(struct cloudfs_seg), MS_SYNC);
  }

  dbg_print("[DBG] ht_insert(segp=0x%08x)=%d\n", (unsigned int) segp, retval);

  return retval;
}

/**
 * @brief Search for a particular segment.
 *        Match is found if seg_size and md5 are the same.
 * @param segp The segment to search for.
 * @param found If found, place the match's pointer here,
 *              If not found, this will be set to NULL.
 * @return 0 on success, -errno otherwise.
 */
int ht_search(struct cloudfs_seg *segp, struct cloudfs_seg **found)
{
  int retval = 0;
  int bucket_id = 0;
  char bucket[MAX_PATH_LEN] = "";

  bucket_id = hash_value(segp->md5) % Bkt_num;
  snprintf(bucket , MAX_PATH_LEN, "%s%d", Bkt_prfx, bucket_id);
  dbg_print("[DBG] bucket file to search is %s\n", bucket);

  struct stat sb;
  retval = lstat(bucket, &sb);
  if (retval < 0) {
    retval = cloudfs_error("ht_search - lstat");
    return retval;
  }

  dbg_print("[DBG] searching segment\n");
#ifdef DEBUG
  print_seg(segp);
#endif

  int i = 0;
  for (i = 0; i < sb.st_size / sizeof(struct cloudfs_seg); i++) {
    struct cloudfs_seg *slotp = (struct cloudfs_seg *)
      (Buckets[bucket_id] + i * sizeof(struct cloudfs_seg));
    if ((slotp->ref_count > 0) && (slotp->seg_size == segp->seg_size)
        && (memcmp(slotp->md5, segp->md5, MD5_DIGEST_LENGTH) == 0)) {
      dbg_print("[DBG] segment found at slot %d\n", i);
      *found = slotp;
      return retval;
    }
  }
  dbg_print("[DBG] segment not found\n");
  *found = NULL;
  return retval;
}

/**
 * @brief CloudFS should call this function upon exiting.
 *        This function unmaps all buckets and frees allocated memory.
 * @return Void.
 */
void ht_destroy(void)
{
  int i = 0;
  char bucket[MAX_PATH_LEN] = "";

  for (i = 0; i < Bkt_num; i++) {
    snprintf(bucket , MAX_PATH_LEN, "%s%d", Bkt_prfx, i);
    dbg_print("[DBG] unmapping %s\n", bucket);

    struct stat sb;
    if (lstat(bucket, &sb) < 0) {
      cloudfs_error("ht_destroy - lstat");
      continue;
    }

    if (munmap(Buckets[i], sb.st_size) < 0) {
      cloudfs_error("ht_destroy - munmap");
      continue;
    }
  }

  if (Buckets != NULL) {
    free(Buckets);
  }
}

/**
 * @brief A wrapper function for msync.
 *        This should be called everytime when an item in the hash
 *        table is updated (such as ref_count).
 * @param segp The segment to sync.
 * @return Void.
 */
void ht_sync(struct cloudfs_seg *segp)
{
  msync(segp, sizeof(struct cloudfs_seg), MS_SYNC);
}


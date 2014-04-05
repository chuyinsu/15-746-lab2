/**
 * @file hashtable.c
 * @brief A persistent hash table implementation. Each bucket in the hash table
 *        is a file, and all buckets are mmap-ed upon file system starting.
 *        Any changes to the hash table is made first in the memory region
 *        of the file and then msync-ed to disk.
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
static FILE *Log;

/* store the mmap addresses of each bucket */
static void **Buckets;

/* extended attribute to mark how many items are
 * currently stored inside a bucket file */
#define U_ITEM ("user.item")

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
  dbg_print("[DBG] --- end ---\n");
}
#endif

/**
 * @brief Enlarge the size of a bucket file.
 *        This is done when the bucket file is initially created,
 *        or when there is no enough room to insert segments.
 * @param fd The descriptor of the bucket file.
 * @param stretch_factor Number to multiply when enlarging the file.
 *                       This corresponds to how many times this file
 *                       has been enlarged.
 * @return 0 on success, -errno otherwise.
 */
static int stretch_bucket(int fd, int stretch_factor)
{
  int retval = 0;

  if (lseek(fd, stretch_factor * Bkt_size - 1, SEEK_SET) < 0) {
    retval = cloudfs_error("stretch_bucket - lseek");
    return retval;
  }
  if (write(fd, "\0", 1) < 0) {
    retval = cloudfs_error("stretch_bucket - write");
    return retval;
  }

  dbg_print("[DBG] stretch_bucket(fd=%d, stretch_factor=%d)=%d\n",
      fd, stretch_factor, retval);

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
int ht_init(char *bkt_prfx, int bkt_num, int bkt_size, FILE *log)
{
  int retval = 0;
  int fd = 0;
  int i = 0;
  char bkt_file[MAX_PATH_LEN] = "";
  int map_size = 0;

  /* initialize static global variables */
  memset(Bkt_prfx, '\0', MAX_PATH_LEN);
  strncpy(Bkt_prfx, bkt_prfx, MAX_PATH_LEN - 1);
  Bkt_num = bkt_num;
  Bkt_size = bkt_size;
  Log = log;
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

      /* if a bucket file dose not exist, it has to be created and
       * stretched to an initial size */
      fd = open(bkt_file, O_RDWR | O_CREAT | O_EXCL, 0666);
      if (fd < 0) {
        retval = cloudfs_error("ht_init - open");
        return retval;
      }
      retval = stretch_bucket(fd, 1);
      if (retval < 0) {
        return retval;
      }

      /* set the initial items stored in the bucket to be zero */
      int num_item = 0;
      if (fsetxattr(fd, U_ITEM, &num_item, sizeof(int), 0) < 0) {
        retval = cloudfs_error("ht_init - fsetxattr");
        return retval;
      }

      map_size = bkt_size;
    } else {
      dbg_print("[DBG] bucket file %s exists\n", bkt_file);
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

      map_size = sb.st_size;
    }

    Buckets[i] = mmap(NULL, map_size, PROT_WRITE, MAP_SHARED, fd, 0);
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
      " bkt_size=%d, log=0x%08x)=%d\n", bkt_prfx, bkt_num, bkt_size,
      (unsigned int) log, retval);

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
  dbg_print("[DBG] hash_value=%d\n", sum);
  return sum;
}

/**
 * @brief Inserts a segment into the hash table.
 * @param segp Pointer to the segment to insert.
 * @return 0 on success, -1 otherwise.
 */
int ht_insert(struct cloudfs_seg *segp)
{
  int retval = 0;
  int bucket_id = 0;
  int fd = 0;
  char bucket[MAX_PATH_LEN] = "";

  bucket_id = hash_value(segp->md5) % Bkt_num;
  snprintf(bucket , MAX_PATH_LEN, "%s%d", Bkt_prfx, bucket_id);
  dbg_print("[DBG] target bucket file is %s\n", bucket);

  int num_item = 0;
  if (lgetxattr(bucket, U_ITEM, &num_item, sizeof(int)) < 0) {
    retval = cloudfs_error("ht_insert - lgetxattr");
    return retval;
  }
  dbg_print("[DBG] this bucket currently holds %d items\n", num_item);

  struct stat sb;
  retval = lstat(bucket, &sb);
  if (retval < 0) {
    retval = cloudfs_error("ht_insert - lstat");
    return retval;
  }
  dbg_print("[DBG] bucket file stat read, st_size=%llu\n", sb.st_size);

  if (num_item >= (sb.st_size / sizeof(struct cloudfs_seg))) {
    dbg_print("[DBG] bucket is full\n");
    if (munmap(Buckets[bucket_id], sb.st_size) < 0) {
      retval = cloudfs_error("ht_insert - munmap");
      return retval;
    }

    /* how many items does a bucket of default size can hold */
    int base = Bkt_size / sizeof(struct cloudfs_seg);
    dbg_print("[DBG] base=%d\n", base);

    /* the number of times this bucket has been stretched */
    int prev_stretch_factor = num_item / base;
    dbg_print("[DBG] prev_stretch_factor=%d\n", prev_stretch_factor);

    /* now stretch it again */
    fd = open(bucket, O_RDWR);
    if (fd < 0) {
      retval = cloudfs_error("ht_insert - open");
      return retval;
    }
    retval = stretch_bucket(fd, prev_stretch_factor + 1);
    if (retval < 0) {
      return retval;
    }

    /* map the bucket file again */
    Buckets[bucket_id] = mmap(NULL, (prev_stretch_factor + 1) * Bkt_size,
        PROT_WRITE, MAP_SHARED, fd, 0);
    if (Buckets[bucket_id] == MAP_FAILED) {
      retval = cloudfs_error("ht_init - mmap");
      return retval;
    }
    dbg_print("[DBG] file remapped\n");

    if (close(fd) < 0) {
      retval = cloudfs_error("ht_insert - close");
      return retval;
    }
  }

  dbg_print("[DBG] inserting segment\n");
#ifdef DEBUG
  print_seg(segp);
#endif

  struct cloudfs_seg *slotp = (struct cloudfs_seg *)
    (Buckets[bucket_id] + (num_item) * sizeof(struct cloudfs_seg));
  slotp->ref_count = segp->ref_count;
  slotp->seg_size = segp->seg_size;
  memcpy(&slotp->md5, &segp->md5, MD5_DIGEST_LENGTH);

  num_item++;
  if (lsetxattr(bucket, U_ITEM, &num_item, sizeof(int), 0) < 0) {
    retval = cloudfs_error("ht_insert - lgetxattr");
    return retval;
  }

  msync(slotp, sizeof(struct cloudfs_seg), MS_SYNC);

  dbg_print("[DBG] ht_insert(segp=0x%08x)=%d\n", (unsigned int) segp, retval);

  return retval;
}

/**
 * @brief CloudFS should call this function upon exiting.
 * @return Void.
 */
void ht_destroy(void) {
  if (Buckets != NULL) {
    free(Buckets);
  }
}


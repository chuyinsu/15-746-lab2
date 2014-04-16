#ifndef __CLOUDFS_H_
#define __CLOUDFS_H_

#define MAX_PATH_LEN 4096
#define MAX_HOSTNAME_LEN 1024

#include <openssl/md5.h>

struct cloudfs_state {
  char ssd_path[MAX_PATH_LEN];
  char fuse_path[MAX_PATH_LEN];
  char hostname[MAX_HOSTNAME_LEN];
  int ssd_size;
  int threshold;
  int avg_seg_size;
  int rabin_window_size;
  int cache_size;
  char no_dedup;
  char no_cache;
  char no_compress;
};

/* structure of the key for deduplication hash table,
 * represents a segment of a file */
struct cloudfs_seg {
  int ref_count;
  long seg_size;
  char md5[MD5_DIGEST_LENGTH * 2 + 1];
};

int cloudfs_start(struct cloudfs_state* state,
    const char* fuse_runtime_name);  
void cloudfs_get_fullpath(const char *path, char *fullpath);
int cloudfs_error(char *error_str);

/* a simple debugging utility,
 * uncomment the next line to log debugging information */
//#define DEBUG
#ifdef DEBUG
# define dbg_print(...) fprintf(Log, __VA_ARGS__)
#else
# define dbg_print(...) 
#endif

#define DEFAULT_FILE_MODE (0666)
#define DEFAULT_DIR_MODE (0777)

/* bucket name in the cloud */
#define BUCKET ("yinsuc")

#endif


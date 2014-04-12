#include <stdio.h>

#include "cloudfs.h"
#include "cloudapi.h"
#include "compressapi.h"
#include "zlib.h"

#define COMP_SUFFIX (".compressed")

extern FILE *Log;

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
 * @brief Download from the cloud according to the key,
 *        and de-compress into "target_file".
 * @param target_file Pathname of the file to de-compress into.
 *                    It should have MAX_PATH_LEN bytes.
 * @param key The key of the cloud file. It should have
 *            MD5_DIGEST_LENGTH bytes.
 * @return 0 on success, negative otherwise.
 */
int compress_layer_download_seg(char *target_file, char *key)
{
  int retval = 0;

  char tpath[MAX_PATH_LEN] = "";
  sprintf(tpath, "%s%s", target_file, COMP_SUFFIX);

  Tfile = fopen(tpath, "wb");
  cloud_get_object(BUCKET, key, get_buffer);
  cloud_print_error();
  fclose(Tfile);

  dbg_print("[DBG] segment downloaded to file %s\n", tpath);

  FILE *comp = fopen(tpath, "rb");
  FILE *decomp = fopen(target_file, "wb");
  if (comp == NULL || decomp == NULL) {
    retval = cloudfs_error("compress_layer_download_seg");
    return retval;
  }

  retval = inf(comp, decomp);
  if (retval < 0) {
    dbg_print("[ERR] failed to de-compress\n");
    return retval;
  }

  fclose(comp);
  fclose(decomp);

  retval = remove(tpath);
  if (retval < 0) {
    retval = cloudfs_error("compress_layer_download_seg");
  }

  dbg_print("[DBG] compress_layer_download_seg(target_file=\"%s\","
      " key=\"%s\")=%d\n", target_file, key, retval);

  return retval;
}

/**
 * @brief Compress and upload a segment.
 *        The segment is defined by "offset" and "len" in a file.
 * @param fpath Pathname of the entire file.
 * @param offset Offset of the segment into the file.
 * @param key Cloud key of the segment.
 * @param len Length of the segment.
 * @return 0 on success, negative otherwise.
 */
int compress_layer_upload_seg(char *fpath, long offset, char *key, long len)
{
  int retval = 0;

  char tpath[MAX_PATH_LEN] = "";
  sprintf(tpath, "%s%s.%ld.%ld%s", fpath, ".seg", offset, len, COMP_SUFFIX);

  FILE *decomp = fopen(fpath, "rb");
  fseek(decomp, offset, SEEK_SET);

  FILE *comp = fopen(tpath, "wb");
  retval = def(decomp, comp, len, Z_DEFAULT_COMPRESSION);
  if (retval < 0) {
    dbg_print("[ERR] failed to compress %s\n", fpath);
    return retval;
  }

  dbg_print("[DBG] compressed file is %s\n", tpath);

  fclose(decomp);
  fclose(comp);

  long len_compressed_file = 0;
  Cfile = fopen(tpath, "rb");
  fseek(Cfile, 0, SEEK_END);
  len_compressed_file = ftell(Cfile);
  fseek(Cfile, 0, SEEK_SET);

  dbg_print("[DBG] length of compressed file is %ld\n", len_compressed_file);

  cloud_put_object(BUCKET, key, len_compressed_file, put_buffer);
  cloud_print_error();
  fclose(Cfile);

  retval = remove(tpath);
  if (retval < 0) {
    retval = cloudfs_error("compress_layer_upload_seg");
  }

  dbg_print("[DBG] compress_layer_upload_seg(fpath=\"%s\", offset=%ld,"
      " key=\"%s\", len=%ld)=%d\n", fpath, offset, key, len, retval);

  return retval;
}


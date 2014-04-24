/**
 * @file compress_layer.c
 * @brief The compress layer of CloudFS.
 *        Reference: compress-example.c in the provided code.
 * @author Yinsu Chu (yinsuc)
 */

#include <stdio.h>

#define DEBUG
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
 * @brief Decompress a file to the target file.
 * @param fpath Pathname of the compressed file.
 * @param target_file Pathname of the file to store the result.
 * @return 0 on success, negative otherwise.
 */
int compress_layer_decompress(char *fpath, char *target_file)
{
  int retval = 0;

  FILE *comp = fopen(fpath, "rb");
  FILE *decomp = fopen(target_file, "wb");
  if (comp == NULL || decomp == NULL) {
    retval = cloudfs_error("compress_layer_decompress");
    return retval;
  }

  retval = inf(comp, decomp);
  if (retval < 0) {
    dbg_print("[ERR] failed to decompress %s\n", fpath);
    return retval;
  }

  fclose(comp);
  fclose(decomp);

  return retval;
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

  dbg_print("[DBG] compressed segment downloaded to file %s\n", tpath);

  retval = compress_layer_decompress(tpath, target_file);
  if (retval < 0) {
    return retval;
  }

  retval = remove(tpath);
  if (retval < 0) {
    retval = cloudfs_error("compress_layer_download_seg");
  }

  dbg_print("[DBG] compress_layer_download_seg(target_file=\"%s\","
      " key=\"%s\")=%d\n", target_file, key, retval);

  return retval;
}

/**
 * @brief Compress part of a file to the target file.
 * @param fpath Pathname of the entire file.
 * @param offset Offset of the part to compress.
 * @param len Length of the part to compress.
 * @param target_file Pathname of the target file to store the result.
 * @return Length of the compressed file on success, negative otherwise.
 */
long compress_layer_compress(char *fpath, long offset, long len,
    char *target_file)
{
  long retval = 0;

  FILE *decomp = fopen(fpath, "rb");
  if (decomp == NULL) {
    retval = cloudfs_error("compress_layer_compress - fopen");
    return retval;
  }

  retval = fseek(decomp, offset, SEEK_SET);
  if (retval < 0) {
    retval = cloudfs_error("compress_layer_compress - fseek");
    return retval;
  }

  FILE *comp = fopen(target_file, "wb");
  if (comp == NULL) {
    retval = cloudfs_error("compress_layer_compress - fopen");
    return retval;
  }

  retval = def(decomp, comp, len, Z_DEFAULT_COMPRESSION);
  if (retval < 0) {
    dbg_print("[ERR] failed to compress %s\n", fpath);
    return retval;
  }

  dbg_print("[DBG] compressed file is %s\n", target_file);

  fclose(decomp);
  fclose(comp);

  comp = fopen(target_file, "rb");
  fseek(comp, 0, SEEK_END);
  retval = ftell(comp);
  fclose(comp);

  dbg_print("[DBG] length of compressed file is %ld\n", retval);

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

  long len_compressed_file = compress_layer_compress(fpath, offset, len, tpath);
  if (len_compressed_file < 0) {
    return len_compressed_file;
  }

  Cfile = fopen(tpath, "rb");
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


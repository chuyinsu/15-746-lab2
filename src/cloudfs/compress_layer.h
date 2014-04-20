#ifndef __COMPRESS_LAYER_H_
#define __COMPRESS_LAYER_H_

int compress_layer_decompress(char *fpath, char *target_file);
int compress_layer_download_seg(char *target_file, char *key);
long compress_layer_compress(char *fpath, long offset, long len,
    char *target_file);
int compress_layer_upload_seg(char *fpath, long offset, char *key, long len);

#endif


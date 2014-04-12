#ifndef __COMPRESS_LAYER_H_
#define __COMPRESS_LAYER_H_

int compress_layer_download_seg(char *target_file, char *key);
int compress_layer_upload_seg(char *fpath, long offset, char *key, long len);

#endif


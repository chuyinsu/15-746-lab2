#ifndef __CACHE_LAYER_H_
#define __CACHE_LAYER_H_

int cache_layer_init(int total_space, int init_space);
int cache_layer_download_seg(char *target_file, char *key);
int cache_layer_upload_seg(char *fpath, long offset, char *key, long len);
int cache_layer_remove_seg(char *key);

#endif


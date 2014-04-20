#ifndef __DEDUP_LAYER_H_
#define __DEDUP_LAYER_H_

void dedup_layer_init(int window_size, int avg_seg_size, int min_seg_size,
    int max_seg_size, int no_cache);
void dedup_layer_destroy(void);
int dedup_layer_read_seg(char *temp_dir, struct cloudfs_seg *segp, char *buf,
    int size, int offset);
int dedup_layer_remove(char *fpath);
int dedup_layer_upload(char *fpath);

#endif


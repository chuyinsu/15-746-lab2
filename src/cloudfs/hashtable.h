#ifndef __HASHTABLE_H_
#define __HASHTABLE_H_

int ht_init(char *bkt_prfx, int bkt_num, int bkt_size, FILE *log);
int ht_insert(struct cloudfs_seg *segp);

#endif


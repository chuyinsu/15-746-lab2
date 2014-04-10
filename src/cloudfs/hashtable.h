#ifndef __HASHTABLE_H_
#define __HASHTABLE_H_

int ht_init(char *bkt_prfx, int bkt_num, int bkt_size);
int ht_insert(struct cloudfs_seg *segp);
int ht_search(struct cloudfs_seg *segp, struct cloudfs_seg **found);
void ht_destroy(void);
#ifdef DEBUG
void print_seg(struct cloudfs_seg *segp);
#endif
void ht_sync(struct cloudfs_seg *segp);

#endif


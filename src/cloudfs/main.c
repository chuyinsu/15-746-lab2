/**
 * @file main.c
 * @brief Entry point for CloudFS.
 *        Modified by Yinsu Chu (yinsuc)
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "cloudfs.h"

static void usageExit(FILE *out)
{
  fprintf(out,
      "   Command Line:\n"
      "\n"
      "   -s/--ssd-path        :  The mount directory of SSD disk\n"
      "   -f/--fuse-path       :  The directory where cloudfs mounts\n"
      "   -h/--hostname        :  The hostname of S3 server, e.g. (localhost,"
      "localhost:80)\n"
      "   -a/--ssd-size        :  The size of SSD disk(in KB)\n"
      "   -t/--threshold       :  The maximum size of files in SSD(in KB)\n"
      "   -/--no-dedup        :  Turn off deduplication\n"
      "   -/--avg-seg-size    :  "
      "Desired average segment size for deduplication(in KB)\n"
      "   -/--rabin-window-size: Size of the internal rolling window used for"
      "                           calculating Rabin fingerprint(in bytes)\n"
      "   -/--no-cache        :  Turn off the file cache\n"
      "   -/--no-compress        :  Turn off the compression\n"
      "   -c/--cache-size      :  The maximum size of SSD cache(in KB)\n"
      "\n"
      " Commands (with <required parameters> and [optional parameters]) :\n"
      "\n");
  exit(-1);
}

static struct option longOptionsG[] =
{
  { "ssd-path",			required_argument,			0,  's' },
  { "fuse-path",			required_argument,			0,  'f' },
  { "hostname",			required_argument,			0,  'h' },
  { "ssd-size",			required_argument,			0,  'a' },
  { "threshold",			required_argument,			0,  't' },
  { "no-dedup",			no_argument,				0,  'd' },
  { "avg-seg-size",		required_argument,			0,  'S' },
  { "rabin-window-size",	required_argument,			0,  'w' },
  { "no-cache",			no_argument,				0,  'o' },
  { "no-compress",		no_argument,				0,  'z' },
  { "cache-size",			required_argument,			0,  'c' },
  { 0,					0,							0,   0	}
};

static void parse_arguments(int argc, char* argv[], 
    struct cloudfs_state *state) {
  // Default Values
  memset(state->ssd_path, '\0', MAX_PATH_LEN);
  strcpy(state->ssd_path, "/mnt/ssd/");
  memset(state->fuse_path, '\0', MAX_PATH_LEN);
  strcpy(state->fuse_path, "/mnt/fuse/");
  memset(state->hostname, '\0', MAX_HOSTNAME_LEN);
  strcpy(state->hostname, "localhost:8888");
  state->ssd_size = 1024*1024*1024;
  state->threshold = 64*1024;

  state->no_dedup = 0;
  state->avg_seg_size = 4096;
  state->rabin_window_size = 48;

  state->no_cache = 0;
  state->cache_size = 32*1024*1024;
  state->no_compress = 0;

  // Parse args
  while (1) {
    int idx = 0;
    int c = getopt_long(argc, argv, "s:f:h:a:t:dS:w:oc:z:", longOptionsG, &idx);

    if (c == -1) {
      // End of options
      break;
    }

    switch (c) {
      case 's':
        memset(state->ssd_path, '\0', MAX_PATH_LEN);
        strcpy(state->ssd_path, optarg);
        break;
      case 'f':
        memset(state->fuse_path, '\0', MAX_PATH_LEN);
        strcpy(state->fuse_path, optarg);
        break;
      case 'h':
        memset(state->hostname, '\0', MAX_HOSTNAME_LEN);
        strcpy(state->hostname, optarg);
        break;
      case 'a': 
        state->ssd_size = atoi(optarg)*1024;
        break; 
      case 't': 
        state->threshold = atoi(optarg)*1024;
        break;
      case 'd':
        state->no_dedup = 1;
        break;
      case 'S': 
        state->avg_seg_size = atoi(optarg)*1024;
        break;
      case 'w': 
        state->rabin_window_size = atoi(optarg);
        break;
      case 'o':
        state->no_cache = 1;
        break;
      case 'c':
        state->cache_size = atoi(optarg)*1024;
        break;
      case 'z':
        state->no_compress = 1;
        break;
      default:
        fprintf(stderr, "\nERROR: Unknown option: -%c\n", c);
        // Usage exit
        usageExit(stderr);
    }
  }
}

// main ------------------------------------------------------------------------

int main(int argc, char **argv)
{

  struct cloudfs_state state;
  parse_arguments(argc, argv, &state);

  cloudfs_start(&state, argv[0]);

  return 0;
}


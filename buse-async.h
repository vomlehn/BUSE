#ifndef BUSE_H_INCLUDED
#define BUSE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

  /* Most of this file was copied from nbd.h in the nbd distribution. */
#include <linux/types.h>
#include <sys/types.h>
#include <linux/nbd.h>

/* Forward declaration */
struct nbd_reply;

  struct buse_async_operations {
    int (*async_read)(void *buf, u_int32_t len, u_int64_t offset,
      void *userdata, struct nbd_reply *reply);
    int (*async_write)(const void *buf, u_int32_t len, u_int64_t offset,
      void *userdata, struct nbd_reply *reply);
    void (*async_disc)(void *userdata, struct nbd_reply *reply);
    int (*async_flush)(void *userdata, struct nbd_reply *reply);
    int (*async_trim)(u_int64_t from, u_int32_t len, void *userdata,
      struct nbd_reply *reply);

    u_int64_t size;
  };

  extern int buse_async_main(const char* dev_file,
    const struct buse_async_operations *bop, void *userdata);

  extern void return_status(int status, struct nbd_reply *reply);
#ifdef __cplusplus
}
#endif

#endif /* BUSE_H_INCLUDED */

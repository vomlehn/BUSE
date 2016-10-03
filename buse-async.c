/*
 * buse - block-device userspace extensions
 * Copyright (C) 2013 Adam Cozzette
 *
 * This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>

#include "buse-async.h"

#define container_of_nocheck(ptr, type, member) ({		\
		size_t __container_of_offset;			\
		char *__container_of_p;				\
		__container_of_offset = offsetof(type, member);	\
		__container_of_p = (char *)(ptr) -		\
			__container_of_offset;			\
		(type*)__container_of_p;			\
	})

#define container_of(ptr, type, member) ({			\
		typeof(ptr)__ptr_type;				\
		typeof(((type *)NULL)->member) *__member_type;	\
		(void) (&__ptr_type == &__member_type);		\
		container_of_nocheck(ptr, type, member);	\
	})

struct async_request {
				struct nbd_request	nbd_request;
				struct nbd_reply		nbd_reply;
				char								*chunk;
				int									sk;
};

/*
 * These helper functions were taken from cliserv.h in the nbd distribution.
 */
#ifdef WORDS_BIGENDIAN
u_int64_t ntohll(u_int64_t a) {
  return a;
}
#else
u_int64_t ntohll(u_int64_t a) {
  u_int32_t lo = a & 0xffffffff;
  u_int32_t hi = a >> 32U;
  lo = ntohl(lo);
  hi = ntohl(hi);
  return ((u_int64_t) lo) << 32U | hi;
}
#endif
#define htonll ntohll

static int read_all(int fd, char* buf, size_t count)
{
  int bytes_read;

  while (count > 0) {
    bytes_read = read(fd, buf, count);
    assert(bytes_read > 0);
    buf += bytes_read;
    count -= bytes_read;
  }
  assert(count == 0);

  return 0;
}

static int write_all(int fd, char* buf, size_t count)
{
  int bytes_written;

  while (count > 0) {
    bytes_written = write(fd, buf, count);
    assert(bytes_written > 0);
    buf += bytes_written;
    count -= bytes_written;
  }
  assert(count == 0);

  return 0;
}

int buse_async_main(const char* dev_file, const struct buse_async_operations *aop, void *userdata)
{
  int sp[2];
  int nbd, sk, err, tmp_fd;
  u_int64_t from;
  u_int32_t len;
  ssize_t bytes_read;
  void *chunk;

  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sp));

  nbd = open(dev_file, O_RDWR);
  assert(nbd != -1);

  assert(ioctl(nbd, NBD_SET_SIZE, aop->size) != -1);
  assert(ioctl(nbd, NBD_CLEAR_SOCK) != -1);

  if (!fork()) {
    /* The child needs to continue setting things up. */
    close(sp[0]);
    sk = sp[1];

    if(ioctl(nbd, NBD_SET_SOCK, sk) == -1){
      fprintf(stderr, "ioctl(nbd, NBD_SET_SOCK, sk) failed.[%s]\n", strerror(errno));
    }
#if defined NBD_SET_FLAGS && defined NBD_FLAG_SEND_TRIM
    else if(ioctl(nbd, NBD_SET_FLAGS, NBD_FLAG_SEND_TRIM) == -1){
      fprintf(stderr, "ioctl(nbd, NBD_SET_FLAGS, NBD_FLAG_SEND_TRIM) failed.[%s]\n", strerror(errno));
    }
#endif
    else{
      err = ioctl(nbd, NBD_DO_IT);
      fprintf(stderr, "nbd device terminated with code %d\n", err);
      if (err == -1)
	fprintf(stderr, "%s\n", strerror(errno));
    }

    ioctl(nbd, NBD_CLEAR_QUE);
    ioctl(nbd, NBD_CLEAR_SOCK);

    exit(0);
  }

  /* The parent opens the device file at least once, to make sure the
   * partition table is updated. Then it closes it and starts serving up
   * requests. */

  tmp_fd = open(dev_file, O_RDONLY);
  assert(tmp_fd != -1);
  close(tmp_fd);

  close(sp[1]);
  sk = sp[0];

  for (;;) {
		struct async_request *request;
		ssize_t zrc;

    /* Allocate space for both the request and the reply */
    request = malloc(sizeof(*request));
    assert(request != NULL);

		bytes_read = read(sk, &request, sizeof(request));
		if (bytes_read < 0)
						break;

    request->nbd_reply.magic = htonl(NBD_REPLY_MAGIC);
    request->nbd_reply.error = htonl(0);
    request->nbd_reply.magic = htonl(NBD_REPLY_MAGIC);
    request->nbd_reply.error = htonl(0);
		request->chunk = NULL;
    request->sk = sk;

    memcpy(request->nbd_reply.handle, request->nbd_request.handle,
      sizeof(request->nbd_reply.handle));

    len = ntohl(request->nbd_request.len);
    from = ntohll(request->nbd_request.from);
    assert(request->nbd_request.magic == htonl(NBD_REQUEST_MAGIC));

    switch(ntohl(request->nbd_request.type)) {
      /* I may at some point need to deal with the the fact that the
       * official nbd server has a maximum buffer size, and divides up
       * oversized requests into multiple pieces. This applies to reads
       * and writes.
       */
      case NBD_CMD_READ:
        fprintf(stderr, "Request for read of size %d\n", len);
        assert(aop->async_read);
        request->chunk = malloc(len);
				assert(request->chunk != NULL);
        aop->async_read(request->chunk, len, from, userdata,
          &request->nbd_reply);
        break;

      case NBD_CMD_WRITE:
        fprintf(stderr, "Request for write of size %d\n", len);
        assert(aop->async_write);
        request->chunk = malloc(len);
				assert(request->chunk != NULL);
        read_all(sk, request->chunk, len);
        aop->async_write(request->chunk, len, from, userdata,
          &request->nbd_reply);
        break;

      case NBD_CMD_DISC:
        /* Handle a disconnect request. */
        assert(aop->async_disc);
        aop->async_disc(userdata, &request->nbd_reply);
        break;

#ifdef NBD_FLAG_SEND_FLUSH
      case NBD_CMD_FLUSH:
        assert(aop->async_flush);
        aop->async_flush(userdata, &request->nbd_reply);
        break;
#endif

#ifdef NBD_FLAG_SEND_TRIM
      case NBD_CMD_TRIM:
        break;
#endif

      default:
      assert(0);
    }
  }
  if (bytes_read == -1)
    fprintf(stderr, "%s\n", strerror(errno));
  return 0;
}

void buse_async_complete(int status, struct nbd_reply *reply)
{
  struct async_request *request;

  request = container_of(reply, struct async_request, nbd_reply);
  request->nbd_reply.error = status;

  switch(ntohl(request->nbd_request.type)) {
  case NBD_CMD_READ:
    write_all(request->sk, (char*)reply, sizeof(*reply));
    if(request->nbd_reply.error == 0) {
			u_int32_t len;
      len = ntohl(request->nbd_request.len);
	    write_all(request->sk, (char*)request->chunk, len);
    }
    free(request->chunk);
    break;

  case NBD_CMD_WRITE:
    write_all(request->sk, (char*)reply, sizeof(*reply));
    free(request->chunk);
    break;

  case NBD_CMD_DISC:

#ifdef NBD_FLAG_SEND_FLUSH
  case NBD_CMD_FLUSH:
    write_all(request->sk, (char*)reply, sizeof(*reply));
    break;
#endif

#ifdef NBD_FLAG_SEND_TRIM
  case NBD_CMD_TRIM:
    write_all(request->sk, (char*)reply, sizeof(*reply));
    break;
#endif

  default:
    assert(0);
    break;
  }

  free(request);
}

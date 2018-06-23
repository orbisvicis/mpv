/*
 * Original author: M. Tourne
 *
 * This file is part of mpv.
 *
 * mpv is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * mpv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with mpv.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <libsmbclient.h>
#include <unistd.h>
#include <pthread.h>

#include "common/msg.h"
#include "stream.h"
#include "options/m_option.h"

#include "config.h"
#if !HAVE_GPL
#error GPL only
#endif

static int count_lseek = 0;
static int count_read = 0;
static int count_write = 0;
static int count_close = 0;
static int count_open = 0;
static int count_init = 0;
static pthread_cond_t smb_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t smb_lock = PTHREAD_MUTEX_INITIALIZER;

// The 'condition_expr' could be the sum of all count variables minus
// 'count_var' and therefore not required, but that is less efficient.
#define GEN_LOCKED(condition_expr, count_var, function, result_type, ...)\
    pthread_mutex_lock(&smb_lock);\
    while(condition_expr) { pthread_cond_wait(&smb_cond, &smb_lock); }\
    count_var++;\
    pthread_mutex_unlock(&smb_lock);\
    result_type result = function(__VA_ARGS__);\
    pthread_mutex_lock(&smb_lock);\
    count_var--;\
    if (!count_var) { pthread_cond_broadcast(&smb_cond); }\
    pthread_mutex_unlock(&smb_lock);\
    return result;

static off_t smbc_lseek_locked(int fd, off_t offset, int whence) {
    GEN_LOCKED(count_read || count_write || count_close || count_open || count_init, count_lseek, smbc_lseek, off_t, fd, offset, whence)
}

static ssize_t smbc_read_locked(int fd, void *buf, size_t bufsize) {
    GEN_LOCKED(count_lseek || count_write || count_close || count_open || count_init, count_read, smbc_read, ssize_t, fd, buf, bufsize)
}

static ssize_t smbc_write_locked(int fd, const void *buf, size_t bufsize) {
    GEN_LOCKED(count_lseek || count_read || count_close || count_open || count_init, count_write, smbc_write, ssize_t, fd, buf, bufsize)
}

static int smbc_close_locked(int fd) {
    GEN_LOCKED(count_lseek || count_read || count_write || count_open || count_init, count_close, smbc_close, int, fd)
}

static int smbc_open_locked(const char *furl, int flags, mode_t mode) {
    GEN_LOCKED(count_lseek || count_read || count_write || count_close || count_init, count_open, smbc_open, int, furl, flags, mode)
}

static int smbc_init_locked(smbc_get_auth_data_fn fn, int debug) {
    GEN_LOCKED(count_lseek || count_read || count_write || count_close || count_open, count_init, smbc_init, int, fn, debug)
}

struct priv {
    int fd;
};

static void smb_auth_fn(const char *server, const char *share,
             char *workgroup, int wgmaxlen, char *username, int unmaxlen,
             char *password, int pwmaxlen)
{
  strncpy(workgroup, "LAN", wgmaxlen - 1);
}

static int control(stream_t *s, int cmd, void *arg) {
  struct priv *p = s->priv;
  switch(cmd) {
    case STREAM_CTRL_GET_SIZE: {
      off_t size = smbc_lseek_locked(p->fd,0,SEEK_END);
      smbc_lseek_locked(p->fd,s->pos,SEEK_SET);
      if(size != (off_t)-1) {
        *(int64_t *)arg = size;
        return 1;
      }
    }
    break;
  }
  return STREAM_UNSUPPORTED;
}

static int seek(stream_t *s,int64_t newpos) {
  struct priv *p = s->priv;
  if(smbc_lseek_locked(p->fd,newpos,SEEK_SET)<0) {
    return 0;
  }
  return 1;
}

static int fill_buffer(stream_t *s, char* buffer, int max_len){
  struct priv *p = s->priv;
  int r = smbc_read_locked(p->fd,buffer,max_len);
  return (r <= 0) ? -1 : r;
}

static int write_buffer(stream_t *s, char* buffer, int len) {
  struct priv *p = s->priv;
  int r;
  int wr = 0;
  while (wr < len) {
    r = smbc_write_locked(p->fd,buffer,len);
    if (r <= 0)
      return -1;
    wr += r;
    buffer += r;
  }
  return len;
}

static void close_f(stream_t *s){
  struct priv *p = s->priv;
  smbc_close_locked(p->fd);
}

static int open_f (stream_t *stream)
{
  char *filename;
  int64_t len;
  int fd, err;

  struct priv *priv = talloc_zero(stream, struct priv);
  stream->priv = priv;

  filename = stream->url;

  bool write = stream->mode == STREAM_WRITE;
  mode_t m = write ? O_RDWR|O_CREAT|O_TRUNC : O_RDONLY;

  if(!filename) {
    MP_ERR(stream, "[smb] Bad url\n");
    return STREAM_ERROR;
  }

  err = smbc_init_locked(smb_auth_fn, 1);
  if (err < 0) {
    MP_ERR(stream, "Cannot init the libsmbclient library: %d\n",err);
    return STREAM_ERROR;
  }

  fd = smbc_open_locked(filename, m,0644);
  if (fd < 0) {
    MP_ERR(stream, "Could not open from LAN: '%s'\n", filename);
    return STREAM_ERROR;
  }

  len = 0;
  if(!write) {
    len = smbc_lseek_locked(fd,0,SEEK_END);
    smbc_lseek_locked (fd, 0, SEEK_SET);
  }
  if(len > 0 || write) {
    stream->seekable = true;
    stream->seek = seek;
  }
  priv->fd = fd;
  stream->fill_buffer = fill_buffer;
  stream->write_buffer = write_buffer;
  stream->close = close_f;
  stream->control = control;
  stream->read_chunk = 128 * 1024;
  stream->streaming = true;

  return STREAM_OK;
}

const stream_info_t stream_info_smb = {
    .name = "smb",
    .open = open_f,
    .protocols = (const char*const[]){"smb", NULL},
    .can_write = true, //who's gonna do that?
};

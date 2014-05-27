/*
 * kfifo.c - circular buffer device
 *
 * Copyright (C) 2011 Paolo Rovelli
 *
 * Author: Paolo Rovelli <paolorovelli@yahoo.it>
 */

#ifndef __KFIFO_H__
#define __KFIFO_H__

struct kfifo;

extern int kfifo_create(struct kfifo **kfifo, int size);
extern int kfifo_delete(struct kfifo *kfifo);
extern int kfifo_read(struct kfifo *kfifo, char *buf, int count);
extern int kfifo_write(struct kfifo *kfifo, char *buf, int count);
extern int kfifo_clear(struct kfifo *kfifo);
extern int kfifo_size(struct kfifo *kfifo);
extern int kfifo_free(struct kfifo *kfifo);
extern int kfifo_ready(struct kfifo *kfifo);

#endif /* __KFIFO_H__ */


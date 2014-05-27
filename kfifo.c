/*
 * kfifo.c - circular buffer device
 *
 * Copyright (C) 2011 Paolo Rovelli
 *
 * Author: Paolo Rovelli <paolorovelli@yahoo.it>
 */

#include "kfifo.h"

#ifdef __KERNEL__
        #include <linux/slab.h>
        #define alloc(size) kmalloc(size, GFP_KERNEL)
        #define free(ptr) kfree(ptr)
#else
        #include <stdlib.h>
        #define alloc(size) malloc(size)
#endif

struct kfifo {
        char *buf;
        int write_idx;
        int read_idx;
        int size;
        int status;
};

enum {
        KFIFO_EMPTY,
        KFIFO_DATA,
        KFIFO_FULL
};

int kfifo_create(struct kfifo **kfifo, int size)
{
	if (size <= 0)
		return -1; /* failure */

	*kfifo = alloc(sizeof(struct kfifo));
	if (*kfifo) {
		(*kfifo)->buf = alloc(size);
		if ((*kfifo)->buf) {
			(*kfifo)->size = size;
			(*kfifo)->read_idx = 0;
			(*kfifo)->write_idx = 0;
			(*kfifo)->status = KFIFO_EMPTY;
			return 0; /* success */
		} else {
			free(*kfifo);
			*kfifo = NULL;
		}
	}
	return -1; /* failure */
}

int kfifo_delete(struct kfifo *kfifo)
{
	if (kfifo) {
		if (kfifo->buf) {
			free(kfifo->buf);
			kfifo->buf = NULL;
		}
		free(kfifo);
		kfifo = NULL;
	}
	return 0;
}

int kfifo_read(struct kfifo *kfifo, char *buf, int count)
{
	int read = 0;

	if (kfifo) {
		while ((kfifo->status != KFIFO_EMPTY) && count > 0) {
			buf[read] = kfifo->buf[kfifo->read_idx];
			read++;
			count--;

			kfifo->read_idx = (kfifo->read_idx + 1)
				% kfifo->size;
			if (kfifo->read_idx == kfifo->write_idx)
				kfifo->status = KFIFO_EMPTY;
			else
				kfifo->status = KFIFO_DATA;
		}
	}
	return read;
}

int kfifo_write(struct kfifo *kfifo, char *buf, int count)
{
	int written = 0;

	if (kfifo) {
		while ((kfifo->status != KFIFO_FULL) && count > 0) {
			kfifo->buf[kfifo->write_idx] = buf[written];
			written++;
			count--;

			kfifo->write_idx = (kfifo->write_idx + 1)
				% kfifo->size;
			if (kfifo->write_idx == kfifo->read_idx)
				kfifo->status = KFIFO_FULL;
			else
				kfifo->status = KFIFO_DATA;
		}
	}
	return written;
}

int kfifo_clear(struct kfifo *kfifo)
{
	if (kfifo) {
		kfifo->read_idx = 0;
		kfifo->write_idx = 0;
		kfifo->status = KFIFO_EMPTY;
	}
	return 0;
}

int kfifo_size(struct kfifo *kfifo)
{
	if (kfifo) {
		return kfifo->size;
	}
	return 0;
}

int kfifo_free(struct kfifo *kfifo)
{
	if (kfifo) {
		switch(kfifo->status) {
		case KFIFO_EMPTY:
			return kfifo->size;
		case KFIFO_FULL:
			return 0;
		case KFIFO_DATA:
		default:
			return kfifo->read_idx >= kfifo->write_idx ?
				kfifo->read_idx - kfifo->write_idx :
				kfifo->size - kfifo->write_idx
					+ kfifo->read_idx;
		}
	}
	return 0;
}

int kfifo_ready(struct kfifo *kfifo)
{
	if (kfifo) {
		return kfifo_size(kfifo) - kfifo_free(kfifo);
	}
	return 0;
}


/* 
 * kbuf.c - KBUF device driver
 *
 * Copyright (C) 2011 Paolo Rovelli
 *
 * Author: Paolo Rovelli <paolorovelli@yahoo.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>

#include "kbuf.h"
#include "kfifo.h"

#define KBUF_MAX_NUM 64
#define KBUF_MAX_SIZE (128*1024) /* max 128 Kbyte (kmalloc limit) */

#define KBUF_NAME "kbuf"
#define KBUF_NAMES "kbuf%d"

/* kbuf module parameters */
static unsigned int kbuf_no = 1;
module_param(kbuf_no, uint, 0644);
MODULE_PARM_DESC(kbuf_no, "kbuf instances (default 1)");

static unsigned int kbuf_size = 1024;
module_param(kbuf_size, uint, 0644);
MODULE_PARM_DESC(kbuf_size, "kbuf buffer size (default 1 KByte)");

static dev_t kbuf_id;
static unsigned int kbuf_major = 0; /* let the system to choose the major */
static unsigned int kbuf_minor = 0; /* start allocating from minor 0 */

static struct class *kbuf_class;
static struct device *kbuf_device;

static struct kbuf_info {
	struct kfifo *kfifo;
	struct cdev cdev;
	struct mutex lock;
	wait_queue_head_t in_queue; /* queue of processes suspended on read */
	wait_queue_head_t out_queue; /* queue of processes suspended on write */
	struct fasync_struct *async_queue; /* asynchronous readers */
} *kbuf;

/**
 * kbuf_open - Opens the KBUF device.
 * @inode: inode pointer
 * @file: file pointer
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static int kbuf_open(struct inode *inode, struct file *file)
{
	struct kbuf_info *kbuf;

	pr_debug("%s(inode %p, file %p, flags %x)\n",
		__func__, inode, file, file->f_flags);

	/* retrieve the reference to kbuf from the inode and save it */
	kbuf = container_of(inode->i_cdev, struct kbuf_info, cdev);
	file->private_data = kbuf;

	return 0;
}

/**
 * kbuf_close - Closes the KBUF device.
 * @inode: inode pointer
 * @file: file pointer
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static int kbuf_close(struct inode *inode, struct file *file)
{
	struct kbuf_info *kbuf = file->private_data;

	pr_debug("%s(inode %p, file %p)\n",  __func__, inode, file);

	return fasync_helper(-1, file, 0, &kbuf->async_queue);
}

/**
 * kbuf_read - Reads from the KBUF device.
 * @file: file pointer
 * @buf: user buffer pointer
 * @count: size of the requested data transfer
 * @offp: file position pointer (not used)
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static ssize_t kbuf_read(struct file *file, char __user *buf,
	size_t count, loff_t *offp)
{
	struct kbuf_info *kbuf = file->private_data;
	char *tmpbuf;
	ssize_t retval;

	pr_debug("%s(file %p, buf %p, size %d, off %p)\n",
		__func__, file, buf, count, offp);

	if (mutex_lock_interruptible(&kbuf->lock)) {
		retval = -ERESTARTSYS;
		goto err1;
	}

	/* while there is no data in the buffer */
	while (kfifo_ready(kbuf->kfifo) == 0) {
		mutex_unlock(&kbuf->lock);
		/* return immediately if kbuf is open in non-blocking mode */
		if (file->f_flags & O_NONBLOCK) {
			pr_debug("%s(): no data, return on reading\n", __func__);
			retval = -EAGAIN;
			goto err1;
		}
		/* else suspend if kbuf is open in blocking (default) mode */
		pr_debug("%s(): no data, \"%s\" reading, going to sleep\n",
			__func__, current->comm);
		if (wait_event_interruptible(kbuf->in_queue, 
			kfifo_ready(kbuf->kfifo) != 0)) {
			retval = -ERESTARTSYS;
			goto err1;
		}
		/* reaquire the lock to check that data is really in the buffer */
		if (mutex_lock_interruptible(&kbuf->lock)) {
			retval = -ERESTARTSYS;
			goto err1;
		}
	}

	tmpbuf = kmalloc(count, GFP_KERNEL);
	if (!tmpbuf) {
		retval = -ENOMEM;
		goto err2;
	}
	retval = kfifo_read(kbuf->kfifo, tmpbuf, count);
	pr_debug("%s(): read %d bytes of %d \n", __func__, retval, count);
	if (copy_to_user(buf, tmpbuf, retval)) {
		retval = -EFAULT;
		goto err3;
	}
	kfree(tmpbuf);

	mutex_unlock(&kbuf->lock);

	/* awake any writer, there is now room in the buffer */
	wake_up_interruptible(&kbuf->out_queue);
	/* and signal asynchronous writers */
	if (kbuf->async_queue)
		kill_fasync(&kbuf->async_queue, SIGIO, POLL_OUT);

	return retval;

err3:
	kfree(tmpbuf);
err2:
	mutex_unlock(&kbuf->lock);
err1:
	return retval;
}

/**
 * kbuf_write - Writes to the KBUF device.
 * @file: file pointer
 * @buf: user buffer pointer
 * @count: size of the requested data transfer
 * @offp: file position pointer (not used)
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static ssize_t kbuf_write(struct file *file, const char __user *buf,
	size_t count, loff_t *offp)
{
	struct kbuf_info *kbuf = file->private_data;
	char *tmpbuf;
	ssize_t retval;

	pr_debug("%s(file %p, buf %p, size %d, off %p)\n",
		__func__, file, buf, count, offp);

	if (mutex_lock_interruptible(&kbuf->lock)) {
		retval = -ERESTARTSYS;
		goto err1;
	}

	/* while there is no room in the buffer */
	while (kfifo_free(kbuf->kfifo) == 0) {
		/* release the lock */
		mutex_unlock(&kbuf->lock);
		/* return immediately if kbuf is open in non-blocking mode */
		if (file->f_flags & O_NONBLOCK) {
			pr_debug("%s(): no room, return on writing\n", __func__);
			retval = -EAGAIN;
			goto err1;
		}
		/* suspend if kbuf is open in blocking (default) mode */
		pr_debug("%s(): no room, \"%s\" writing, going to sleep\n",
			__func__, current->comm);
		if (wait_event_interruptible(kbuf->out_queue, 
			kfifo_free(kbuf->kfifo) != 0)) {
			retval = -ERESTARTSYS;
			goto err1;
		}
		/* reaquire the lock to check that data is really in the buffer */
		if (mutex_lock_interruptible(&kbuf->lock)) {
			retval = -ERESTARTSYS;
			goto err1;
		}
	}

	tmpbuf = kmalloc(count, GFP_KERNEL);
	if (!tmpbuf) {
		retval = -ENOMEM;
		goto err2;
	}
	if (copy_from_user(tmpbuf, buf, count)) {
		retval = -EFAULT;
		goto err3;
	}
	retval = kfifo_write(kbuf->kfifo, tmpbuf, count);
	pr_debug("%s(): written %d bytes of %d \n", __func__, retval, count);
	kfree(tmpbuf);

	mutex_unlock(&kbuf->lock);
	
	/* awake any reader, there is now data in the buffer */
	wake_up_interruptible(&kbuf->in_queue);
	/* and signal asynchronous readers */
	if (kbuf->async_queue)
		kill_fasync(&kbuf->async_queue, SIGIO, POLL_IN);
	
	return retval;

err3:
	kfree(tmpbuf);
err2:
	mutex_unlock(&kbuf->lock);
err1:
	return retval;
}

/**
 * kbuf_poll - Poll the KBUF device.
 * @file: file pointer
 * @wait: poll table pointer
 * 
 * Returns a bit mask describing which operations could be completed immediately.
 */
static unsigned int kbuf_poll(struct file *file, poll_table *wait)
{
	struct kbuf_info *kbuf = file->private_data;
	unsigned int retval = 0;

	pr_debug("%s(file %p, polltable %p)\n", __func__, file, wait);

	if (mutex_lock_interruptible(&kbuf->lock)) {
		retval = POLLERR;
		goto err1;
	}

	poll_wait(file, &kbuf->in_queue, wait);
	poll_wait(file, &kbuf->out_queue, wait);

	if (kfifo_ready(kbuf->kfifo) != 0) {
		retval |= POLLIN | POLLRDNORM; /* readable */
	}
	if (kfifo_free(kbuf->kfifo) != 0) {
		retval |= POLLOUT | POLLWRNORM; /* writable */
	}

	mutex_unlock(&kbuf->lock);
	return retval;

err1:
	return retval;
}

/**
 * kbuf_ioctl - Controls and queries the KBUF device.
 * @inode: inode pointer
 * @file: file pointer
 * @cmd: ioctl command code
 * @arg: ioctl command argument
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static int kbuf_ioctl(struct inode *inode, struct file *file,
	unsigned int cmd, unsigned long arg)
{
	struct kbuf_info *kbuf = file->private_data;
	int retval = 0;

	pr_debug("%s(inode %p, file %p, cmd %d, arg %lx)\n",
		__func__, inode, file, cmd, arg);

	if (mutex_lock_interruptible(&kbuf->lock)) {
		retval = -ERESTARTSYS;
		goto err1;
	}

	switch (cmd) {
	case KBUF_IOCTL_SIZE_GET:
		if (put_user(kfifo_size(kbuf->kfifo), (int __user *)arg)) {
			retval = -EFAULT;
			goto err2;
		}
		break;
	case KBUF_IOCTL_FREE_GET:
		if (put_user(kfifo_free(kbuf->kfifo), (int __user *)arg)) {
			retval = -EFAULT;
			goto err2;
		}
		break;
	case KBUF_IOCTL_READY_GET:
		if (put_user(kfifo_ready(kbuf->kfifo), (int __user *)arg)) {
			retval = -EFAULT;
			goto err2;
		}
		break;
	default:
		retval = -ENOTTY; /* invalid ioctl command (hystoric) */
		goto err2;
	}

	mutex_unlock(&kbuf->lock);
	return retval;

err2:
	mutex_unlock(&kbuf->lock);
err1:
	return retval;
}

/**
 * kbuf_fasync - Notify to the KBUF device a change in its FASYNC flag.
 * @fd:
 * @file: file pointer
 * @mode:
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static int kbuf_fasync(int fd, struct file *file, int mode)
{
	struct kbuf_info *kbuf = file->private_data;

	pr_debug("%s(fd %d, file %p, mode %x)\n",  __func__, fd, file, mode);

	return fasync_helper(fd, file, mode, &kbuf->async_queue);
}

static const struct file_operations kbuf_fops = {
	.owner = THIS_MODULE,
	.open = kbuf_open,
	.release = kbuf_close,
	.read = kbuf_read,
	.write = kbuf_write,
	.ioctl = kbuf_ioctl,
	.poll = kbuf_poll,
	.fasync = kbuf_fasync
};

/**
 * kbuf_init(): Initializes the KBUF device.
 * 
 * Returns 0 if no error, standard error number otherwise.
 */
static int __init kbuf_init(void)
{
	int i, err, retval = 0;

	pr_debug("%s()\n", __func__);

	/* check module parameters */
	if (kbuf_no == 0 || kbuf_no > KBUF_MAX_NUM) {
		pr_err("%s(): invalid kbuf_no=%d \n", __func__, kbuf_no);
		retval = -EINVAL;
		goto err1;
	}
	if (kbuf_size > KBUF_MAX_SIZE) {
		pr_err("%s(): invalid kbuf_size=%d \n", __func__, kbuf_no);
		retval = -EINVAL;
		goto err1;
	}
	
	/* register chrdev region, get the major number */
	if (kbuf_major) {
		kbuf_id = MKDEV(kbuf_major, kbuf_minor);
		err = register_chrdev_region(kbuf_id, kbuf_no, KBUF_NAME);
	} else {
		err = alloc_chrdev_region(&kbuf_id, kbuf_minor, kbuf_no, KBUF_NAME);
		kbuf_major = MAJOR(kbuf_id);
	}
	if (err < 0) {
		pr_err("%s(): can't get major number %d\n", __func__, kbuf_major);
		retval = -ENODEV;
		goto err1;
        } 
	pr_debug("%s(): allocated major number %d\n", __func__, kbuf_major);

	/* init kbuf - to be done before calling cdev_add() */
	kbuf = kzalloc((kbuf_no * sizeof(struct kbuf_info)), GFP_KERNEL);
	if (!kbuf) {
		pr_err("%s(): can't create kbuf\n", __func__);
		retval = -ENOMEM;
		goto err2;
	}
	for (i = 0; i < kbuf_no; i++) {
		err =  kfifo_create(&kbuf[i].kfifo, kbuf_size);
		if (err < 0) {
			pr_err("%s(): can't create kfifo for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
			retval = -ENOMEM;
			goto err3;
	        } 
		pr_debug("%s(): created kfifo for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
		
		init_waitqueue_head(&kbuf[i].in_queue);
		init_waitqueue_head(&kbuf[i].out_queue);
		mutex_init(&kbuf[i].lock);
	}

	/* init and add cdev */
	for (i = 0; i < kbuf_no; i++) {
		cdev_init(&kbuf[i].cdev, &kbuf_fops);
		kbuf[i].cdev.owner = THIS_MODULE;
		err = cdev_add(&kbuf[i].cdev, MKDEV(kbuf_major, kbuf_minor + i), 1);
		if (err < 0) {
			pr_err("%s(): can't create cdev for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
			retval = -ENODEV;
			goto err4;
	        } 
		pr_debug("%s(): created cdev for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
	}

	/* register to sysfs and send uevents to create dev nodes */
	kbuf_class = class_create(THIS_MODULE, KBUF_NAME);
	for (i = 0; i < kbuf_no; i++) {
		kbuf_device = device_create(kbuf_class, NULL, 
			MKDEV(kbuf_major, kbuf_minor + i), NULL, KBUF_NAMES, i);
		pr_debug("%s(): created device node for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
	}

        return retval;

err4:
err3:
	kfree(kbuf);
err2:
	unregister_chrdev_region(kbuf_id, kbuf_no);
err1:
	return retval;
}

/**
 * kbuf_exit(): Terminates the KBUF device.
 */
static void __exit kbuf_exit(void)
{
	int i;

	pr_debug("%s()\n", __func__);

	/* unregister from sysfs and send uevents to destroy dev nodes */
	for (i = 0; i < kbuf_no; i++) {
		device_destroy(kbuf_class, MKDEV(kbuf_major, kbuf_minor + i));
		pr_debug("%s(): deleted device node for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
	}
	class_destroy(kbuf_class);

	/* delete cdev */
	for (i = 0; i < kbuf_no; i++) {
		cdev_del(&kbuf[i].cdev);
		pr_debug("%s(): deleted cdev for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
	}

	/* delete kbuf */
	for (i = 0; i < kbuf_no; i++) {
		kfifo_delete(kbuf[i].kfifo);
		pr_debug("%s(): deleted kfifo for device %d, %d\n",
			__func__, kbuf_major, kbuf_minor + i);
	}
	kfree(kbuf);
	
	/* unregister chrdev region, release the major number */
	unregister_chrdev_region(kbuf_id, kbuf_no);
	pr_debug("%s(): released major number %d\n", __func__, kbuf_major);

	return;
}

module_init(kbuf_init);
module_exit(kbuf_exit);

MODULE_DESCRIPTION("Paolo Rovelli - KBUF device driver");
MODULE_AUTHOR("Paolo Rovelli <paolorovelli@yahoo.it>");
MODULE_LICENSE("GPL");


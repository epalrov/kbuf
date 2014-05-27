/*
 * ktest.c - KBUF test utility
 *
 * Copyright (C) 2011 Paolo Rovelli
 *
 * Author: Paolo Rovelli <paolorovelli@yahoo.it>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include "kbuf.h"

#define KBUF_BUFFER_READ_SIZE (4 * 1024)

static void ktest_usage(FILE *out)
{
	static const char usage_str[] = (
		"Usage:\n  ktest [options] [function] devices\n\n"
		"Functions:\n"
		"  -r | --read       read from device (read)\n"
		"  -w | --write      write to device (write)\n"
		"  -p | --poll       poll devices (poll)\n"
		"  -i | --info       show devices info (ioctl)\n\n"
		"Options:\n"
		"  -b | --nonblock   open devices in non-blocking mode\n"
		"  -n | --nonewline  do not write the trailing newline\n"
		"  -v | --version    show the program version and exit\n"
		"  -h | --help       show this help and exit\n\n"
		"Examples:\n"
		"  ktest -b -r /dev/kbuf0\n"
		"  ktest -n -w \"something new\" /dev/kbuf0\n"
		"  ktest -i /dev/kbuf0 /dev/kbuf2\n"
		"  ktest -p /dev/kbuf*\n\n");

	fprintf(out, "%s", usage_str); 
	fflush(out);
	return;
}

static void ktest_version(FILE *out)
{
	static const char prog_str[] = "ktest";
	static const char ver_str[] = "1.0";
	static const char author_str[] = "Paolo Rovelli";

	fprintf(out, "%s %s written by %s\n", prog_str, ver_str, author_str);
	fflush(out);
	return;
}

static int ktest_read(int dev_no, char *dev[], int nonblock)
{
	int fd, flags, retval = 0;
	char *buf;
	size_t size;
	ssize_t count;

	if (dev_no != 1)
		fprintf(stderr, "Read only from %s\n", dev[0]);

	flags = nonblock ? (O_RDONLY | O_NONBLOCK) : (O_RDONLY);
	fd = open(dev[0], flags);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", dev[0]);
		retval = -1;
		goto err1;
	}
	size = KBUF_BUFFER_READ_SIZE;
	buf = malloc(size);
	if (buf == NULL) {
		fprintf(stderr, "Can't get memory\n");
		retval = -1;
		goto err2;
	}
	while (1) {
		count = read(fd, buf, size);
		if (count <= 0)
			break;
		count = write(fileno(stdout), buf, count);
	}
	free(buf);	
	close(fd);
	return retval;

err2:
	close(fd);
err1:
	return retval;
}

static int ktest_write(int dev_no, char *dev[], char *buf,
	size_t size, int nonblock, int nonewline)
{
	int fd, flags, retval = 0;
	ssize_t count;

	if (dev_no != 1)
		fprintf(stderr, "Write only to %s\n", dev[0]);

	flags = nonblock ? (O_WRONLY | O_NONBLOCK) : (O_WRONLY);
	fd = open(dev[0], flags);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", dev[0]);
		retval = -1;
		goto err1;
	}
	count = write(fd, buf, size);
	if (!nonewline) {
		count += write(fd, "\n", 1);
	}
	close(fd);
	return retval;

err1:
	return retval;
}

static int ktest_ioctl(int dev_no, char *dev[], int nonblock)
{
	int fd, flags, i, retval = 0;
	int dev_size, dev_free, dev_ready; 

	fprintf(stdout, "device\t\tsize\tfree\tready\n");
	fprintf(stdout, "-------------------------------------\n");

	flags = nonblock ? (O_RDONLY | O_NONBLOCK) : (O_RDONLY);
	for (i = 0; i < dev_no; i++) {
		fd = open(dev[i], flags);
		if (fd < 0) {
			fprintf(stderr, "Can't open %s\n", dev[i]);
			retval = -1;
			goto err1;
		}
		if (ioctl(fd, KBUF_IOCTL_SIZE_GET, &dev_size) < 0) {
			fprintf(stderr, "Can't ioctl %s\n", dev[i]);
			retval = -1;
			goto err2;
		}
		if (ioctl(fd, KBUF_IOCTL_FREE_GET, &dev_free) < 0) {
			fprintf(stderr, "Can't ioctl %s\n", dev[i]);
			retval = -1;
			goto err2;
		}
		if (ioctl(fd, KBUF_IOCTL_READY_GET, &dev_ready) < 0) {
			fprintf(stderr, "Can't ioctl %s\n", dev[i]);
			retval = -1;
			goto err2;
		}
		fprintf(stdout, "%s\t%d\t%d\t%d\n", dev[i], 
			dev_size, dev_free, dev_ready);
		close(fd);
	}
	return retval;

err2:
	close(fd);
err1:
	return retval;
}

static int ktest_poll(int dev_no, char *dev[], int nonblock)
{
	int flags, i, retval = 0;
	struct pollfd *fds;
	char *buf;
	size_t size;
	ssize_t count;

	flags = nonblock ? (O_RDONLY | O_NONBLOCK) : (O_RDONLY);
	fds = calloc(dev_no, sizeof(struct pollfd));
	for (i = 0; i < dev_no; i++) {
		fds[i].fd = open(dev[i], flags);
		fds[i].events = POLLIN;
		if (fds[i].fd < 0) {
			fprintf(stderr, "Can't open %s\n", dev[i]);
			retval = -1;
			goto err1;
		}
	}
	size = KBUF_BUFFER_READ_SIZE;
	buf = malloc(size);
	if (buf == NULL) {
		fprintf(stderr, "Can't get memory\n");
		retval = -1;
		goto err2;
	}
	while (1) {
		if (poll(fds, dev_no, -1) < 0) {
			fprintf(stderr, "Can't poll devices\n");
			retval = -1;
			goto err3;
		}
		for (i = 0; i < dev_no; i++) {
			if (fds[i].revents & POLLIN) { 
				count = read(fds[i].fd, buf, size);
				if (count < 0) {
					fprintf(stderr, "Can't read %s\n", dev[i]);
					retval = -1;
					goto err3;
				}
				count = write(fileno(stdout), buf, count);
				fds[i].revents &= ~POLLIN;
			}
		}
	}
	free(buf);
	for (i = 0; i < dev_no; i++)
		close(fds[i].fd);
	return retval;

err3:
	free(buf);
err2:
	for (i = 0; i < dev_no; i++)
		close(fds[i].fd);
err1:
	return retval;
}

static const struct option long_opts[] = {
	{ "read",        no_argument,       NULL, 'r' },
	{ "write",       required_argument, NULL, 'w' },
	{ "poll",        no_argument,       NULL, 'p' },
	{ "info",        no_argument,       NULL, 'i' },
	{ "nonblock",    no_argument,       NULL, 'b' },
	{ "nonewline",   no_argument,       NULL, 'n' },
	{ "version",     no_argument,       NULL, 'v' },
	{ "help",        no_argument,       NULL, 'h' },
	{  NULL,         0,                 NULL,  0  }
};

int main(int argc, char *argv[])
{
	int opt, opt_nonblock, opt_nonewline;
	int opt_read, opt_write, opt_poll, opt_info;
	char *arg_write;
	int retval = 0;

	/* default options */
	opt_nonblock = opt_nonewline = 0;
	opt_read = opt_write = opt_poll = opt_info = 0;
	arg_write = NULL;

	while ((opt = getopt_long(argc, argv, "rw:pibnvh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'r':
			opt_read = 1;
			break;
		case 'w':
			opt_write = 1;
			arg_write = optarg;
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'i':
			opt_info = 1;
			break;
		case 'b':
			opt_nonblock = 1;
			break;
		case 'n':
			opt_nonewline = 1;
			break;
		case 'v':
			ktest_version(stdout);
			exit(EXIT_SUCCESS);
		case 'h':
			ktest_usage(stdout);
			exit(EXIT_SUCCESS);
		default:
			ktest_usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (opt_read + opt_write + opt_poll + opt_info == 0) {
		fprintf(stderr, "You have to provide a function.\n");
		exit(EXIT_FAILURE);
	}
	if (opt_read + opt_write + opt_poll + opt_info > 1) {
		fprintf(stderr, "You have specified multiple functions.\n"
			"You can only perform one function at a time.\n");
		exit(EXIT_FAILURE);
	}
	if (argc == optind) {
		fprintf(stderr, "You have to provide at least a device.\n");
		exit(EXIT_FAILURE);
	}

	/* 
	 * after the options parsing, shift argc/argv to device nodes:
	 *  - argc: number of device nodes
	 *  - argv[0]: point to the first device node
	 */
	argc -= optind;
	argv += optind;

	if (opt_read) {
		retval = ktest_read(argc, argv, opt_nonblock);
	} else if (opt_write) {
		retval = ktest_write(argc, argv, arg_write, strlen(arg_write),
			opt_nonblock, opt_nonewline);
	} else if (opt_poll) {
		retval = ktest_poll(argc, argv, opt_nonblock);
	} else if (opt_info) {
		retval = ktest_ioctl(argc, argv, opt_nonblock);
	} else {
		retval = -1;
	}

	exit(retval == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}


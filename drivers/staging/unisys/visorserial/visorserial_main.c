/* visorserial_main.c
 *
 * Copyright (c) 2010 - 2014 UNISYS CORPORATION
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 */

#include "visorserial_private.h"
#include "linuxserial.h"
#include "linuxconsole.h"
#include "uisutils.h"
#include <linux/kfifo.h>

static dev_t majordevserial = -1;
				/**< indicates major num for serial devices */
static spinlock_t devnopool_lock;
static void *devnopool;	/**< pool to grab device numbers from */

static int visorserial_probe(struct visor_device *dev);
static void visorserial_remove(struct visor_device *dev);
static void visorserial_channel_interrupt(struct visor_device *dev);

#ifdef HAVE_UNLOCKED_IOCTL
static long visorserial_serial_ioctl(struct file *file,
				     unsigned int cmd, unsigned long arg);
#else
static int visorserial_serial_ioctl(struct inode *inode, struct file *file,
				    unsigned int cmd, unsigned long arg);
#endif
static int visorserial_serial_open(struct inode *inode, struct file *file);
static int visorserial_serial_release(struct inode *inode, struct file *file);
static ssize_t visorserial_serial_read(struct file *file,
				       char __user *buf,
				       size_t count, loff_t *ppos);
static ssize_t visorserial_serial_write(struct file *file,
					const char __user *buf,
					size_t count, loff_t *ppos);
static unsigned int visorserial_serial_poll(struct file *file,
					    poll_table *wait);

#define POLLJIFFIES     10

static void visorbus_enable_channel_interrupts(struct visor_device *dev);
static void visorbus_disable_channel_interrupts(struct visor_device *dev);

static int
simplebus_match(struct device *xdev, struct device_driver *xdrv)
{
	return 1;
}

/** This describes the TYPE of bus.
 *  (Don't confuse this with an INSTANCE of the bus.)
 */
static struct bus_type simplebus_type = {
	.name = "visorconsole",
	.match = simplebus_match,
};

static struct workqueue_struct *periodic_dev_workqueue;
static struct visor_device *standalonedevice;

static const struct file_operations visorserial_serial_fops = {
	.owner = THIS_MODULE,
	.open = visorserial_serial_open,
	.read = visorserial_serial_read,
	.write = visorserial_serial_write,
	.release = visorserial_serial_release,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = visorserial_serial_ioctl,
#else
	.ioctl = visorserial_serial_ioctl,
#endif
	.poll = visorserial_serial_poll,
};

/** These are all the counters we maintain for each device.
 *  They will all be reported under /sys/bus/visorbus/devices/<devicename>.
 */
struct devdata_counters {
	u64 host_bytes_in;   /**< bytes we have input from the host */
	u64 host_bytes_out;  /**< bytes we have output to the host */
	u64 umode_bytes_in;  /**< bytes we have input from user mode */
	u64 umode_bytes_out; /**< bytes we have output to user mode */
};

/** These are all the devdata properties we maintain for each device.
 *  They will all be reported under /sys/bus/visorbus/devices/<devicename>.
 */
enum visorserial_devdata_properties {
	prop_openfile_count,
	/* Add items above, but don't forget to modify
	 * register_devdata_attributes whenever you do...
	 */
	prop_DEVDATAMAX
};

/** This is the private data that we store for each device.
 *  A pointer to this struct is kept in each "struct device", and can be
 *  obtained using visor_get_drvdata(dev).
 */
struct visorserial_devdata {
	int devno;
	struct visor_device *dev;
	/** lock for dev */
	struct rw_semaphore lock_visor_dev;
	char name[99];
	struct list_head list_all;   /**< link within list_all_devices list */
	/** head of list of visorserial_filedata_serial structs, linked
	 *  via the list_all member */
	struct list_head list_files_serial;
	uint open_file_count;
	/** lock for list_files_serial */
	rwlock_t lock_files;
	/** lock for open_file_count */
	struct rw_semaphore lock_open_file_count;
	struct devdata_counters counter;
	struct device_attribute devdata_property[prop_DEVDATAMAX];
	struct kref kref;
	struct cdev cdev_serial;
	int xmitqueue;
	int recvqueue;
	struct linux_serial *linuxserial;
};

/** List of all visorserial_devdata structs, linked via the list_all member */
static LIST_HEAD(list_all_devices);
static DEFINE_SPINLOCK(lock_all_devices);

#define devdata_put(devdata, why)					\
	{								\
		int refcount;						\
		kref_put(&devdata->kref, devdata_release);		\
		refcount = atomic_read(&devdata->kref.refcount);	\
	}
#define devdata_get(devdata, why)					\
	{								\
		int refcount;						\
		kref_get(&devdata->kref);				\
		refcount = atomic_read(&devdata->kref.refcount);	\
	}

/** This is the private data that we store for each file descriptor that is
 *  opened to the "serial" character device.
 */
struct visorserial_filedata_serial {
	struct visorserial_devdata *devdata;
	/** link within devdata.list_files_serial list */
	struct list_head list_all;
	/** tasks queued here are waiting for read data */
	wait_queue_head_t waiting_readers;
	struct kfifo *data_from_host;
	unsigned char buf[NFILEWRITEBYTESTOBUFFER];
};

static void new_char_from_host(struct visorserial_devdata *devdata, u8 c);
static void new_char_to_host(void *context, u8 c);
static void serial_destroy_file(struct visorserial_filedata_serial *filedata);
static void host_side_disappeared(struct visorserial_devdata *devdata);

/*  DEVICE attributes
 *
 *  define & implement display of device attributes under
 *  /sys/bus/visorbus/devices/<devicename>.
 *
 */

static ssize_t
devdata_property_show(struct device *ddev,
		      struct device_attribute *attr, char *buf)
{
	struct visorserial_devdata *devdata = dev_get_drvdata(ddev);
	ulong offset = (ulong) (attr) - (ulong) (devdata->devdata_property);
	ulong ix = offset / sizeof(struct device_attribute);

	if (ix >= prop_DEVDATAMAX) {
		pr_err("%s:%d trouble in paradise; ix=%lu\n",
		       __FILE__, __LINE__, ix);
		return 0;
	}
	switch (ix) {
	case prop_openfile_count:
		return sprintf(buf, "%u\n", devdata->open_file_count);
	default:
		pr_err("%s:%d trouble in paradise; ix=%lu\n",
		       __FILE__, __LINE__, ix);
		return 0;
	}
	return 0;
}

static int
register_devdata_attributes(struct visor_device *dev)
{
	int i, rc = 0;
	struct visorserial_devdata *devdata = visor_get_drvdata(dev);
	struct device_attribute *pattr = devdata->devdata_property;

	pattr[prop_openfile_count].attr.name = "open_file_count";
	for (i = 0; i < prop_DEVDATAMAX; i++) {
		pattr[i].attr.mode = S_IRUGO;
		pattr[i].show = devdata_property_show;
		pattr[i].store = NULL;
		rc = device_create_file(&dev->device, &pattr[i]);
		if (rc < 0)
				return rc;
	}
	return 0;
}

static int
register_device_attributes(struct visor_device *dev)
{
	return register_devdata_attributes(dev);
}

static int
unregister_devdata_attributes(struct visor_device *dev)
{
	int i;

	struct visorserial_devdata *devdata = visor_get_drvdata(dev);
	struct device_attribute *pattr = devdata->devdata_property;

	for (i = 0; i < prop_DEVDATAMAX; i++)
		device_remove_file(&dev->device, &pattr[i]);
	return 0;
}

static int
unregister_device_attributes(struct visor_device *dev)
{
	unregister_devdata_attributes(dev);
	return 0;
}

static struct visorserial_devdata *
devdata_create(struct visor_device *dev)
{
	void *rc = NULL;
	struct visorserial_devdata *devdata = NULL;
	int devno = -1;

	devdata = kmalloc(sizeof(*devdata),
			  GFP_KERNEL|__GFP_NORETRY);
	if (devdata == NULL)
			goto cleanups;

	memset(devdata, '\0', sizeof(struct visorserial_devdata));
	cdev_init(&devdata->cdev_serial, NULL);
	spin_lock(&devnopool_lock);
	devno = find_first_zero_bit(devnopool, MAXDEVICES);
	set_bit(devno, devnopool);
	spin_unlock(&devnopool_lock);
	if (devno == MAXDEVICES)
		devno = -1;
	if (devno < 0)
			goto cleanups;

	devdata->devno = devno;
	devdata->dev = dev;
	dev_set_name(&devdata->dev->device, devdata->name);
	devdata->xmitqueue = 0;
	devdata->recvqueue = 1;
	if (visorserial_rxtxswap && ((devno % 2) == 0)) {
		devdata->xmitqueue = 1;
		devdata->recvqueue = 0;
	}

	cdev_init(&devdata->cdev_serial, &visorserial_serial_fops);
	devdata->cdev_serial.owner = THIS_MODULE;
	if (cdev_add(&devdata->cdev_serial,
		     MKDEV(MAJOR(majordevserial), devdata->devno), 1) < 0) {
		goto cleanups;
	}

	rwlock_init(&devdata->lock_files);
	init_rwsem(&devdata->lock_open_file_count);
	init_rwsem(&devdata->lock_visor_dev);
	INIT_LIST_HEAD(&devdata->list_files_serial);
	kref_init(&devdata->kref);

	spin_lock(&lock_all_devices);
	list_add_tail(&devdata->list_all, &list_all_devices);
	spin_unlock(&lock_all_devices);

	if (visorserial_createttydevice)
		devdata->linuxserial = linuxserial_create(devno, devdata,
							  new_char_to_host);
	if (devdata->linuxserial != NULL)
		/* since we may have a tty attached, we will need to get
		 * interrupted when data comes in on the channel so we can
		 * deliver it to the tty
		 */
		visorbus_enable_channel_interrupts(devdata->dev);

	rc = devdata;
cleanups:
	if (rc == NULL) {
		if (devno >= 0)	{
			spin_lock(&devnopool_lock);
			clear_bit(devno, devnopool);
			spin_unlock(&devnopool_lock);
		}
		if (devdata != NULL) {
			if (devdata->cdev_serial.ops != NULL)
				cdev_del(&devdata->cdev_serial);
			kfree(devdata);
		}
	}
	return rc;
}

static void
devdata_release(struct kref *mykref)
{
	struct visorserial_devdata *devdata = container_of(mykref,
							   struct
							   visorserial_devdata,
							   kref);
	spin_lock(&devnopool_lock);
	clear_bit(devdata->devno, devnopool);
	spin_unlock(&devnopool_lock);
	spin_lock(&lock_all_devices);
	list_del(&devdata->list_all);
	spin_unlock(&lock_all_devices);
	cdev_del(&devdata->cdev_serial);
	if (devdata->linuxserial) {
		linuxserial_destroy(devdata->linuxserial);
		devdata->linuxserial = NULL;
		down_read(&devdata->lock_visor_dev);
		if (devdata->dev != NULL)
			visorbus_disable_channel_interrupts(devdata->dev);
		up_read(&devdata->lock_visor_dev);
	}
	kfree(devdata);
}

static int
visorserial_probe(struct visor_device *dev)
{
	struct visorserial_devdata *devdata = NULL;

	devdata = devdata_create(dev);
	if (devdata == NULL)
			return -1;

	if (ULTRA_CONSOLE_CHANNEL_OK_CLIENT
	    (visorchannel_get_header(dev->visorchannel), NULL) ||
	    ULTRA_CONSOLESERIAL_CHANNEL_OK_CLIENT
	    (visorchannel_get_header(dev->visorchannel), NULL))
		;
	else
		return -1;

	visor_set_drvdata(dev, devdata);
	if (register_device_attributes(dev) < 0)
			return -1;

	return 0;
}

static void
visorserial_remove(struct visor_device *dev)
{
	struct visorserial_devdata *devdata = visor_get_drvdata(dev);

	if (devdata == NULL)
			return;

	unregister_device_attributes(dev);
	visor_set_drvdata(dev, NULL);
	host_side_disappeared(devdata);
}

static void
visorserial_channel_interrupt(struct visor_device *dev)
{
	u8 data;
	struct visorserial_devdata *devdata = visor_get_drvdata(dev);

	if (devdata == NULL)
			return;

	while (visorchannel_signalremove(dev->visorchannel,
					 devdata->recvqueue, &data)) {
		new_char_from_host(devdata, data);
		devdata->counter.host_bytes_in++;
	}
}

static void
destroy_visor_device(struct visor_device *dev)
{
	if (dev == NULL)
		return;
	if (dev->periodic_work != NULL) {
		visor_periodic_work_destroy(dev->periodic_work);
		dev->periodic_work = NULL;
	}
	if (dev->visorchannel != NULL) {
		visorchannel_destroy(dev->visorchannel);
		dev->visorchannel = NULL;
	}
	kfree(dev);
}

static void
simplebus_release_device(struct device *xdev)
{
	struct visor_device *dev = to_visor_device(xdev);

	destroy_visor_device(dev);
}

static void
dev_periodic_work(void *xdev)
{
	struct visor_device *dev = (struct visor_device *)xdev;

	visorserial_channel_interrupt(dev);
	if (!visor_periodic_work_nextperiod(dev->periodic_work))
		put_visordev(dev, "delayed work", visorserial_debugref);
}

static void
dev_start_periodic_work(struct visor_device *dev)
{
	if (dev->being_removed)
		return;
	/* now up by at least 2 */
	get_visordev(dev, "delayed work", visorserial_debugref);
	if (!visor_periodic_work_start(dev->periodic_work))
		put_visordev(dev, "delayed work", visorserial_debugref);
}

static void
dev_stop_periodic_work(struct visor_device *dev)
{
	if (visor_periodic_work_stop(dev->periodic_work))
		put_visordev(dev, "delayed work", visorserial_debugref);
}

static void
visorbus_enable_channel_interrupts(struct visor_device *dev)
{
	dev_start_periodic_work(dev);
}

static void
visorbus_disable_channel_interrupts(struct visor_device *dev)
{
	dev_stop_periodic_work(dev);
}

static struct visor_device *
create_visor_device(u64 addr)
{
	struct visor_device *rc = NULL;
	struct visorchannel *visorchannel = NULL;
	struct visor_device *dev = NULL;
	BOOL gotten = FALSE;
	uuid_le guid = ULTRA_CONSOLE_CHANNEL_PROTOCOL_GUID;

	/* prepare chan_hdr (abstraction to read/write channel memory) */
	visorchannel =
	    visorchannel_create(addr, 0 /*size in chan hdr */ , guid);
	if (visorchannel == NULL)
			goto cleanups;

	dev = kmalloc(sizeof(dev), GFP_KERNEL|__GFP_NORETRY);
	if (dev == NULL)
			goto cleanups;

	memset(dev, 0, sizeof(struct visor_device));
	dev->visorchannel = visorchannel;
	sema_init(&dev->visordriver_callback_lock, 1);	/* unlocked */
	dev->device.bus = &simplebus_type;
	device_initialize(&dev->device);
	dev->device.release = simplebus_release_device;
	/* keep a reference just for us */
	get_visordev(dev, "create", visorserial_debugref);
	gotten = TRUE;
	dev->periodic_work = visor_periodic_work_create(POLLJIFFIES,
							periodic_dev_workqueue,
							dev_periodic_work,
							dev,
							dev_name(&dev->device));
	if (dev->periodic_work == NULL)
			goto cleanups;

	/* bus_id must be a unique name with respect to this bus TYPE
	 * (NOT bus instance).  That's why we need to include the bus
	 * number within the name.
	 */
	dev_set_name(&dev->device, "visorconsole");

	if (device_add(&dev->device) < 0)
			goto cleanups;
	/* note: device_register is simply device_initialize + device_add */
	rc = dev;
cleanups:
	if (rc == NULL) {
		if (gotten)
			put_visordev(dev, "create", visorserial_debugref);
		if (dev != NULL) {
			destroy_visor_device(dev);
			dev = NULL;
		}
	}
	return rc;
}

static void
visorserial_cleanup_guts(void)
{
	if (standalonedevice) {
		standalonedevice->being_removed = TRUE;
		/* ensure that the being_removed flag is set before
		 * continuing
		 */
		wmb();
		dev_stop_periodic_work(standalonedevice);
		lxcon_console_offline(standalonedevice);
		visorserial_remove(standalonedevice);
		put_visordev(standalonedevice, "create", visorserial_debugref);
		device_unregister(&standalonedevice->device);
		standalonedevice = NULL;
	}
	flush_workqueue(periodic_dev_workqueue); /* better not be any work! */
	destroy_workqueue(periodic_dev_workqueue);
	periodic_dev_workqueue = NULL;
	bus_unregister(&simplebus_type);
	if (MAJOR(majordevserial) >= 0) {
		unregister_chrdev_region(majordevserial, MAXDEVICES);
		majordevserial = MKDEV(0, 0);
	}
	if (devnopool != NULL) {
		kfree(devnopool);
		devnopool = NULL;
	}
}

int __init
visorserial_init(void)
{
	int rc = -1;
	u64 visorserial_addr = 0;

	majordevserial = MKDEV(0, 0);
	spin_lock_init(&devnopool_lock);
	devnopool = kzalloc(BITS_TO_LONGS(MAXDEVICES), GFP_KERNEL);
	if (devnopool == NULL)
			goto cleanups;

	if (alloc_chrdev_region(&majordevserial, 0, MAXDEVICES,
				MYDRVNAME "_serial") < 0) {
		goto cleanups;
	}
	rc = bus_register(&simplebus_type);
	if (rc < 0)
			goto cleanups;

	periodic_dev_workqueue = create_singlethread_workqueue("visorconsole");
	if (periodic_dev_workqueue == NULL) {
		rc = -ENOMEM;
		goto cleanups;
	}
	if (!visorserial_channeladdress) {
		if (!VMCALL_SUCCESSFUL
		    (issue_vmcall_io_visorserial_addr(&visorserial_addr))) {
			rc = -1;
			goto cleanups;
		}
		visorserial_channeladdress = visorserial_addr;
	}
	standalonedevice =
	    create_visor_device(visorserial_channeladdress);
	if (standalonedevice == NULL) {
		rc = -1;
		goto cleanups;
	}
	if (visorserial_probe(standalonedevice) < 0) {
		rc = -1;
		goto cleanups;
	}
	if (visor_get_drvdata(standalonedevice) != NULL)
		lxcon_console_online(visor_get_drvdata(standalonedevice),
				     new_char_to_host);

	rc = 0;
cleanups:
	if (rc < 0)
		visorserial_cleanup_guts();
	return rc;
}

static void
visorserial_cleanup(void)
{
	visorserial_cleanup_guts();
}

static struct visorserial_filedata_serial *
serial_create_file(struct visorserial_devdata *devdata)
{
	void *rc = NULL;
	struct visorserial_filedata_serial *filedata = NULL;

	filedata = kmalloc(sizeof(*devdata),
			   GFP_KERNEL|__GFP_NORETRY);
	if (filedata == NULL) {
		rc = NULL;
		goto cleanups;
	}
	filedata->devdata = devdata;
	devdata_get(devdata, "create_file");
	filedata->data_from_host = NULL;
	init_waitqueue_head(&filedata->waiting_readers);
	kfifo_alloc(filedata->data_from_host, NHOSTBYTESTOBUFFER, GFP_KERNEL);
	if (filedata->data_from_host == NULL) {
		rc = NULL;
		goto cleanups;
	}
	rc = filedata;
cleanups:
	if (rc == NULL) {
		if (filedata != NULL) {
			serial_destroy_file(filedata);
			filedata = NULL;
		}
	}
	return rc;
}

static void
serial_destroy_file(struct visorserial_filedata_serial *filedata)
{
	if (filedata->data_from_host != NULL) {
		kfifo_free(filedata->data_from_host);
		filedata->data_from_host = NULL;
	}
	devdata_put(filedata->devdata, "create_file");
	kfree(filedata);
}

static void
serial_new_host_char(struct visorserial_filedata_serial *filedata, u8 c)
{
	kfifo_in(filedata->data_from_host, filedata->buf, c);
	wake_up(&filedata->waiting_readers);
}

static void
new_char_from_host(struct visorserial_devdata *devdata, u8 c)
{
	struct list_head *listentry, *listtmp;

	read_lock(&devdata->lock_files);
	list_for_each_safe(listentry, listtmp, &devdata->list_files_serial) {
		struct visorserial_filedata_serial *filedata =
		    list_entry(listentry, struct visorserial_filedata_serial,
			       list_all);
		serial_new_host_char(filedata, c);
	}
	if (devdata->linuxserial != NULL)
		linuxserial_rx_char(devdata->linuxserial, c);
	read_unlock(&devdata->lock_files);
}

static void
new_char_to_host(void *context, u8 c)
{
	struct visorserial_devdata *devdata =
	    (struct visorserial_devdata *)(context);
	int done = 0;

	if (devdata->dev == NULL)
			return;

	while (!done) {
		if (visorchannel_signalinsert(devdata->dev->visorchannel,
					      devdata->xmitqueue, &c)) {
			devdata->counter.host_bytes_out++;
			done = 1;
		} else if (OK_TO_BLOCK_FOR_CONSOLE) {
			/* bug here; counter will show that we dropped
			* chars, when we actually didn't
			*/
			int i;

			for (i = 0; i < 100000; i++)
				cpu_relax();
		} else {
			done = 1;
	     }
	}
}

static void
host_side_disappeared(struct visorserial_devdata *devdata)
{
	struct list_head *listentry, *listtmp;

	down_write(&devdata->lock_visor_dev);
	sprintf(devdata->name, "<dev#%d-history>", devdata->devno);
	devdata->dev = NULL;	/* indicate device destroyed */
	up_write(&devdata->lock_visor_dev);
	read_lock(&devdata->lock_files);
	list_for_each_safe(listentry, listtmp, &devdata->list_files_serial) {
		struct visorserial_filedata_serial *filedata =
		    list_entry(listentry, struct visorserial_filedata_serial,
			       list_all);
		wake_up(&filedata->waiting_readers);
	}
	read_unlock(&devdata->lock_files);
}

static BOOL
serial_ready_to_read(struct visorserial_filedata_serial *filedata)
{
	if (!kfifo_is_empty(filedata->data_from_host))
		return TRUE;
	if (filedata->devdata->dev == NULL)	/* channel disappeared */
		return TRUE;
	return FALSE;
}

static void
first_file_opened(struct visorserial_filedata_serial *filedata)
{
	struct visorserial_devdata *devdata = filedata->devdata;

	if (devdata->linuxserial == NULL) {
		down_read(&devdata->lock_visor_dev);
		if (devdata->dev != NULL)
			visorbus_enable_channel_interrupts(devdata->dev);
		up_read(&devdata->lock_visor_dev);
	}
}

static void
last_file_closed(struct visorserial_filedata_serial *filedata)
{
	struct visorserial_devdata *devdata = filedata->devdata;

	if (devdata->linuxserial == NULL) {
		down_read(&devdata->lock_visor_dev);
		if (devdata->dev != NULL)
			visorbus_disable_channel_interrupts(devdata->dev);
		up_read(&devdata->lock_visor_dev);
	}
}

static int
visorserial_serial_open(struct inode *inode, struct file *file)
{
	struct visorserial_devdata *devdata = NULL;
	struct visorserial_filedata_serial *filedata = NULL;
	unsigned minor_number = iminor(inode);

	list_for_each_entry(devdata, &list_all_devices, list_all) {
		if (devdata->devno == minor_number) {
			filedata = serial_create_file(devdata);
			if (filedata == NULL)
					return -ENOMEM;

			file->private_data = filedata;
			write_lock(&devdata->lock_files);
			list_add_tail(&filedata->list_all,
				      &devdata->list_files_serial);
			write_unlock(&devdata->lock_files);
			down_write(&devdata->lock_open_file_count);
			devdata->open_file_count++;
			if (devdata->open_file_count == 1)
				first_file_opened(filedata);
			up_write(&devdata->lock_open_file_count);
			return 0;
		}
	}
	return -ENODEV;
}

static int
visorserial_serial_release(struct inode *inode, struct file *file)
{
	struct visorserial_filedata_serial *filedata =
	    (struct visorserial_filedata_serial *)(file->private_data);
	struct visorserial_devdata *devdata = NULL;

	if (filedata == NULL)
			return -1;

	devdata = filedata->devdata;
	if (devdata == NULL)
			return -1;

	down_write(&devdata->lock_open_file_count);
	if (devdata->open_file_count == 1)
		last_file_closed(filedata);
	devdata->open_file_count--;
	up_write(&devdata->lock_open_file_count);
	write_lock(&devdata->lock_files);
	list_del(&filedata->list_all);
	write_unlock(&devdata->lock_files);
	serial_destroy_file(filedata);
	file->private_data = NULL;
	return 0;
}

#ifdef HAVE_UNLOCKED_IOCTL
static long
visorserial_serial_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int
visorserial_serial_ioctl(struct inode *inode, struct file *file,
			 unsigned int cmd, unsigned long arg)
#endif
{
	struct visorserial_filedata_serial *filedata =
	    (struct visorserial_filedata_serial *)(file->private_data);
	struct visorserial_devdata *devdata = NULL;

	if (filedata == NULL)
			return -1;

	devdata = filedata->devdata;
	if (devdata == NULL)
			return -1;
	return 0;
}

static ssize_t
visorserial_serial_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	int readchars = 0, mycount = count;
	struct visorserial_filedata_serial *filedata =
	    (struct visorserial_filedata_serial *)(file->private_data);
	struct visorserial_devdata *devdata = NULL;
	loff_t pos = *ppos;

	if (pos < 0)
		return -EINVAL;

	if (pos > 0 || !count)
		return 0;

	if (filedata == NULL)
			return -1;

	devdata = filedata->devdata;
	if (devdata == NULL)
			return -1;

	if (file->f_flags & O_NONBLOCK)
		if (!serial_ready_to_read(filedata))
				return -EAGAIN;
	if (mycount > NFILEREADBYTESTOBUFFER)
		mycount = NFILEREADBYTESTOBUFFER;
	while (readchars <= 0) {
		wait_event_interruptible(filedata->waiting_readers,
					 serial_ready_to_read(filedata));
		if (signal_pending(current))
				return -EINTR;
		if (devdata->dev == NULL)
				return 0;
		readchars = kfifo_out(filedata->data_from_host,
				      filedata->buf, mycount);
	}
	if (copy_to_user(buf, filedata->buf, readchars))
			return -EFAULT;
	devdata->counter.umode_bytes_out += readchars;
	*ppos += readchars;
	return readchars;
}

static ssize_t
visorserial_serial_write(struct file *file,
			 const char __user *buf, size_t count, loff_t *ppos)
{
	int i = 0, writechars = 0;
	struct visorserial_filedata_serial *filedata =
	    (struct visorserial_filedata_serial *)(file->private_data);
	struct visorserial_devdata *devdata = NULL;

	if (filedata == NULL)
			return -1;

	devdata = filedata->devdata;
	if (devdata == NULL)
			return -1;

	if (count > NFILEWRITEBYTESTOBUFFER)
		count = NFILEWRITEBYTESTOBUFFER;
	if (copy_from_user(filedata->buf, buf, count))
			return -EFAULT;
	devdata->counter.umode_bytes_in += count;
	down_read(&devdata->lock_visor_dev);
	if (devdata->dev == NULL) {	/* host channel is gone */
		up_read(&devdata->lock_visor_dev);
		return 0;
	}

	for (i = 0; i < count; i++) {
		devdata->counter.host_bytes_out++;
		writechars++;
	}
	up_read(&devdata->lock_visor_dev);

	return count;
}

static unsigned int
visorserial_serial_poll(struct file *file, poll_table *wait)
{
	struct visorserial_filedata_serial *filedata =
	    (struct visorserial_filedata_serial *)(file->private_data);
	struct visorserial_devdata *devdata = NULL;

	if (filedata == NULL)
			return -1;

	devdata = filedata->devdata;
	if (devdata == NULL)
			return -1;

	poll_wait(file, &filedata->waiting_readers, wait);
	if (serial_ready_to_read(filedata))
			return POLLIN | POLLRDNORM;
	return 0;
}

module_param_named(rxtxswap, visorserial_rxtxswap, int, S_IRUGO);
MODULE_PARM_DESC(visorserial_rxtxswap,
		 "non-0 if you want even-numbered devices to have their receive and transmit wires crossed");
int visorserial_rxtxswap = 1;

module_param_named(createttydevice, visorserial_createttydevice,
		   int, S_IRUGO);
MODULE_PARM_DESC(visorserial_createttydevice,
		 "non-0 if you want to create a tty device for each visorserial device, suitable for logins and getty");
int visorserial_createttydevice = 1;

module_param_named(channeladdress, visorserial_channeladdress,
		   ulong, S_IRUGO);
MODULE_PARM_DESC(visorserial_channeladdress,
		 "if a specific console channel is to be used, and there is no visor bus, specify the physical address of the channel here");
ulong visorserial_channeladdress = 0;

module_param_named(clearchannel, visorserial_clearchannel,
		   int, S_IRUGO);
MODULE_PARM_DESC(visorserial_clearchannel,
		 "non-0 when you want to forcibly initialize the channel to a known-good state before first using it");
int visorserial_clearchannel = 0;

module_param_named(debug, visorserial_debug, int, S_IRUGO);
MODULE_PARM_DESC(visorserial_debug, "1 to debug");
int visorserial_debug = 0;

module_param_named(debugref, visorserial_debugref, int, S_IRUGO);
MODULE_PARM_DESC(visorserial_debugref, "1 to debug reference counts");
int visorserial_debugref = 0;

module_init(visorserial_init);
module_exit(visorserial_cleanup);

MODULE_AUTHOR("Unisys");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervisor visorserial driver for service partition: ver "
		   VERSION);
MODULE_VERSION(VERSION);

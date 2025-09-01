#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/signal.h>
#include <linux/kfifo.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/idr.h>
#include <linux/dma-map-ops.h>
#include "kirin_pcie.h"

#define DMA_IN_SIZE (64 * 1024 * 1024)
#define DMA_OUT_SIZE (128 * 1024)
#define BAR_IO_SIZE (4 * 1024 * 1024)

struct kirin_pdriver_dev {
	struct fasync_struct *fasync_ptr;
	struct cdev chrdev;
	struct pci_dev *pdev;
	dev_t devnum;
	int instance;
	size_t dma_in_size;
	size_t dma_out_size;
	dma_addr_t dma_addr_in;
	dma_addr_t dma_addr_out;
	void __iomem *cpuaddr_in;
	void __iomem *cpuaddr_out;
	void __iomem *ioremap_base;
	struct class *class;
	struct device *device;          // Device structure for the char device
	char device_name[40];
	char driver_name[40];
	int major;
};

#define PCIE_DEV_NAME "fpcie"
#define DRIVER_NAME "kirin_pcie"
#define CLASS_NAME "fpcie_class"
#define PCIE_DEV_MINORS		(1U << MINORBITS)

static struct pci_device_id kirin_pcie_id_table[] = {
	{ PCI_DEVICE(0x10EE, 0x7024) },
	{ 0, } /* 表结尾 */
};
MODULE_DEVICE_TABLE(pci, kirin_pcie_id_table);

static DEFINE_IDA(kirin_pcie_ida);

static irqreturn_t kirin_pcie_isr(int irq, void *dev_id)
{
	struct pci_dev *pdev = (struct pci_dev *)dev_id;
	__maybe_unused struct kirin_pdriver_dev *kirin_pdev = dev_get_drvdata(&pdev->dev);
	dev_info(&pdev->dev, "Interrupt received\n");
	kill_fasync(&kirin_pdev->fasync_ptr, SIGIO, POLL_IN);

	return IRQ_HANDLED;
}

static int kirin_device_open(struct inode *inode, struct file *file)
{
	__maybe_unused const char *device_name = file->f_path.dentry->d_iname;
	file->private_data = container_of(inode->i_cdev, struct kirin_pdriver_dev, chrdev);
	printk(KERN_INFO "Device %s opened\n", device_name);

	return 0;
}

static int kirin_device_release(struct inode *inode, struct file *file)
{
	__maybe_unused const char *device_name = file->f_path.dentry->d_iname;
	struct kirin_pdriver_dev *kirin_pdev = file->private_data;
	printk(KERN_INFO "Device %s closed\n", device_name);
	fasync_helper(-1, file, 0, &kirin_pdev->fasync_ptr);

	return 0;
}

static int kirin_device_async(int fd, struct file *file, int on)
{
	struct kirin_pdriver_dev *kirin_pdev = file->private_data;
	printk(KERN_INFO "fasync called\n");
	return fasync_helper(fd, file, on, &kirin_pdev->fasync_ptr);
}

static long kirin_device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -1;
	return ret;
}

static int kirin_pcie_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct kirin_pdriver_dev *dev = filp->private_data;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size   = vma->vm_end - vma->vm_start;
	unsigned long barsize = pci_resource_len(dev->pdev, 0);
	unsigned long pfn;

	if (offset + size <= barsize) {
		pfn = (pci_resource_start(dev->pdev, 0) + offset) >> PAGE_SHIFT;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	} else if (offset + size <= barsize + dev->dma_in_size) {
		pfn = dev->dma_addr_in >> PAGE_SHIFT;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	} else if (offset + size <= barsize + dev->dma_in_size + dev->dma_out_size) {
		pfn = dev->dma_addr_out >> PAGE_SHIFT;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	} else {
		return -EINVAL;
	}

	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = kirin_device_open,
	.unlocked_ioctl = kirin_device_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= kirin_device_ioctl,
#endif
	.release = kirin_device_release,
	.fasync = kirin_device_async,
	.mmap = kirin_pcie_mmap,
};

static int kirin_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err;
	int devnum;
	int major;
	void __iomem *ioremap_base = NULL;
	struct kirin_pdriver_dev *kirin_pdev = NULL;
	char class_name[40];

	dev_info(&pdev->dev, "PCIe device probed\n");

	kirin_pdev = kzalloc(sizeof(*kirin_pdev), GFP_KERNEL);
	if (kirin_pdev == NULL) {
		dev_err(&pdev->dev, "alloc kirin pcie pdev failed!\n");
		return -EFAULT;
	}

	kirin_pdev->instance = -1;
	/* register the cdev */
	err = ida_alloc(&kirin_pcie_ida, GFP_KERNEL);
	if (err < 0) {
		dev_err(&pdev->dev, "alloc kirin pcie ida failed!\n");
		kfree(kirin_pdev);
		return -EFAULT;
	}

	kirin_pdev->instance = devnum = err;
	sprintf(kirin_pdev->device_name, PCIE_DEV_NAME"%d", devnum);
	sprintf(kirin_pdev->driver_name, DRIVER_NAME"%d", kirin_pdev->instance);

	/* enable pcie device */
	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable device\n");
		ida_free(&kirin_pcie_ida, kirin_pdev->instance);
		kfree(kirin_pdev);
		return err;
	}

	/* alloc pcie pcie request */
	err = pci_request_regions(pdev, kirin_pdev->driver_name);
	if (err) {
		dev_err(&pdev->dev, "Failed to request regions\n");
		pci_disable_device(pdev);
		ida_free(&kirin_pcie_ida, kirin_pdev->instance);
		kfree(kirin_pdev);
		return err;
	}

	/* set dma operation bitmask */
	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "No suitable DMA available\n");
			goto err_rel;
		}
	}

	/* get the pcie bar address for cpu access */
	u8 idx = 0;
	ioremap_base = pci_iomap(pdev, idx, pci_resource_len(pdev, idx));
	if (!ioremap_base) {
		dev_err(&pdev->dev, "Failed to ioremap\n");
		goto err_rel;
	}

	/* alloc the dma recv buff and send buf */
	kirin_pdev->dma_in_size = DMA_IN_SIZE;
	/* kirin_pdev->cpuaddr_in = dma_alloc_coherent(&pdev->dev, kirin_pdev->dma_in_size, &kirin_pdev->dma_addr_in, GFP_KERNEL | GFP_DMA32); */
	kirin_pdev->cpuaddr_in = dma_alloc_from_contiguous(&pdev->dev, kirin_pdev->dma_in_size);
	if (kirin_pdev->cpuaddr_in == NULL) {
		dev_err(&pdev->dev, "alloc dma in buff failed!\n");
		goto err_rel;
	}

	kirin_pdev->dma_out_size = DMA_OUT_SIZE;
	kirin_pdev->cpuaddr_out = dma_alloc_coherent(&pdev->dev, kirin_pdev->dma_out_size, &kirin_pdev->dma_addr_out, GFP_KERNEL | GFP_DMA32);
	if (kirin_pdev->cpuaddr_out == NULL) {
		dev_err(&pdev->dev, "alloc dma out buff failed!\n");
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		goto err_rel;
	}

	err = alloc_chrdev_region(&kirin_pdev->devnum, 0, PCIE_DEV_MINORS, kirin_pdev->device_name);
	if (err < 0) {
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		dev_err(&pdev->dev, "chrdev register failed\n");
		goto err_rel;
	}

	cdev_init(&kirin_pdev->chrdev, &fops);
	kirin_pdev->chrdev.owner = THIS_MODULE;
	err = cdev_add(&kirin_pdev->chrdev, kirin_pdev->devnum, 1);
	if (err < 0) {
		unregister_chrdev_region(kirin_pdev->devnum, 1);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		dev_err(&pdev->dev, "chrdev add failed\n");
		goto err_rel;
	}

	/* register the class for dev */
	memset(class_name, 0, ARRAY_SIZE(class_name));
	sprintf(class_name, CLASS_NAME"%d", kirin_pdev->instance);
	kirin_pdev->class = class_create(THIS_MODULE, class_name);
	if (IS_ERR(kirin_pdev->class)) {
		unregister_chrdev_region(kirin_pdev->devnum, 1);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		dev_err(&pdev->dev, "class device register failed!\n");
		err = PTR_ERR(kirin_pdev->class);
		goto err_rel;
	}

	/* create the device for kirinpcie */
	major = kirin_pdev->major = MAJOR(kirin_pdev->devnum);
	if (major < 0) {
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		unregister_chrdev_region(kirin_pdev->devnum, 1);
		class_destroy(kirin_pdev->class);
		dev_err(&pdev->dev, "char major failed!\n");
		goto err_rel;
	}

	kirin_pdev->device = device_create(kirin_pdev->class, NULL, MKDEV(major, 0), NULL, kirin_pdev->device_name);
	if (IS_ERR(kirin_pdev->device)) {
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		class_destroy(kirin_pdev->class);
		unregister_chrdev_region(kirin_pdev->devnum, 1);
		dev_err(&pdev->dev, "device create failed\n");
		err = PTR_ERR(kirin_pdev->device);
		goto err_rel;
	}

	/* this should be alloc by pcie scan phase */
	/* pci_assign_irq(pdev); */
	kirin_pdev->ioremap_base = ioremap_base;
	err = request_irq(pdev->irq, kirin_pcie_isr, IRQF_SHARED, kirin_pdev->driver_name, pdev);
	if (err) {
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
		dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
		class_destroy(kirin_pdev->class);
		unregister_chrdev_region(kirin_pdev->devnum, 1);
		dev_err(&pdev->dev, "Failed to request IRQ\n");
		goto err_rel;
	}

	kirin_pdev->pdev = pdev;
	dev_set_drvdata(&pdev->dev, kirin_pdev);
	printk(KERN_INFO "pcie driver loaded!\n");
	return 0;

err_rel:
	if (ioremap_base)
		pci_iounmap(pdev, ioremap_base);

	if (kirin_pdev->instance != -1) {
		ida_free(&kirin_pcie_ida, kirin_pdev->instance);
		kirin_pdev->instance = -1;
	}

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	if (kirin_pdev)
		kfree(kirin_pdev);

	return err;
}

static void kirin_pcie_remove(struct pci_dev *pdev)
{
	struct kirin_pdriver_dev *kirin_pdev = dev_get_drvdata(&pdev->dev);
	dev_info(&pdev->dev, "PCIe device removed\n");

	if (kirin_pdev->instance != -1) {
		ida_free(&kirin_pcie_ida, kirin_pdev->instance);
		kirin_pdev->instance = -1;
	}

	/* free irq resource */
	free_irq(pdev->irq, pdev);

	if (kirin_pdev->ioremap_base)
		pci_iounmap(pdev, kirin_pdev->ioremap_base);

	device_destroy(kirin_pdev->class, MKDEV(kirin_pdev->devnum, 0));
	class_destroy(kirin_pdev->class);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	unregister_chrdev_region(kirin_pdev->devnum, 1);
	dma_free_coherent(&pdev->dev, kirin_pdev->dma_in_size, kirin_pdev->cpuaddr_in, kirin_pdev->dma_addr_in);
	dma_free_coherent(&pdev->dev, kirin_pdev->dma_out_size, kirin_pdev->cpuaddr_out, kirin_pdev->dma_addr_out);
	kfree(kirin_pdev);
}

static struct pci_driver kirin_pcie_driver = {
	.name = DRIVER_NAME,
	.id_table = kirin_pcie_id_table,
	.probe = kirin_pcie_probe,
	.remove = kirin_pcie_remove,
};

static int __init kirin_pcie_driver_init(void)
{
	return pci_register_driver(&kirin_pcie_driver);
}

static void __exit kirin_pcie_driver_exit(void)
{
	pci_unregister_driver(&kirin_pcie_driver);
}

module_init(kirin_pcie_driver_init);
module_exit(kirin_pcie_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("china");
MODULE_DESCRIPTION("A kirin fpcie driver");

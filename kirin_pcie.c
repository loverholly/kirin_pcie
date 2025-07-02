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
#include "kirin_pcie.h"

struct kirin_pdriver_dev {
	struct fasync_struct *fasync_ptr;
	struct cdev chrdev;
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
	char name[40];
	char driver_name[40];
	int major;
};

#define PCIE_DEV_NAME "fpcie"
#define DRIVER_NAME "kirin_pcie"
#define PCIE_DEV_MINORS		(1U << MINORBITS)

static struct pci_device_id kirin_pcie_id_table[] = {
	{ PCI_DEVICE(0x1234, 0x5678) },
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
	int ret = 0;
	unsigned long virtaddr;
	void __user *user_arg = (void __user *)arg;
	struct kirin_pdriver_dev *kirin_pdev = filp->private_data;

	switch (cmd) {
	case KIRIN_GET_DMA_IN:
		virtaddr = (unsigned long)kirin_pdev->cpuaddr_in;
		printk(KERN_INFO "kirin pcie dmaaddr in get\n");
		ret = copy_to_user(user_arg, &virtaddr, sizeof(virtaddr));
		break;
	case KIRIN_GET_DMA_OUT:
		virtaddr = (unsigned long)kirin_pdev->cpuaddr_out;
		printk(KERN_INFO "kirin pcie dmaaddr out get\n");
		ret = copy_to_user(user_arg, &virtaddr, sizeof(virtaddr));
		break;
	case KIRIN_GET_BAR:
		virtaddr = (unsigned long)kirin_pdev->ioremap_base;
		printk(KERN_INFO "kirin pcie bar get\n");
		ret = copy_to_user(user_arg, &virtaddr, sizeof(virtaddr));
		break;
	default:
		ret = -EFAULT;
		break;
	}

	return ret;
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
};

static int kirin_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err;
	int devnum;
	resource_size_t io_addr;
	void __iomem *ioremap_base = NULL;
	struct kirin_pdriver_dev *kirin_pdev = NULL;

	dev_info(&pdev->dev, "PCIe device probed\n");

	/* enable pcie device */
	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable device\n");
		return err;
	}

	/* alloc pcie pcie request */
	err = pci_request_regions(pdev, DRIVER_NAME);
	if (err) {
		dev_err(&pdev->dev, "Failed to request regions\n");
		pci_disable_device(pdev);
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
	io_addr = pci_resource_start(pdev, 0);
	ioremap_base = ioremap(io_addr, 0x10000);
	if (!ioremap_base) {
		dev_err(&pdev->dev, "Failed to ioremap\n");
		goto err_rel;
	}

	kirin_pdev = kzalloc(sizeof(*kirin_pdev), GFP_KERNEL);
	if (kirin_pdev == NULL) {
		dev_err(&pdev->dev, "alloc kirin pcie pdev failed!\n");
		goto err_rel;
	}

	/* alloc the dma recv buff and send buf */
	kirin_pdev->dma_in_size = 128 * 1024;
	kirin_pdev->cpuaddr_in = dma_alloc_coherent(&pdev->dev, kirin_pdev->dma_in_size, &kirin_pdev->dma_addr_in, GFP_KERNEL);
	if (kirin_pdev->cpuaddr_in == NULL) {
		dev_err(&pdev->dev, "alloc dma in buff failed!\n");
		goto err_rel;
	}

	kirin_pdev->dma_out_size = 64 * 1024 * 1024;
	kirin_pdev->cpuaddr_out = dma_alloc_coherent(&pdev->dev, kirin_pdev->dma_out_size, &kirin_pdev->dma_addr_out, GFP_KERNEL);
	if (kirin_pdev->cpuaddr_out == NULL) {
		dev_err(&pdev->dev, "alloc dma out buff failed!\n");
		goto err_rel;
	}

	kirin_pdev->instance = -1;
	/* register the cdev */
	err = ida_alloc(&kirin_pcie_ida, GFP_KERNEL);
	if (err < 0) {
		dev_err(&pdev->dev, "alloc kirin pcie cdev failed!\n");
		goto err_rel;
	}

	kirin_pdev->instance = devnum = err;
	sprintf(kirin_pdev->name, PCIE_DEV_NAME"%d", devnum);
	err = alloc_chrdev_region(&kirin_pdev->devnum, 0, PCIE_DEV_MINORS, kirin_pdev->name);
	if (err < 0) {
		dev_err(&pdev->dev, "chrdev register failed\n");
		goto err_rel;
	}

	cdev_init(&kirin_pdev->chrdev, &fops);
	kirin_pdev->chrdev.owner = THIS_MODULE;
	err = cdev_add(&kirin_pdev->chrdev, kirin_pdev->devnum, 1);
	if (err < 0) {
		dev_err(&pdev->dev, "chrdev add failed\n");
		goto err_rel;
	}

	/* this should be alloc by pcie scan phase */
	/* pci_assign_irq(pdev); */
	kirin_pdev->ioremap_base = ioremap_base;
	sprintf(kirin_pdev->driver_name, DRIVER_NAME"%d", kirin_pdev->instance);
	err = request_irq(pdev->irq, kirin_pcie_isr, IRQF_SHARED, kirin_pdev->driver_name, pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to request IRQ\n");
		goto err_rel;
	}

	dev_set_drvdata(&pdev->dev, kirin_pdev);
	printk(KERN_INFO "pcie driver loaded!\n");
	return 0;

err_rel:
	if (ioremap_base)
		iounmap(ioremap_base);

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
		iounmap(kirin_pdev->ioremap_base);

	pci_release_regions(pdev);
	pci_disable_device(pdev);

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

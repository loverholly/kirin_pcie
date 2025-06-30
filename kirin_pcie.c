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

#define DRIVER_NAME "kirin_pcie"

static struct pci_device_id kirin_pcie_id_table[] = {
    { PCI_DEVICE(0x1234, 0x5678) },
    { 0, } /* 表结尾 */
};
MODULE_DEVICE_TABLE(pci, kirin_pcie_id_table);

static void __iomem *ioremap_base;
struct kirin_pdriver_dev {
	struct fasync_struct *fasync_ptr;
	struct cdev chrdev;
	void __iomem *ioremap_base;
	struct class *class;
};

static irqreturn_t kirin_pcie_isr(int irq, void *dev_id)
{
    struct pci_dev *pdev = (struct pci_dev *)dev_id;
    dev_info(&pdev->dev, "Interrupt received\n");
    return IRQ_HANDLED;
}

static int kirin_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    int err;
    unsigned long io_addr;
    void __iomem *ioremap_base;

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

    /* 设置DMA掩码 */
    err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
    if (err) {
        err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
        if (err) {
            dev_err(&pdev->dev, "No suitable DMA available\n");
            pci_release_regions(pdev);
            pci_disable_device(pdev);
            return err;
        }
    }

    /* get the pcie bar address for cpu access */
    io_addr = pci_resource_start(pdev, 0);
    ioremap_base = ioremap(io_addr, 0x10000);
    if (!ioremap_base) {
        dev_err(&pdev->dev, "Failed to ioremap\n");
        pci_release_regions(pdev);
        pci_disable_device(pdev);
        return -EIO;
    }


    err = request_irq(pdev->irq, kirin_pcie_isr, IRQF_SHARED, DRIVER_NAME, pdev);
    if (err) {
        dev_err(&pdev->dev, "Failed to request IRQ\n");
        iounmap(ioremap_base);
        pci_release_regions(pdev);
        pci_disable_device(pdev);
        return err;
    }


    return 0;
}

static void kirin_pcie_remove(struct pci_dev *pdev)
{
    dev_info(&pdev->dev, "PCIe device removed\n");

    /* free irq resource */
    free_irq(pdev->irq, pdev);

    if (ioremap_base)
        iounmap(ioremap_base);

    pci_release_regions(pdev);

    pci_disable_device(pdev);
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
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple PCIe driver");

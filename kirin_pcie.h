#ifndef __KIRIN_PCIE_H__
#define __KIRIN_PCIE_H__

#include <linux/ioctl.h>

#define KIRIN_IO_MAGIC 'k'

#define KIRIN_GET_DMA_IN _IOR(KIRIN_IO_MAGIC, 1, unsigned long *)
#define KIRIN_GET_DMA_OUT _IOR(KIRIN_IO_MAGIC, 2, unsigned long *)
#define KIRIN_GET_BAR _IOR(KIRIN_IO_MAGIC, 3, unsigned long *)

#endif	/* __KIRIN_PCIE_H__ */

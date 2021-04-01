#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("Georgiy Lebedev");
MODULE_DESCRIPTION("Miscellaneous character driver implementing a message queue");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#define KTHREAD_NAME "message_queue_character_device_kthread"

static int free_ptr(void *ptr)
{
    kfree(ptr);
    
    do_exit(0);
}

struct {
	struct device *dev;
	struct mutex dev_lock;
	
    struct message_queue {
        const char **messages;
        
        size_t head;
        size_t tail;
        size_t capacity;
    } mq;
} static *drv_ctx;

#define MESSAGE_QUEUE_INIT_CAPACITY 2lu
#define MESSAGE_QUEUE_GROWTH_COEFF 2lu

static int message_queue_enqueue(struct message_queue *mq, const char *msg, const size_t msglen)
{
    const char **new_messages = NULL;
    const size_t new_capacity = mq->capacity * MESSAGE_QUEUE_GROWTH_COEFF;
    size_t mq_sz = 0;
    const size_t head_sz = mq->head + 1;
    const size_t tail_sz = mq->capacity - mq->tail - 1;
    size_t last_msg_idx = 0;
    
    	dev_info(drv_ctx->dev, "enqueing message");

    if (mq->capacity == 0) {
    	dev_info(drv_ctx->dev, "constructing new message queue with initial capacity '%zu' and grow coefficient '%zu'", MESSAGE_QUEUE_INIT_CAPACITY, MESSAGE_QUEUE_GROWTH_COEFF);
    
        mq->messages = kzalloc(MESSAGE_QUEUE_INIT_CAPACITY * sizeof(*mq->messages), GFP_KERNEL);
        if (unlikely(mq->messages == NULL)) return -ENOMEM;
        
        mq->capacity = MESSAGE_QUEUE_INIT_CAPACITY;
        mq->head = mq->tail = MESSAGE_QUEUE_INIT_CAPACITY - 1;
    } else if ((mq->tail - 1 + mq->capacity) % mq->capacity == mq->head) {
    	dev_info(drv_ctx->dev, "reallocating message queue from capacity '%zu' to capacity '%zu'", mq->capacity, new_capacity);
    
        new_messages = kzalloc(new_capacity * sizeof(*new_messages), GFP_KERNEL);
        if (unlikely(new_messages == NULL)) return -ENOMEM;
        
        last_msg_idx = (mq->tail + 1) % mq->capacity;
        if (last_msg_idx <= mq->head) {
            mq_sz = mq->capacity - 1 - (mq->tail + 1) % mq->capacity;
            memcpy(new_messages + new_capacity - mq_sz, mq->messages + last_msg_idx, mq_sz * sizeof(*mq->messages));
            
            mq->tail = new_capacity - mq_sz - 1;
        } else {
            memcpy(new_messages + new_capacity - head_sz, mq->messages, (head_sz) * sizeof(*mq->messages));
            memcpy(new_messages + new_capacity - head_sz - tail_sz, mq->messages + mq->tail + 1, tail_sz * sizeof(*mq->messages));
            
            mq->tail = new_capacity - head_sz - tail_sz - 1;
        }
       
        
        kthread_run(free_ptr, mq->messages, KTHREAD_NAME);
        
        mq->messages = new_messages;
        
        mq->head = new_capacity - 1;
        mq->capacity = new_capacity;
    }
    
    mq->messages[mq->tail] = msg;
    mq->tail = (mq->tail - 1) % mq->capacity;
    
    return 0;
}

#undef MESSAGE_QUEUE_INIT_CAPACITY
#undef MESSAGE_QUEUE_GROWTH_COEFF

static const char *message_queue_dequeue(struct message_queue *mq)
{
    const char *msg = mq->messages[mq->head];
    
	dev_info(drv_ctx->dev, "dequeing message");

    if (mq->tail == mq->head) return NULL;
    
    mq->head = (mq->head - 1) % mq->capacity;
    
    return msg;
}

static int dev_open(struct inode *inode, struct file *filp)
{
    if (mutex_is_locked(&drv_ctx->dev_lock)) {
      dev_info(drv_ctx->dev, "device already in use");
      
      return -EBUSY;
   }

	dev_info(drv_ctx->dev, "opening file");
	
	mutex_lock(&drv_ctx->dev_lock);

	return nonseekable_open(inode, filp);
}

static ssize_t dev_read(struct file *filp, char __user *user_buf, const size_t sz, loff_t *off)
{
	char *msg = NULL;
	size_t msglen = 0;

    dev_info(drv_ctx->dev, "reading message: sz=%zu, off=%llu", sz, *off);
    
    if (*off > 0) return 0;

	msg = (char *) message_queue_dequeue(&drv_ctx->mq);
	if (msg == NULL) return 0;
	
	msglen = strlen(msg);
    
    if (copy_to_user(user_buf, msg, msglen) != 0) {
	    dev_warn(drv_ctx->dev, "copy_to_user failed");
	    
        kthread_run(free_ptr, msg, KTHREAD_NAME);
	
		return -EFAULT;
    }
	
	dev_info(drv_ctx->dev, "reading message: msg=%s", msg);
    
    kthread_run(free_ptr, msg, KTHREAD_NAME);
    
    *off += msglen;
    
    return msglen;
}

static ssize_t dev_write(struct file *filp, const char __user *user_buf, const size_t sz, loff_t *off)
{
    char *msg = NULL;
	int status = 0;
    
    dev_info(drv_ctx->dev, "writing message: sz=%zu, off=%llu", sz, *off);
    
    msg = kzalloc((sz + 1) * sizeof(*msg), GFP_KERNEL);
    if (unlikely(msg == NULL)) return -ENOMEM;
    
    if (copy_from_user(msg, user_buf, sz) != 0) {
	    dev_warn(drv_ctx->dev, "copy_from_user failed");
	    
        kthread_run(free_ptr, msg, KTHREAD_NAME);
		
        return -EFAULT;
    }
	
	dev_info(drv_ctx->dev, "writing message: msg=%s", msg);
	
	status = message_queue_enqueue(&drv_ctx->mq, msg, sz);
	if (status != 0) {
	    kthread_run(free_ptr, msg, KTHREAD_NAME);
		
		return status;
	}
    
    return sz;
}

static int dev_close(struct inode *_, struct file *__)
{
	dev_info(drv_ctx->dev, "closing file");
	
	mutex_unlock(&drv_ctx->dev_lock);

	return 0;
}

static const struct file_operations fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.llseek = no_llseek,
	.release = dev_close,
};

static struct miscdevice miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mq",
	.mode = 0666,
	.fops = &fops,
};

static int __init drv_init(void)
{
	int status = 0;

    pr_info("initializing module");

	status = misc_register(&miscdev);
	if (status != 0) {
		pr_notice("intializing module: misc device registration failed, aborting");
		return status;
	}
	
	dev_info(miscdev.this_device, "initializing module: misc driver (major#=10) registered: minor#=%d", miscdev.minor);

	drv_ctx = devm_kzalloc(miscdev.this_device, sizeof(*drv_ctx), GFP_KERNEL);
	if (unlikely(drv_ctx == NULL)) return -ENOMEM;

	drv_ctx->dev = miscdev.this_device;
	mutex_init(&drv_ctx->dev_lock); 
	
	dev_info(drv_ctx->dev, "initializing module: driver initialized");

	return 0;
}

static void __exit drv_exit(void)
{
    size_t idx = drv_ctx->mq.head;
    size_t last_msg_idx = 0;
    size_t i = 0;
    
	pr_info("exiting module");
	
    dev_info(drv_ctx->dev, "exiting module: head=%zu tail=%zu capacity=%zu", drv_ctx->mq.head, drv_ctx->mq.tail, drv_ctx->mq.capacity);
    for (; i < drv_ctx->mq.capacity; ++i) dev_info(drv_ctx->dev, "exiting module: messages[%zu]=%s", i, drv_ctx->mq.messages[i]); 

    if (drv_ctx->mq.head == drv_ctx->mq.tail) goto deregister;
    
    last_msg_idx = (drv_ctx->mq.tail + 1) % drv_ctx->mq.capacity;
    if (last_msg_idx <= drv_ctx->mq.head) {
        for (; last_msg_idx <= idx; --idx) kthread_run(free_ptr, (char *) drv_ctx->mq.messages[idx], KTHREAD_NAME);
    } else {
        for (; 0 <= idx; --idx) kthread_run(free_ptr, (char *) drv_ctx->mq.messages[idx], KTHREAD_NAME);
        
        idx = drv_ctx->mq.capacity - 1;
        for (; drv_ctx->mq.tail < idx; --idx) kthread_run(free_ptr, (char *) drv_ctx->mq.messages[idx], KTHREAD_NAME);
    }
    
    kthread_run(free_ptr, drv_ctx->mq.messages, KTHREAD_NAME);
    
deregister:
	misc_deregister(&miscdev);
	pr_info("exiting moudle: driver deregistered");
}

#undef pr_fmt

module_init(drv_init);
module_exit(drv_exit);

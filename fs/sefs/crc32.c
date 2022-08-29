#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/delay.h>

  
#define BUFSIZE     1024*4   
  
static unsigned int crc_table[256];  
  
static int  crc32_init = 0;
static void init_crc_table(void);  
  
static void init_crc_table(void)  
{  
    unsigned int c;  
    unsigned int i, j;  
      
	if(crc32_init != 0)
		return ;
	
    for (i = 0; i < 256; i++) {  
        c = (unsigned int)i;  
        for (j = 0; j < 8; j++) {  
            if (c & 1)  
                c = 0xedb88320L ^ (c >> 1);  
            else  
                c = c >> 1;  
        }  
        crc_table[i] = c;  
    }  
	crc32_init = 1;
}  
  

unsigned int my_crc32(unsigned int crc,unsigned char *buffer, unsigned int size)  
{  
    unsigned int i;  
	init_crc_table();
    for (i = 0; i < size; i++) {  
        crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);  
    }  
    return crc ;  
}

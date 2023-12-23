#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/add_to_page_cache_lru")
int trace_page_cache_lru_addition(struct pt_regs *ctx) {
	struct task_struct *task;
	struct page *page = (struct page *)PT_REGS_PARM1(ctx);
	struct address_space *mapping = (struct address_space *)PT_REGS_PARM2(ctx);
	struct inode *inode;
	bpf_probe_read(&inode,sizeof(inode),&mapping->host);
	u64 inumber = inode->i_ino;
	task = (struct task_struct *)bpf_get_current_task();
//bpf_get_current_comm(&comm,sizeof(comm));
	bpf_printk("inode number: %llu\n",inumber);


	return 0;
}
char _license[] SEC("license") = "GPL";

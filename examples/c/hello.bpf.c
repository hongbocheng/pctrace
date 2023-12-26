#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define pgoff_t unsigned long

//typedef unsigned int __bitwise gfp_t;

SEC("kprobe/add_to_page_cache_lru")
//int trace_page_cache_lru_addition(struct pt_regs *ctx) {
int BPF_KPROBE(add_to_page_cache_lru,struct page *page, struct address_space *mapping) { //,pgoff_t offset, gfp_t gfp_mask) {
	//struct page *page = (struct page *)PT_REGS_PARM1(ctx);
	//struct address_space *mapping = (struct address_space *)PT_REGS_PARM2(ctx);
        u64 inumber = BPF_CORE_READ(mapping,host,i_ino);
	//bpf_probe_read(&inode,sizeof(inode),&mapping->host);
	bpf_printk("inode number: %llu\n",inumber);
	//task = (struct task_struct *)bpf_get_current_task();
//bpf_get_current_comm(&comm,sizeof(comm));


	return 0;
}
char _license[] SEC("license") = "GPL";

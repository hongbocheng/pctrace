#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define pgoff_t unsigned long
#define MAX_ENTRIES	8192
//typedef unsigned int __bitwise gfp_t;

struct data_t {
    __u32 pid;
    __u64 inode;
    char filename[256];
};

/*
BPF_HASH(tmp, u32, struct data_t);
BPF_HASH(openfiles, u64, struct data_t);
*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct data_t);
} tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct data_t);
} openfiles SEC(".maps");

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(struct pt_regs *ctx)
{
    struct data_t data = {};

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.pid = pid;
    bpf_probe_read(&data.filename, sizeof(data.filename), (void*)PT_REGS_PARM2(ctx));

    bpf_map_update_elem(&tmp, &pid, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
    struct inode *inode = file->f_inode;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *data = bpf_map_lookup_elem(&tmp,&pid);

    if (!data) {
        return 0; // missed entry
    }

    data->inode = inode->i_ino; // get the inode number
    //openfiles.update(&data->inode, data);
    bpf_map_update_elem(&openfiles, &pid, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_open")
int kretprobe__do_sys_open(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&tmp,&pid);
    return 0;
}


/* trace page cache addition */
SEC("kprobe/add_to_page_cache_lru")
//int trace_page_cache_lru_addition(struct pt_regs *ctx) {
int BPF_KPROBE(add_to_page_cache_lru,struct page *page, struct address_space *mapping) { //,pgoff_t offset, gfp_t gfp_mask) {
        u64 inumber = BPF_CORE_READ(mapping,host,i_ino);
	bpf_printk("inode number: %llu\n",inumber);
	//struct task_struct *task;
	//task = (struct task_struct *)bpf_get_current_task();
//bpf_get_current_comm(&comm,sizeof(comm));


	return 0;
}
char _license[] SEC("license") = "GPL";

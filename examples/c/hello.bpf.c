#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

SEC("kprobe/add_to_page_cache_lru")
int bpf_prog(void *ctx)
{
	char msg[] = "hello world!\n";
//	bpf_trace_printk(msg, sizeof(msg));
	char comm[16] = "";
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	bpf_get_current_comm(&comm,sizeof(comm));
	bpf_trace_printk(comm,sizeof(comm));


	return 0;
}
char _license[] SEC("license") = "GPL";

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define pgoff_t unsigned long
#define MAX_ENTRIES	81920
//typedef unsigned int __bitwise gfp_t;

struct vfsfiles {
    char filename[256];
    char vfsfilename[128];
};

struct openat_key {
	pid_t pid;
	pid_t tid;
};

struct openat_files {
	char fname[256];
};

/*
BPF_HASH(tmp, u32, struct data_t);
BPF_HASH(openfiles, u64, struct data_t);
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct openat_key);
	__type(value, struct openat_files);
} openatinfo SEC(".maps");

/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct data_t);
} tmp SEC(".maps");
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct vfsfiles);
} vfsopenfiles SEC(".maps");

SEC("fentry/do_sys_openat2")
int BPF_PROG(do_sys_openat2, int dfd, char *filename)
{
    struct openat_files openfile = {};
    struct openat_key key = {};
        pid_t pid,tid;
	u64 id;
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

    key.pid = pid;
    key.tid = tid;
    //char *fname = filename
    bpf_probe_read(&openfile.fname, sizeof(openfile.fname), (void*) filename);

    bpf_printk("id: %llu, pid: %lu, tid: %lu, file: %s\n",id,key.pid,key.tid,openfile.fname);


    bpf_map_update_elem(&openatinfo, &key, &openfile, BPF_ANY);

    return 0;
}

SEC("fentry/vfs_open")
int BPF_PROG(vfs_open, struct path *path, struct file *file)
{
//__u32 ino = file->f_inode->i_ino;

//if (!path || !path->dentry)
//	return 0;

        pid_t pid,tid;
	u64 id;
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	struct openat_key key = {};
	key.pid = pid;
	key.tid = tid;
	struct openat_files *openat_fname = bpf_map_lookup_elem(&openatinfo,&key);

    if (!openat_fname) {
    bpf_printk("vfs_open not found existing openat_files record!\n");
        return 0; // missed entry
    }
    u64 inode_id = path->dentry->d_inode->i_ino; // set the inode number in data struct
    struct vfsfiles vfsfile = {};
    bpf_probe_read(vfsfile.vfsfilename, sizeof(vfsfile.vfsfilename),  (struct path *)path->dentry->d_name.name);
    bpf_probe_read(vfsfile.filename,sizeof(vfsfile.filename),(struct vfsfiles *)openat_fname->fname);
    /*
    */
    //vfsfile.vfsfilename = path->dentry->d_name.name;
    //bpf_printk("file name from vfs_open: %s, inode id: %llu openat filename: %s\n",path->dentry->d_name.name,inode_id,openat_fname->fname); 
    bpf_printk("file name from vfs_open: %s, inode id: %llu openat filename: %s\n",vfsfile.vfsfilename,inode_id,vfsfile.filename); 
    bpf_map_update_elem(&vfsopenfiles, &inode_id, &vfsfile , BPF_ANY);
    return 0;
}

/*
SEC("kretprobe/do_sys_open")
int BPF_KRETPROBE(do_sys_open_ret, int ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&tmp,&pid);
    return 0;
}
*/

/* trace page cache addition 
*/
SEC("fentry/add_to_page_cache_lru")
//int trace_page_cache_lru_addition(struct pt_regs *ctx) {
int BPF_PROG(add_to_page_cache_lru,struct page *page, struct address_space *mapping) { //,pgoff_t offset, gfp_t gfp_mask) {
        u64 inumber = BPF_CORE_READ(mapping,host,i_ino);
        pid_t pid,tid;
	u64 id;
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
    struct vfsfiles *pcdata = bpf_map_lookup_elem(&vfsopenfiles,&inumber);
    if (pcdata) {
	bpf_printk("inode number from page cache ---: %llu, pc_pid: %lu, vfs_file: %s, filename: %s\n",inumber,pid,pcdata->vfsfilename,pcdata->filename);
    } else {
	    bpf_printk("inode number---: %llu\n",inumber);
    }
	//struct task_struct *task;
	//task = (struct task_struct *)bpf_get_current_task();
//bpf_get_current_comm(&comm,sizeof(comm));


	return 0;
}
char _license[] SEC("license") = "GPL";

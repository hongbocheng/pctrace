#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define pgoff_t unsigned long
#define MAX_ENTRIES	81920
//typedef unsigned int __bitwise gfp_t;

struct vfsopenfiles {
    char openat_name[256];
    char vfsopen_name[128];
};

struct openat_key {
	pid_t pid;
	pid_t tid;
};

struct openat_files {
	char openat_name[256];
};


// map definition
// -- hash map to store information retrieved from do_sys_openat2 probe
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct openat_key);
	__type(value, struct openat_files);
} openatinfo_m SEC(".maps");

//map for storing info from vfs_open probe
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct vfsopenfiles);
} vfsopen_m SEC(".maps");

// tracing with fentry/fexit ...
//
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

    //use bpf_probe_read to set value for openat_name in the openfile struct
    bpf_probe_read(&openfile.openat_name, sizeof(openfile.openat_name), (void*) filename);
    //for debugging 
    bpf_printk("id: %llu, pid: %lu, tid: %lu, file: %s\n",id,key.pid,key.tid,openfile.openat_name);

    //update openatinfo_m map
    bpf_map_update_elem(&openatinfo_m, &key, &openfile, BPF_ANY);
    return 0;
}

SEC("fentry/vfs_open")
int BPF_PROG(vfs_open, struct path *path, struct file *file)
{
   if (!path || !path->dentry)
       return 0;

    pid_t pid,tid;
    u64 id;
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    struct openat_key key = {};
    key.pid = pid;
    key.tid = tid;

    //lookup openat hashmap to retrieve full file name
    struct openat_files *openat_t = bpf_map_lookup_elem(&openatinfo_m,&key);

    if (!openat_t) {
    bpf_printk("vfs_open not found existing openat_files record!\n");
        return 0; // missed entry
    }
    u64 inode_id = path->dentry->d_inode->i_ino; // set the inode number in data struct
    struct vfsopenfiles vfsopen_t = {};
    bpf_probe_read(vfsopen_t.vfsopen_name, sizeof(vfsopen_t.vfsopen_name),  (struct path *)path->dentry->d_name.name);
    bpf_probe_read(vfsopen_t.openat_name,sizeof(vfsopen_t.openat_name),(struct openat_files *)openat_t->openat_name);
    /*
    */
    //vfsfile.vfsfilename = path->dddentry->d_name.name;
    //bpf_printk("file name from vfs_open: %s, inode id: %llu openat filename: %s\n",path->dentry->d_name.name,inode_id,openat_fname->fname); 
    bpf_printk("file name from vfs_open: %s, inode id: %llu openat filename: %s\n",vfsopen_t.vfsopen_name,inode_id,vfsopen_t.openat_name); 
    bpf_map_update_elem(&vfsopen_m, &inode_id, &vfsopen_t , BPF_ANY);
    return 0;
}

/* trace page cache addition 
*/
SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(add_to_page_cache_lru,struct page *page, struct address_space *mapping) { //,pgoff_t offset, gfp_t gfp_mask) {
	//read inode number from the mapping argument of add_to_page_cache_lru function
        u64 inumber = BPF_CORE_READ(mapping,host,i_ino);

	//routine operation to get pid/tid
        pid_t pid,tid;
	u64 id;
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	//lookup the vfsopen_m map with inode number as key
    struct vfsopenfiles *pcdata = bpf_map_lookup_elem(&vfsopen_m,&inumber);
    if (pcdata) {
	bpf_printk("inode number from page cache ---: %llu, pc_pid: %lu, vfs_file: %s, filename: %s\n",inumber,pid,pcdata->vfsopen_name,pcdata->openat_name);
    } else {
	    bpf_printk("inode number---: %llu\n",inumber);
    }
	//struct task_struct *task;
	//task = (struct task_struct *)bpf_get_current_task();
//bpf_get_current_comm(&comm,sizeof(comm));


	return 0;
}
char _license[] SEC("license") = "GPL";

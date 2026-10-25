#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define MODE_LOGGER 1
#define MODE_BLOCKER 2
#define BLOCK_POSITIVE 1
#define BLOCK_NEGATIVE 2

#define COMMAND_SIZE 64

char __license[] SEC("license") = "Dual MIT/GPL";

struct user_key {
    __u32 userns_inum;
    __u32 host_uid;
};

struct command_key {
    char name[COMMAND_SIZE];
};

struct policy_config {
    __u32 mode; 
    __u32 block_type;
    __u32 has_users;
    __u32 has_commands;
};

struct exec_event {
    __u32 tgid;
    __u32 pid;
    __u32 host_uid;
    __u32 userns_inum;
    __u32 effective_uid;
    __u32 would_block;
    __u32 blocked;
    char command[COMMAND_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct user_key);
    __type(value, __u8);
} users SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, __u32);
} namespaces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct command_key);
    __type(value, __u8);
} commands SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(user_command_controller, struct linux_binprm *bprm, int prior_ret)
{
    if (prior_ret != 0)
        return prior_ret;

    __u32 zero = 0;
    const struct policy_config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || cfg->mode == 0)
        return 0;

    struct user_key uk = {};
    uk.host_uid = (__u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 effective_uid = BPF_CORE_READ(task, cred, euid.val);
    if (uk.host_uid == 0 || effective_uid == 0)
        return 0;
    uk.userns_inum = BPF_CORE_READ(task, cred, user_ns, ns.inum);
    const __u32 *root_uid = bpf_map_lookup_elem(&namespaces, &uk.userns_inum);
    if (!root_uid || uk.host_uid == *root_uid || effective_uid == *root_uid)
        return 0;

    struct command_key ck = {};
    struct file *file = BPF_CORE_READ(bprm, file);
    const unsigned char *name = NULL;
    if (file)
        name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name)
        return 0;
    long name_len = bpf_probe_read_kernel_str(ck.name, sizeof(ck.name), name);
    if (name_len <= 0)
        return 0;
    char final_byte = 0;
    if (name_len == COMMAND_SIZE &&
        (bpf_probe_read_kernel(&final_byte, sizeof(final_byte), name + COMMAND_SIZE - 1) < 0 || final_byte != 0))
        return 0;

    bool has_user = cfg->has_users && bpf_map_lookup_elem(&users, &uk);
    bool has_command = cfg->has_commands && bpf_map_lookup_elem(&commands, &ck);

    bool selected = (cfg->has_users || cfg->has_commands) &&
                    (!cfg->has_users || has_user) &&
                    (!cfg->has_commands || has_command);
    bool would_block = cfg->block_type == BLOCK_POSITIVE ? selected : !selected;
    bool blocked = cfg->mode == MODE_BLOCKER && would_block;
    if (!would_block)
        return 0;

    struct exec_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        __u64 id = bpf_get_current_pid_tgid();
        evt->tgid = id >> 32;
        evt->pid = (__u32)id;
        evt->host_uid = uk.host_uid;
        evt->userns_inum = uk.userns_inum;
        evt->effective_uid = effective_uid;
        evt->would_block = would_block;
        evt->blocked = blocked;
        __builtin_memcpy(evt->command, ck.name, sizeof(evt->command));
        bpf_ringbuf_submit(evt, 0);
    }

    return blocked ? -EPERM : 0;
}


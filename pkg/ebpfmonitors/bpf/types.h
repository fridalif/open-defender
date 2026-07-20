#ifndef __TYPES_H__
#define __TYPES_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#define BPF_MAP_TYPE_RINGBUF 27

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, rbp, rbx;
	unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
	unsigned long orig_rax, rip, cs, eflags, rsp, ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#elif defined(__TARGET_ARCH_arm)
struct pt_regs {
	unsigned long uregs[18];
};
#endif

struct sock;

struct sk_buff {
	unsigned char *head;
	__u16 transport_header;
	__u16 network_header;
} __attribute__((preserve_access_index));

struct iphdr {
	__u8 ihl_version;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};

struct tcphdr {
	__u16 source;
	__u16 dest;
};

struct udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};

#endif /* __TYPES_H__ */

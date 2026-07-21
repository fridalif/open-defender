/*
 * Минимальная замена vmlinux.h: только то, что нужно программам этого каталога.
 * Никаких kprobe / pt_regs — значит объект собирается одной generic-целью (bpf).
 */
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

/* Требуются прототипам хелперов в bpf_helper_defs.h. */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#define BPF_MAP_TYPE_RINGBUF 27

/*
 * Контекст tracepoint tcp:tcp_send_reset. Объявлены только используемые поля;
 * их смещения подставляет CO-RE на загрузке (preserve_access_index), поэтому
 * структура переносима между версиями ядра, а её имя обязано совпадать с BTF.
 * saddr/daddr — это sockaddr: [0..1] family, [2..3] порт (BE), [4..7] IPv4.
 */
struct trace_event_raw_tcp_send_reset {
	int state;
	__u8 saddr[28];
	__u8 daddr[28];
} __attribute__((preserve_access_index));

#endif /* __TYPES_H__ */

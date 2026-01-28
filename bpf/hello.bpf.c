// +build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 16);
} info SEC(".maps");


SEC("kprobe/sys_execve")

int hello(void *ctx)
{
    char data[30];
    bpf_get_current_comm(&data, sizeof(data));
    bpf_perf_event_output(ctx, &info, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
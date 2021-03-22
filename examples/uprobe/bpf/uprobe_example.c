#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";
u32 __version SEC("version")    = 266002;

struct event_t {
	u32 pid;
	char str[80];
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

SEC("uprobe/bash_readline")
int bash_readline(struct pt_regs *ctx) {
	struct event_t event;

	event.pid = bpf_get_current_pid_tgid();
	bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

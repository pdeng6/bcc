#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "monitor_perf_adjust_freq.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * Use following method to fetch event you want to probe:
 *
 * #cat /proc/kallsyms | grep perf_adjust_freq_unthr_context
 * ffffffff9f124d30 t perf_adjust_freq_unthr_context

 */

static inline int rcu_read_lock_any_held(void)
{
	return 1;
}

#define check_arg_count_one(dummy)
#define __list_check_rcu(dummy, cond, extra...)				\
	({								\
	check_arg_count_one(extra);					\
	})

#define list_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)

#define list_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = list_entry_rcu((head)->next, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

SEC("kprobe/perf_adjust_freq_unthr_context")
int sys_perf_adjust_freq_unthr_context(struct pt_regs *ctx) {
    struct perf_event *event;
    struct perf_event_context *pevent_ctx = (void *)&PT_REGS_PARM1(ctx);
    bool unthrottle = PT_REGS_PARM2(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};
    const char *argp;

    data.pid = pid;
    data.unthrottle = unthrottle;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
    data.active_event_num = 0;

    const struct perf_event_context *my_pevent_ctx;
    bpf_core_read(&my_pevent_ctx, sizeof(my_pevent_ctx), pevent_ctx);
    bpf_core_read(&data.event_num, sizeof(data.event_num), &my_pevent_ctx->nr_events);

    if (!__builtin_memcmp(data.comm, "swapper", 7) 
        || ! __builtin_memcmp(data.comm, "cpptools", 8)
        || ! __builtin_memcmp(data.comm, "node", 4)
        || ! __builtin_memcmp(data.comm, "ps", 2)
        || ! __builtin_memcmp(data.comm, "git", 3))
        return 0;
    

    // To iterate rcu list is complicate macros, need a lot of changes so satisfy bpf...
    // list_for_each_entry_rcu(event, &my_pevent_ctx->event_list, event_entry) {
    //     if (event->state == PERF_EVENT_STATE_ACTIVE)
	// 		data.active_event_num++;
    // }

    // bpf_core_read(&argp, sizeof(argp), file_name);
    // if (argp) {
    //     bpf_core_read_user_str(&data.path, sizeof(data.path), argp);
    // }
    data.event_names[0] = 'a';
    data.event_names[1] = 'd';
    data.event_names[2] = 'j';
    data.event_names[3] = 'u';
    data.event_names[4] = 's';
    data.event_names[5] = 't';
    data.event_names[6] = '\0';
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/list_add_event")
int sys_list_add_event(struct pt_regs *ctx) {
    struct perf_event *event = (void *)&PT_REGS_PARM1(ctx);;
    struct perf_event_context *pevent_ctx = (void *)&PT_REGS_PARM2(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.pid = pid;
    data.unthrottle = 1;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    const struct perf_event_context *my_pevent_ctx;
    bpf_core_read(&my_pevent_ctx, sizeof(my_pevent_ctx), pevent_ctx);
    bpf_core_read(&data.event_num, sizeof(data.event_num), &my_pevent_ctx->nr_events);

    data.event_names[0] = 'a';
    data.event_names[1] = 'd';
    data.event_names[2] = 'd';
    data.event_names[3] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/event_sched_in")
int sys_event_sched_in(struct pt_regs *ctx) {
    struct perf_event *event = (void *)&PT_REGS_PARM1(ctx);;
    struct perf_event_context *pevent_ctx = (void *)&PT_REGS_PARM2(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.pid = pid;
    data.unthrottle = 1;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    const struct perf_event_context *my_pevent_ctx;
    bpf_core_read(&my_pevent_ctx, sizeof(my_pevent_ctx), pevent_ctx);
    bpf_core_read(&data.event_num, sizeof(data.event_num), &my_pevent_ctx->nr_events);

    data.event_names[0] = 's';
    data.event_names[1] = 'c';
    data.event_names[2] = 'h';
    data.event_names[3] = 'e';
    data.event_names[4] = 'd';
    data.event_names[5] = 'i';
    data.event_names[6] = 'n';
    data.event_names[7] = '\0';


    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

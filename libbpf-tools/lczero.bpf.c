#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lczero.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

__u32 search_worker_tid = 0;
__u32 task_worker_tid1 = 0;
__u32 task_worker_tid2 = 0;
__u32 task_worker_tid3 = 0;
__u32 task_worker_tid4 = 0;

__u64 start_time_ns = 0;

static bool is_interested(u32 cur_tid) {
    return (cur_tid == search_worker_tid)       \
            || (cur_tid == task_worker_tid1)   \
            || (cur_tid == task_worker_tid2)   \
            || (cur_tid == task_worker_tid3)   \
            || (cur_tid == task_worker_tid4);
}

SEC("kprobe/update_deadline")
int update_deadline(struct pt_regs *ctx) {
    const struct sched_entity *se = (struct sched_entity *)&PT_REGS_PARM2(ctx);
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    if (!is_interested(tid)) {
        return -1;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.type = 1;
    data.pid = pid;
    data.tid = tid;
    bpf_core_read(&data.vruntime, sizeof(data.vruntime), &se->vruntime);
    bpf_core_read(&data.deadline, sizeof(data.deadline), &se->deadline);
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kretprobe/update_deadline")
int update_deadline_ret(struct pt_regs *ctx) {
    const struct sched_entity *se = (struct sched_entity *)&PT_REGS_PARM2(ctx);
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    if (!is_interested(tid)) {
        return -1;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.type = 2;
    data.pid = pid;
    data.tid = tid;
    bpf_core_read(&data.vruntime, sizeof(data.vruntime), &se->vruntime);
    bpf_core_read(&data.deadline, sizeof(data.deadline), &se->deadline);
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("uprobe//home/pnp/pdeng6/ebpf/bcc/libbpf-tools/lc0:_ZN6lczero12SearchWorker17NotifyTaskWorkersEv")\
int BPF_UPROBE(uprobe_main)
{
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    if (!is_interested(tid)) {
        return -1;
    }
    struct data_t data = {};
    data.type = 3;
    data.vruntime = bpf_ktime_get_ns();
    start_time_ns = data.vruntime;
    data.tid = tid;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
}

SEC("uretprobe//home/pnp/pdeng6/ebpf/bcc/libbpf-tools/lc0:_ZN6lczero12SearchWorker17NotifyTaskWorkersEv")
int BPF_URETPROBE(uretprobe_main)
{
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    if (!is_interested(tid)) {
        return -1;
    }
    struct data_t data = {};
    data.type = 4;
    data.vruntime = bpf_ktime_get_ns();
    data.deadline = data.vruntime - start_time_ns;
    data.tid = tid;
    start_time_ns = 0;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
}

SEC("kprobe/pick_eevdf")
int pick_eevdf(struct pt_regs *ctx) {
    return 0;
}

SEC("kretprobe/pick_eevdf")
int BPF_KRETPROBE(kprobe_pick_eevdf_exit, long ret) {
    struct cfs_rq *cfs_rq = (struct cfs_rq *)&PT_REGS_PARM1(ctx);
    struct sched_entity *curr = NULL;
    bpf_core_read(&curr, sizeof(struct sched_entity*), &cfs_rq->curr);
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sched_entity *best  = (struct sched_entity *)ret;
    struct task_struct *picked_task = container_of(best, struct task_struct, se);
    u32 next_task_tid = 0;
    bpf_core_read(&next_task_tid, sizeof(picked_task->pid), &picked_task->pid);

    if (!is_interested(tid) && !is_interested(next_task_tid)) {
        return -1;
    }

    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.type = 5;
    data.pid = pid;
    data.tid = tid;
    data.next_tid = next_task_tid;
    bpf_core_read(&data.vruntime, sizeof(data.vruntime), &curr->vruntime);
    bpf_core_read(&data.deadline, sizeof(data.deadline), &curr->deadline);
    bpf_core_read(&data.nextt_vruntime, sizeof(data.nextt_vruntime), &best->vruntime);
    bpf_core_read(&data.nextt_deadline, sizeof(data.nextt_deadline), &best->deadline);
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
    BPF_CORE_READ_STR_INTO(&data.nextt_comm, picked_task, group_leader, comm);


    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

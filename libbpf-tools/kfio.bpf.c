#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "kfio.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("kprobe/process_one_work")
int process_one_work(struct pt_regs *ctx) {
	struct worker *worker = (struct worker* )PT_REGS_PARM1(ctx);
	struct worker_pool* pool = 0;
	struct task_struct *current = (void *)bpf_get_current_task();
	bpf_core_read(&pool, sizeof(struct worker_pool *), &worker->pool);
	struct data_t data = {};
	data.type = 1;
	data.pool = (unsigned long long)pool;
	bpf_core_read(&data.pool_id, sizeof(data.pool_id), &pool->id);
	BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

SEC("kprobe/timestamp_truncate")
int timestamp_truncate(struct pt_regs *ctx) {
	// struct timespec64 timestamp_truncate(struct timespec64 t, struct inode *inode)
	// timespec64 use 2*8bytes registers, so that inode is in reg3
	struct inode* inodex = (struct inode*)PT_REGS_PARM3(ctx);
	struct super_block * sb = BPF_CORE_READ(inodex, i_sb);
	unsigned int gran = BPF_CORE_READ(inodex, i_sb, s_time_gran);
	long long tv_sec = PT_REGS_PARM1(ctx);
	long long tv_nsec = PT_REGS_PARM2(ctx);

	long long s_time_min = BPF_CORE_READ(sb, s_time_min);
	long long s_time_max = BPF_CORE_READ(sb, s_time_max);
	struct task_struct *current = (void *)bpf_get_current_task();
	u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;	

	struct data_t data = {};
    data.type = 2;
	data.inode = (unsigned long long)inodex;
	data.super_block = (unsigned long long)sb;
	data.gran = gran;
	data.is_hit_boundary = 0;
	if (tv_sec <= s_time_min || tv_sec >= s_time_max) {
		data.is_hit_boundary = 1;
	}
	data.tv_sec = tv_sec;
	data.tv_nsec = tv_nsec;
	data.s_time_min = s_time_min;
	data.s_time_max = s_time_max;
    data.tid = tid;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

// This one need kernel hack w/ function count_timestamp_truncate_2
SEC("kprobe/count_timestamp_truncate_2.isra.0")
int timestamp_truncate2(struct pt_regs *ctx) {
    struct data_t data = {};
	struct task_struct *current = (void *)bpf_get_current_task();
	u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;

    data.type = 2;
	bpf_core_read(&data.gran, sizeof(data.gran), &PT_REGS_PARM2(ctx));
	bpf_core_read(&data.tv_sec, sizeof(data.tv_sec), &PT_REGS_PARM3(ctx));
	bpf_core_read(&data.tv_nsec, sizeof(data.tv_nsec), &PT_REGS_PARM4(ctx));
	bpf_core_read(&data.s_time_min, sizeof(data.s_time_min), &PT_REGS_PARM5(ctx));
	bpf_core_read(&data.s_time_max, sizeof(data.s_time_max), &PT_REGS_PARM6(ctx));
	data.tid = tid;
	BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/observer_flush_wq_prep_pwq.isra.0")
int observer_flush_wq_prep_pwq(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *current = (void *)bpf_get_current_task();
    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    data.type = 3;
    bpf_core_read(&data.flush_wq_loop_start_ns, sizeof(data.flush_wq_loop_start_ns), &PT_REGS_PARM2(ctx));
    bpf_core_read(&data.flush_wq_loop_end_ns, sizeof(data.flush_wq_loop_end_ns), &PT_REGS_PARM3(ctx));
    data.tid = tid;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "kschedule.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// To measure the overhead of a probe attach
SEC("kprobe/pick_eevdf")
int pick_eevdf(struct pt_regs *ctx) {
    return 0;
}

extern const int sd_llc_size __ksym;
extern const struct sched_domain_shared* sd_llc_shared __ksym;

// print llc sd size
SEC("kprobe/select_idle_cpu")
int select_idle_cpu(struct pt_regs *ctx) {
    bool has_idle_core = PT_REGS_PARM3(ctx);
    int* scale_factor = (int*)&PT_REGS_PARM5(ctx);
    *scale_factor = 768;

    unsigned int* llc_size_pointer = (unsigned int *)bpf_this_cpu_ptr(&sd_llc_size);

    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    data.type = 1;
    data.pid = pid;
    data.tid = tid;
    data.has_idle_core = has_idle_core;

    bpf_core_read(&data.scale_factor, sizeof(data.scale_factor), scale_factor);

    bpf_core_read(&data.sd_llc_size, sizeof(data.sd_llc_size), llc_size_pointer);
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}


// Tried to print the sd_share->nr_idle_scan
// But failed, rcu_reference is not supported in bpf context yet
// extern const struct sched_domain_shared* sd_llc_shared __ksym;
// SEC("kprobe/select_idle_cpu")
// int select_idle_cpu(struct pt_regs *ctx) {
//     int nr = 1;
//     int* target = (int*)&PT_REGS_PARM4(ctx);

//     struct sched_domain_shared* sds = (struct sched_domain_shared*)rcu_dereference(bpf_per_cpu_ptr(&sd_llc_shared, *target));
//     nr = READ_ONCE(sds->nr_idle_scan);

//     if (nr == 1)
//         return -1;

//     u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     struct task_struct *current = (void *)bpf_get_current_task();

//     struct data_t data = {};
//     data.type = 1;
//     data.pid = pid;
//     data.tid = tid;
//     data.nr_idle_scan = nr;

//     BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
//     return 0;
// }

// Tried to print the sd_share->nr_idle_scan
// We add a nr_store param in select_idle_cpu to store the value
// so when return, we retrieve the value
// Failed too, input param stack may be destroyed when retprobe is enter.
// SEC("kretprobe/select_idle_cpu")
// int select_idle_cpu(struct pt_regs *ctx) {
//     int* nr_store = (int*)PT_REGS_PARM5(ctx);

//     struct task_struct *current = (void *)bpf_get_current_task();

//     struct data_t data = {};
//     data.type = 1;

//     bpf_core_read(&data.nr_idle_scan, sizeof(data.nr_idle_scan), nr_store);

//     BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
//     return 0;
// }

SEC("kprobe/select_idle_cpu_nr_observer")
int select_idle_cpu_nr_observer(struct pt_regs *ctx) {
    int* nr_store = (int*)PT_REGS_PARM1(ctx);

    struct data_t data = {};
    data.type = 1;

    bpf_core_read(&data.nr_idle_scan, sizeof(data.nr_idle_scan), nr_store);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/cnt_search_select_idle_core_observer")
int cnt_search_select_idle_core_observer(struct pt_regs *ctx) {
    int* nr_store = (int*)PT_REGS_PARM1(ctx);

    struct data_t data = {};
    data.type = 1;

    bpf_core_read(&data.nr_search_select_idle_core, sizeof(data.nr_search_select_idle_core), nr_store);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/count_select_idle_cpu_return_i.isra.0")
int count_select_idle_cpu_return_i(struct pt_regs *ctx) {
    int prev = PT_REGS_PARM2(ctx);
    int wake_affine_proposed = PT_REGS_PARM3(ctx);
    int recent_used = PT_REGS_PARM4(ctx);
    int idle_cpu_selected = PT_REGS_PARM5(ctx);

    struct data_t data = {};
    data.type = 2;
    data.prev = prev;
    data.cur_cpu = -2;
    data.wake_affine_proposed = wake_affine_proposed;
    data.recent_used = recent_used;
    data.idle_cpu_selected = idle_cpu_selected;
    data.idle_sibling_selected = -2;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/track_select_idle_sibling_result.isra.0")
int track_select_idle_sibling_result(struct pt_regs *ctx) {
    int prev = PT_REGS_PARM2(ctx);
    int cur_cpu = PT_REGS_PARM3(ctx);
    int wake_affine_proposed = PT_REGS_PARM4(ctx);
    int sibling_cpu_selected = PT_REGS_PARM5(ctx);

    struct data_t data = {};
    data.type = 2;
    data.prev = prev;
    data.cur_cpu = cur_cpu;
    data.wake_affine_proposed = wake_affine_proposed;
    data.recent_used = -2;
    data.idle_cpu_selected = -2;
    data.idle_sibling_selected = sibling_cpu_selected;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/select_idle_smt_loop_observer.isra.0")
int select_idle_smt_loop_observer(struct pt_regs *ctx) {
    int target = PT_REGS_PARM2(ctx);
    int cpu = PT_REGS_PARM3(ctx);

    struct data_t data = {};
    data.type = 3;
    data.cur_smt = target;
    data.cpu_smt_found = cpu;
    data.cur_core = -1;
    data.cpu_core_found = -1;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/select_idle_core_loop_observer.isra.0")
int select_idle_core_loop_observer(struct pt_regs *ctx) {
    int core = PT_REGS_PARM2(ctx);
    int cpu = PT_REGS_PARM3(ctx);

    struct data_t data = {};
    data.type = 3;
    data.cur_smt = -1;
    data.cpu_smt_found = -1;
    data.cur_core = core;
    data.cpu_core_found = cpu;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/update_idle_cpu_scan_observer.isra.0")
int update_idle_cpu_scan_observer(struct pt_regs *ctx) {
    struct data_t data = {};
    data.type = 4;

    bpf_core_read(&data.x1, sizeof(data.x1), (__u64*)PT_REGS_PARM1(ctx));
    data.llc_weight = PT_REGS_PARM2(ctx);
    data.x2 = PT_REGS_PARM3(ctx);
    data.pct = PT_REGS_PARM4(ctx);
    data.tmp3 = PT_REGS_PARM5(ctx);
    data.y3 = PT_REGS_PARM6(ctx);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/update_idle_cpu_scan_observer_with_boottime.isra.0")
int update_idle_cpu_scan_observer_with_boottime(struct pt_regs *ctx) {
   struct data_t data = {};
   data.type = 8;

   bpf_core_read(&data.x1, sizeof(data.x1), (__u64*)PT_REGS_PARM1(ctx));
   data.llc_weight = PT_REGS_PARM2(ctx);
   data.x2 = PT_REGS_PARM3(ctx);
   data.pct = PT_REGS_PARM4(ctx);
   data.boot_time = PT_REGS_PARM5(ctx);
   data.y3 = PT_REGS_PARM6(ctx);

   bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

SEC("kprobe/cnt_search_select_idle_core_observer_early_leave.isra.0")
int cnt_search_select_idle_core_observer_early_leave(struct pt_regs *ctx) {
    int* nr_store = (int*)PT_REGS_PARM1(ctx);

    struct data_t data = {};
    data.type = 1;

    bpf_core_read(&data.nr_search_select_idle_core_early_leave, sizeof(data.nr_search_select_idle_core_early_leave), nr_store);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/cnt_search_select_idle_cpu_observer")
int cnt_search_select_idle_cpu_observer(struct pt_regs *ctx) {
    int* nr_store = (int*)PT_REGS_PARM1(ctx);

    struct data_t data = {};
    data.type = 1;

    bpf_core_read(&data.nr_search_select_idle_cpu, sizeof(data.nr_search_select_idle_cpu), nr_store);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/update_idle_cpu_scan.isra.0")
int BPF_KPROBE(kpobe_update_idle_cpu_scan) {
    unsigned long* sum_util = (unsigned long*)&PT_REGS_PARM2(ctx);

    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 1;
    data.pid = pid;
    data.tid = tid;
    data.has_idle_core = 0;
    data.scale_factor = 0;
    data.sd_llc_size = 0;
    data.nr_idle_scan = 0;
    data.sum_util = *sum_util;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

// This one failed, update_idle_cpu_scan is invoked perioically, it doesn't show nr_idle_scan.
SEC("kretprobe/update_idle_cpu_scan.isra.0")
int BPF_KRETPROBE(kretpobe_update_idle_cpu_scan, int ret) {
    int nr_idle_scan = PT_REGS_RC(ctx);
    unsigned long* sum_util = (unsigned long*)&PT_REGS_PARM2(ctx);

    u32 tid = (bpf_get_current_pid_tgid() <<32 ) >> 32;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 1;
    data.pid = pid;
    data.tid = tid;
    data.has_idle_core = 0;
    data.scale_factor = 0;
    data.sd_llc_size = 0;
    data.nr_idle_scan = ret;
    data.sum_util = *sum_util;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

static unsigned long n(unsigned long x) {
    if (x > 1)
        return x * n(x -1);
    else if (x == 1)
        return 1;
}

SEC("kprobe/wake_affine")
int attach_probed_function(struct pt_regs *ctx) {
    unsigned long m = n(6000);
    return m;
}

SEC("kretprobe/wake_affine")
int attach_kretprobed_function(struct pt_regs *ctx) {
    unsigned long m = n(6000);
    return m;
}

SEC("kprobe/util_avg_observer1.isra.0")
int util_avg_observer1(struct pt_regs *ctx) {
    u64 rq_util_avg = (unsigned long)PT_REGS_PARM2(ctx);
    u64 se_util_avg = (unsigned long)PT_REGS_PARM3(ctx);
    u64 rq_util_avg_sub_result = (unsigned long)PT_REGS_PARM4(ctx);

    struct data_t data = {};
    data.type = 5;
    data.rq_util_avg = rq_util_avg;
    data.se_util_avg = se_util_avg;
    data.rq_util_avg_sub_result = rq_util_avg_sub_result;
    data.rq_util_avg_add_result = 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/util_avg_observer2.isra.0")
int util_avg_observer2(struct pt_regs *ctx) {
    u64 rq_util_avg = (unsigned long)PT_REGS_PARM2(ctx);
    u64 se_util_avg = (unsigned long)PT_REGS_PARM3(ctx);
    u64 rq_util_avg_add_result = (unsigned long)PT_REGS_PARM4(ctx);

    struct data_t data = {};
    data.type = 5;
    data.rq_util_avg = rq_util_avg;
    data.se_util_avg = se_util_avg;
    data.rq_util_avg_sub_result = 0;
    data.rq_util_avg_add_result = rq_util_avg_add_result;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kretprobe/get_update_sysctl_factor")
int get_update_sysctl_factor(struct pt_regs *ctx) {
    unsigned int factor = (unsigned int)PT_REGS_RC(ctx);

    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 6;
    data.factor = factor;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kretprobe/update_max_interval")
int update_max_interval(struct pt_regs *ctx) {
    unsigned long max_load_balance_interval = (unsigned long)PT_REGS_RC(ctx);

    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 6;
    data.max_load_balance_interval = max_load_balance_interval;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/max_load_balance_interval_observer1.isra.0")
int max_load_balance_interval_observer1(struct pt_regs *ctx) {
    unsigned long max_load_balance_interval = (unsigned long)PT_REGS_PARM2(ctx);
    unsigned long interval = (unsigned long)PT_REGS_PARM3(ctx);

    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 6;
    data.max_load_balance_interval = max_load_balance_interval;
    data.interval = interval;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/max_load_balance_interval_observer2.isra.0")
int max_load_balance_interval_observer2(struct pt_regs *ctx) {
    unsigned long max_load_balance_interval = (unsigned long)PT_REGS_PARM2(ctx);
    unsigned long interval = (unsigned long)PT_REGS_PARM3(ctx);

    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 6;
    data.max_load_balance_interval = max_load_balance_interval;
    data.interval = interval;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/count_pelt10.isra.0")
int count_pelt10(struct pt_regs *ctx) {
    unsigned long delta = (unsigned long)PT_REGS_PARM2(ctx);

    struct task_struct *current = (void *)bpf_get_current_task();

    struct data_t data = {};
    data.type = 7;
    data.delta = delta;

    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#ifndef __KSCHEDULE_H
#define __KSCHEDULE_H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

struct data_t {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 next_tid;
    __u32 has_idle_core;
    __u32 scale_factor;
    __u32 sd_llc_size;
    __u32 nr_idle_scan;
    __u32 nr_search_select_idle_core;
    __u32 nr_search_select_idle_core_early_leave;
    __u32 nr_search_select_idle_cpu;
    __u32 prev;
    __u32 cur_cpu;
    __u32 wake_affine_proposed;
    __u32 recent_used;
    __u32 idle_cpu_selected;
    __u32 idle_sibling_selected;
    __u32 cur_smt;
    __u32 cpu_smt_found;
    __u32 cur_core;
    __u32 cpu_core_found;
    __u64 sum_util;
    __u64 x1;
    __u32 llc_weight;
    __u64 x2;
    __u32 pct;
    __u64 tmp3;
    __u64 boot_time;
    __u64 y3;
    __u64 rq_util_avg;
    __u64 se_util_avg;
    __u64 rq_util_avg_sub_result;
    __u64 rq_util_avg_add_result;
    __u32 factor;
    __u64 max_load_balance_interval;
    __u64 interval;
    __u64 delta;
    __u64 vruntime;
    __u64 deadline;
    __u64 nextt_vruntime;
    __u64 nextt_deadline;
    char comm[CMD_LEN];
    char nextt_comm[CMD_LEN];
};

#endif //__KSCHEDULE_H

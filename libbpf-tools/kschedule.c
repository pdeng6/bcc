#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "kschedule.h"
#include "kschedule.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16

int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{   
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct data_t *info = data;

    if (info -> type == 1) {
        printf("type:%-2d, has_idle_core? %d, scale_factor: %d sd_llc size %-8u, nr_idle_scan %-8u, nr_search_select_idle_core %-8u, nr_search_select_idle_core_early_leave %-8u, nr_search_select_idle_cpu %-8u, sum_util %llu, %s\n", info->type, info->has_idle_core, info->scale_factor, info->sd_llc_size, info->nr_idle_scan, info->nr_search_select_idle_core, info->nr_search_select_idle_core_early_leave, info->nr_search_select_idle_cpu, info->sum_util, info->comm);
    } else if (info->type == 2) {
        printf("type:%-2d, prev: %-3d, cur_cpu: %-3d, wake_affine_proposed: %-3d, recent_used: %-3d, idle_cpu_selected: %-3d, idle_sibling_selected: %-3d\n", info->type, info->prev, info->cur_cpu, info->wake_affine_proposed, info->recent_used, info->idle_cpu_selected, info->idle_sibling_selected);
    } else if (info->type == 3) {
        printf("type:%-2d, cur_smt: %-3d, cpu_smt_found: %-3d, cur_core: %-3d, cpu_core_found: %-3d\n", info->type, info->cur_smt, info->cpu_smt_found, info->cur_core, info->cpu_core_found);
    }  else if (info->type == 4) {
        printf("type:%-2d, x1: %-3llu, llc_weight: %-3d, x2: %-3llu, pct: %-3d, tmp3: %-3llu, y3: %-3llu\n", info->type, info->x1, info->llc_weight, info->x2, info->pct, info->tmp3,info->y3);
    }  else if (info->type == 5) {
        printf("type:%-2d, rq_util_avg: %-3llu, se_util_avg: %-3llu, rq_util_avg_sub_result: %-3llu, rq_util_avg_add_result: %-3llu\n", info->type, info->rq_util_avg, info->se_util_avg, info->rq_util_avg_sub_result, info->rq_util_avg_add_result);
    }  else if (info->type == 6) {
        printf("type:%-2d, factor: %-3u, max_load_balance_interval: %-3llu, interval: %-3llu\n", info->type, info->factor, info->max_load_balance_interval, info->interval);
    }  else if (info->type == 7) {
        printf("type:%-2d, delta: %-3llu\n", info->type, info->delta);
    }  else if (info->type == 8) {
        printf("type:%-2d, x1: %-3llu, llc_weight: %-3d, x2: %-3llu, pct: %-3d, boot_time: %-3llu, y3: %-3llu\n", info->type, info->x1, info->llc_weight, info->x2, info->pct, info->boot_time,info->y3);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char* argv[]) {
    struct perf_buffer *pb = NULL;
    struct kschedule_bpf *obj;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = kschedule_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = kschedule_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = kschedule_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("%-8s %-16s %-64s\n", "PID", "COMM", "DEADLINE");

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			  handle_event, handle_lost_events, NULL, NULL);

    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    while ((err = perf_buffer__poll(pb, 100)) >= 0)
        ;

cleanup:
    perf_buffer__free(pb);
    kschedule_bpf__destroy(obj);

    return err != 0;
}

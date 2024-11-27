#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "monitor_perf_adjust_freq.h"
#include "monitor_perf_adjust_freq.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16

int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{   
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}


/* Function to be invoked at sys_fchmodat triggered */
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct data_t *info = data;

    printf("%-8d %-16s is unthrottle %-1d all event num: %4d, active number: %4d, probe: %10s\n", info->pid, info->comm,
            info->unthrottle, info->event_num, info->active_event_num, info->event_names);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(void) {
    struct perf_buffer *pb = NULL;
    struct monitor_perf_adjust_freq_bpf *obj;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = monitor_perf_adjust_freq_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = monitor_perf_adjust_freq_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = monitor_perf_adjust_freq_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("%-8s %-16s %-64s %-4s %-12s %-4s\n", "PID", "COMM", "is unthrottle", "NUM", "ACTIVE_NUM", "PROBE");

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
    monitor_perf_adjust_freq_bpf__destroy(obj);

    return err != 0;
}

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "kfio.h"
#include "kfio.skel.h"
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

    if (info->type == 1) {
    	printf("type:%-2d, pool: %-3llx, comm: %s pool id: %-3d\n", info->type, info->pool, info->comm ,info->pool_id);
    } else if (info->type == 2) {
    	printf("type:%-2d, inode: %-3llx, super_block: %-3llx, gran: %2u, is_hit_boundary: %-3d, tv_sec: %-3lld, tv_nsec: %-3lld, s_time_min: %-3lld, s_time_max: %-3lld, tid: %-3u, comm: %s\n", info->type, info->inode, info->super_block, info->gran, info->is_hit_boundary, info->tv_sec, info->tv_nsec, info->s_time_min, info->s_time_max, info->tid, info->comm);
    } else if (info->type == 3) {
    	printf("type:%-2d, flush wq loop start ns: %-3llu, flush wq loop end ns: %-3llu, tid: %-3u, comm: %s\n", info->type, info->flush_wq_loop_start_ns, info->flush_wq_loop_end_ns, info->tid, info->comm);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char* argv[]) {
    struct perf_buffer *pb = NULL;
    struct kfio_bpf *obj;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = kfio_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = kfio_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = kfio_bpf__attach(obj);
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
    kfio_bpf__destroy(obj);

    return err != 0;
}

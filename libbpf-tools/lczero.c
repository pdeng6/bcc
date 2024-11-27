#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "lczero.h"
#include "lczero.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16

__u32 search_worker_tid = 0;
__u32 task_worker_tid1 = 1;
__u32 task_worker_tid2 = 2;
__u32 task_worker_tid3 = 3;
__u32 task_worker_tid4 = 0;

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
    const char* mark_need_resched_string = "resched";
    const char* nomark_need_resched_string = "noresched";
    const char* search_worker_string = "master";
    const char* task_worker_string = "slave";
    const char* who = (info->tid == search_worker_tid) ? search_worker_string : task_worker_string;

    if (info -> type == 1) {
        const char* output = (info->vruntime < info->deadline) ? nomark_need_resched_string : mark_need_resched_string;
        printf("type:%-2d %-8s %-16s vruntime:%-16llu ddl:%-20llu, %s\n", info->type, who, info->comm, info->vruntime, info->deadline, output);
    }

    if (info -> type == 2) {
        printf("type:%-2d %-8s %-16s vruntime:%-16llu ddl:%-20llu\n", info->type, who, info->comm, info->vruntime, info->deadline);
    }

    if (info -> type == 3) {
        printf("type:%-2d %-8s start\n", info->type, who);
    }

    if (info -> type == 4) {
        printf("type:%-2d %-8s NotifyTaskWorker elapsed %-16llums\n", info->type, who, info->deadline/1000000);
    }

    if (info -> type == 5) {

        const char* next = NULL;
        if (info->tid == search_worker_tid) {
            who = search_worker_string;
        } else if (info->tid == task_worker_tid1 || info->next_tid == task_worker_tid2 || info->next_tid == task_worker_tid3 || info->next_tid == task_worker_tid4){
            who = task_worker_string;   
        } else {
            who = info->comm;
        }

        if (info->next_tid == search_worker_tid) {
            next = search_worker_string;
        } else if (info->next_tid == task_worker_tid1 || info->next_tid == task_worker_tid2 || info->next_tid == task_worker_tid3 || info->next_tid == task_worker_tid4){
            next = task_worker_string;   
        } else {
            next = info->nextt_comm;
        }
        printf("type:%-2d %-8s choose %-8s, cur deadline is %-16llums, next deadline is %-16llums\n", info->type, who, next, info->deadline/1000000, info->nextt_deadline/1000000);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int load_worker_tid(const char* file_path, struct lczero_bpf* skel) {
    FILE *fp = fopen(file_path, "r");
    char *line = NULL;
    size_t line_sz = 0;
    int ret = 0;
    size_t read_n = 0;

    if (!fp) {
        printf("Worker tid file open failed!\n");
        return -1;
    }

    if ((read_n = getline(&line, &line_sz, fp)) < 0) {
        printf("Worker tids read failed!\n");
        ret = -1;
        goto tail;
    }

    int a,b,c,d,e;
    size_t filled = sscanf(line, "%d %d %d %d %d\n", &a, &b, &c, &d, &e);

    if (filled != 5) {
        printf("Worker tids recognize failed!\n");
        ret = -1;
        goto tail;
    }

    printf("%u %u %u %u %u\n", search_worker_tid, task_worker_tid1, task_worker_tid2, task_worker_tid3, task_worker_tid4);
    skel->bss->search_worker_tid = a;
    skel->bss->task_worker_tid1 = b;
    skel->bss->task_worker_tid2 = c;
    skel->bss->task_worker_tid3 = d;
    skel->bss->task_worker_tid4 = e;

    search_worker_tid = a;
    task_worker_tid1 = b;
    task_worker_tid2 = c;
    task_worker_tid3 = d;
    task_worker_tid4 = e;

    tail:
    if (line) {
        free(line);
    }
    if (fp) {
        fclose(fp);
    }
    return ret;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Please specify worker tids file\n");
        exit(-1);
    }

    struct perf_buffer *pb = NULL;
    struct lczero_bpf *obj;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = lczero_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = lczero_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = lczero_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    if (load_worker_tid(argv[1], obj) != 0) {
        exit(-1);
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
    lczero_bpf__destroy(obj);

    return err != 0;
}

#ifndef __MONITOR_PERF_ADJUST_FREQ__H
#define __MONITOR_PERF_ADJUST_FREQ__H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

#ifndef EVENTS_LEN
#define EVENTS_LEN 256
#endif

struct data_t {
    __u32 pid;
    bool unthrottle;
    int event_num;
    int active_event_num;
    char comm[CMD_LEN];
    char event_names[EVENTS_LEN];
};

#endif //__MONITOR_PERF_ADJUST_FREQ__H

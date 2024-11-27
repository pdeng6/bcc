#ifndef __LCZERO_H
#define __LCZERO_H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

struct data_t {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 next_tid;
    __u64 vruntime;
    __u64 deadline;
    __u64 nextt_vruntime;
    __u64 nextt_deadline;
    char comm[CMD_LEN];
    char nextt_comm[CMD_LEN];
};

#endif //__LCZERO_H

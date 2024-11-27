#ifndef __KFIO_H
#define __KFIO_H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

struct data_t {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u64 pool;
    __u32 pool_id;
    __u64 inode;
    __u64 super_block;
    __u32 gran;
    __s64 tv_sec;
    __s64 tv_nsec;
    __s64 s_time_min;
    __s64 s_time_max;
    __u32 is_hit_boundary;
    __u64 flush_wq_loop_start_ns;
    __u64 flush_wq_loop_end_ns;
    char comm[CMD_LEN];
    char nextt_comm[CMD_LEN];
};

#endif //__KFIO_H

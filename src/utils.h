#if !defined(UTILS_H)
#define UTILS_H

#include "common.h"

#define NSEC_PER_SEC 1000000000ULL

u64 get_realtime_ns();

u64 get_time_ns();

void normalize_timespec(struct timespec *ts);

u64 timespec_to_ns(struct timespec *ts);

u64 normalize_timestamp_ns(i64 ts, i64 base);

void setup_looping_ts_and_txtime(struct timespec *ts, u64 *looping_ts,
    u64 *txtime, u64 period, u64 offset);

void update_lopping_and_txtime(struct timespec *ts, u64 *looping_ts,
    u64 *txtime, u64 period);
 
i32 set_realtime(pid_t pid, i8 prio, i8 cpu);

#endif // UTILS_H

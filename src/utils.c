#define _GNU_SOURCE

#include <sched.h>

#include "logger.h"
#include "utils.h"

__always_inline u64 timespec_to_ns(struct timespec *ts) {
    return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

__always_inline u64 get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return timespec_to_ns(&ts);
}

__always_inline u64 get_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return timespec_to_ns(&ts);
}

__always_inline void normalize_timespec(struct timespec *ts) {
    while (ts->tv_nsec > 999999999) {
		ts->tv_sec += 1;
		ts->tv_nsec -= NSEC_PER_SEC;
	}

	while (ts->tv_nsec < 0) {
		ts->tv_sec -= 1;
		ts->tv_nsec += NSEC_PER_SEC;
	}
}

__always_inline u64 normalize_timestamp_ns(i64 ts, i64 base) {
    u64 tmp = (u64) (ts / base);
    return tmp * base;
}

__always_inline void setup_looping_ts_and_txtime(
    struct timespec *ts, u64 *looping_ts,
    u64 *txtime, u64 period, u64 offset
) {
    *looping_ts = normalize_timestamp_ns(*looping_ts, period);

    ts->tv_sec = *looping_ts / NSEC_PER_SEC;
    ts->tv_nsec = *looping_ts % NSEC_PER_SEC;

    normalize_timespec(ts);

    *txtime = *looping_ts + offset;
}

__always_inline void update_lopping_and_txtime(
    struct timespec *ts, u64 *looping_ts,
    u64 *txtime, u64 period
) {
    *looping_ts += period;

    ts->tv_sec = *looping_ts / NSEC_PER_SEC;
    ts->tv_nsec = *looping_ts % NSEC_PER_SEC;

    *txtime += period;
}

i32 set_realtime(pid_t pid, i8 prio, i8 cpu) {

    // TODO(garbu): handle different scheduling algo
    // i32 min = sched_get_priority_min(SCHED_FIFO);
    // i32 max = sched_get_priority_max(SCHED_FIFO);

    if (prio < 0) {
        return -1;
    }

    char *sched_name;
    i32 sched_type = sched_getscheduler(pid);
    switch (sched_type) {
        case SCHED_FIFO:
            sched_name = "First in-first out (FIFO)";
            break;
        case SCHED_RR:
            sched_name = "Round-robin (RR)";
            break;
        case SCHED_OTHER:
            sched_name = "Completely Fair Scheduler (CFQ)";
            break;
        default:
            sched_name = "Unknown Scheduler";
            break;
    }

    LOG_DEBUG("Process is scheduled with the %s policy", sched_name);

    struct sched_param sp;
    sp.sched_priority = prio;
    sched_setscheduler(pid, SCHED_FIFO, &sp);

    // i32 err = pthread_getschedparam(thread, &policy, &sp);
    i32 err = sched_getparam(pid, &sp);;
    if (err) {
        LOG_ERROR("Failed to get process params (sched_getparam): %s", strerror(errno));
        return - 1;
    }

    sched_name = "Completely Fair Scheduler (CFQ)";
    sched_type = sched_getscheduler(pid);
    switch (sched_type) {
        case SCHED_FIFO:
            sched_name = "First in-first out (FIFO)";
            break;
        case SCHED_RR:
            sched_name = "Round-robin (RR)";
            break;
        default:
            break;
    }

    LOG_DEBUG("New scheduler: %s\tnew priority = %d", sched_name, sp.sched_priority);

    if (cpu < 0) {
        return -1;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    // err = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    err = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
    if (err) {
        LOG_ERROR("Failed to set thread CPU affinity (sched_setaffinity): %s", strerror(errno));
        return -1;
    }

    return 0;
}

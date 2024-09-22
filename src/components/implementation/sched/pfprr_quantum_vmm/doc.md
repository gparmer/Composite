## sched.pfprr_quantum_static

A minimal scheduling libary implementation of a scheduler based on

- preemptive, fixed-priority, round-robin scheduling,
- periodic, quantum-based timers, and
- static memory allocation for the threads.

### Description

Export mainly the scheduling and blockpoint APIs as a general-purpose scheduler.

### Usage and Assumptions

See the scheduler API.
This assumes that the macros for the maximum number of threads and the quantum size are properly configured.
Does not yet support hierarchy.

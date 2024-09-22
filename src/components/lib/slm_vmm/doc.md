## Minimal/Modular Scheduling Library (`slm`)

`slm` is a set of modules that can be composed into a scheduler.
Unlike our previous version of a scheduling library (`sl`), this focuses on simplifying the logic, removing edge-cases (and functionality), and efficiency.
Efficiency in the scheduling library is of increased importance with `slite` (scheduling light) that avoids system calls on dispatches to blocked threads, thus removing all kernel overhead, and emphasizing library overhead.

### Description

`slm` modularizes scheduling logic into

- timeout and wakeup logic,
- scheduling policy,
- inter-core coordination mechanisms,
- the blockpoint API for efficient client synchronization, and
- core thread state and synchronization logic.

Later, this can include

- a separate thread per-child scheduler to manage hierarchical scheduling.

The core API that this library exports is in `slm.h`, and the APIs of the different modules (only relevant if you're implementing your own) is in `slm_api.h`.

### Usage and Assumptions

An example of `slm`'s use is in `implementation/tests/slm/`.
This library currently assumes that it is the root scheduler of the system (with an infinite `tcap`).

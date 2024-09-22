## netshmem

### Description

This library provides some wrapper api based on lib shm_bm to enable users to initialize and create shared packet memory. 

### Usage and Assumptions

It has two assumptions. One is a thread will only create a single shared packet memory, which enables a component
to find shared memory region by thread id. The other one is that it assumes a thread will not be destoryed and the thread id cannot be assigned to 
another new thread.


```c
void netshmem_create(void);
```

This api is used to create a shared packet memory. Thus, it assumes only the application will call this once to create a shared memory.

```c
void netshmem_map_shmem(cbuf_t shm_id)
```

This api is used to map a shared packet memory. Thus, it assmues the component who needs to map a shared memory region calls this function.

```c
shm_bm_t netshmem_get_shm();
```

This api can return the shared memory pointer of a thread in a component.

```c
cbuf_t netshmem_get_shm_id();
```

This api can return the shared memory id of a thread in a component.

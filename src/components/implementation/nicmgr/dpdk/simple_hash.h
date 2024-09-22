#include <cos_types.h>

#define MAX_IP 100
#define MAX_PORT 1000


void simple_hash_init(void);
void simple_hash_add(u32_t ip, u16_t port, void *data);
void *simple_hash_find(u32_t ip, u16_t port);

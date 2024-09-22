#pragma once

#include <simple_hash.h>
#include <llprint.h>

static void *g_hash_tbl[MAX_IP][MAX_PORT];

void 
simple_hash_add(u32_t ip, u16_t port, void *data) {
	if (!g_hash_tbl[ip % MAX_IP][port]) {
		g_hash_tbl[ip % MAX_IP][port] = data;
	} else {
		printc("hash conflict:ip:%u, port:%u\n", ip, port);
		assert(0);
	}
}

void
simple_hash_init(void)
{
	for (int i = 0; i < MAX_IP; i++) {
		for (int j = 0; j < MAX_PORT; j++) {
			g_hash_tbl[i][j] = 0;
		}
	}
}

void *
simple_hash_find(u32_t ip, u16_t port) {
	if (unlikely(port > MAX_PORT)) return NULL;
	return g_hash_tbl[ip % MAX_IP][port];
}

/*
 * Copyright 2019, Phani Gadepalli, Sebastian Foubert and Runyu Pan
 *
 * This uses a two clause BSD License.
 */

#ifndef PERFDATA_H
#define PERFDATA_H

#include <cos_debug.h>
#include <llprint.h>
#include <errno.h>

#ifndef PERF_VAL_MAX_SZ
#define PERF_VAL_MAX_SZ    10000
#endif

#define PERF_VAL_MIN_SZ    10
#define PERF_DATA_NAME     64
#define PERF_PTILE_SZ      3

#define PERF_DATA_DEBUG

enum ptile_id {
	PTILE_90 = 0,
	PTILE_95,
	PTILE_99,
};

struct perfdata {
	char      name[PERF_DATA_NAME];
	cycles_t *values;
	int       sz;
	int	  array_size;
	cycles_t  min, max, avg, total;
	cycles_t  sd, var;
	cycles_t  ptiles[PERF_PTILE_SZ]; /* 90, 95, 99 */
};

static void
perfdata_init(struct perfdata *pd, const char *nm, cycles_t * result_array, int size)
{
	memset(pd, 0, sizeof(struct perfdata));
	memset(result_array, 0, size * sizeof(cycles_t));
	pd->values = result_array;
	pd->array_size = size;
	strncpy(pd->name, nm, PERF_DATA_NAME-1);
}

static void
__perfdata_print_values(struct perfdata *pd)
{
#ifdef PERF_DATA_DEBUG
	int i;

	for (i = 0 ; i < pd->sz ; i++) printc("%llu\n", pd->values[i]);
#endif
}

static inline int
perfdata_add(struct perfdata *pd, cycles_t val)
{
	//if (unlikely(pd->sz >= PERF_VAL_MAX_SZ)) return -ENOSPC;
	if (unlikely(pd->sz >= pd->array_size)) return -ENOSPC;

	pd->values[pd->sz] = val;
	pd->total += val;
	pd->sz ++;

	return 0;
}

/*
 * From http://stackoverflow.com/questions/3581528/how-is-the-square-root-function-implemented
 * By Argento
 */

static cycles_t
__sqrt_ull(cycles_t n)
{
	cycles_t lo = 0, hi = n, mid;
	int i;

	for(i = 0 ; i < 1000 ; i++) {
		mid = (lo + hi) / 2;

		if(mid * mid == n) return mid;

		if(mid * mid > n) hi = mid;
		else              lo = mid;
	}

	return mid;
}

/*
 * Code from: https://github.com/liuxinyu95/AlgoXY/blob/algoxy/sorting/merge-sort/src/mergesort.c
 *
 * A in-placed version based on:
 * Jyrki Katajainen, Tomi Pasanen, Jukka Teuhola. ``Practical in-place mergesort''. Nordic Journal of Computing, 1996.
 */
static void __inplace_merge_sort(cycles_t *, int, int);

static void
__swap(cycles_t* xs, int i, int j)
{
	cycles_t tmp = xs[i];

	xs[i] = xs[j];
	xs[j] = tmp;
}

/*
 * merge two sorted subs xs[i, m) and xs[j...n) to working area xs[w...]
 */
static void
__workarea_merge(cycles_t* xs, int i, int m, int j, int n, int w)
{
	while (i < m && j < n) __swap(xs, w++, xs[i] < xs[j] ? i++ : j++);
	while (i < m) __swap(xs, w++, i++);
	while (j < n) __swap(xs, w++, j++);
}


/*
 * sort xs[l, u), and put result to working area w.
 * constraint, len(w) == u - l
 */
static void
__workarea_sort(cycles_t* xs, int l, int u, int w)
{
	int m;

	if (u - l > 1) {
		m = l + (u - l) / 2;

		__inplace_merge_sort(xs, l, m);
		__inplace_merge_sort(xs, m, u);
		__workarea_merge(xs, l, m, m, u, w);
	}
	else {
		while (l < u) __swap(xs, l++, w++);
	}
}

static void
__inplace_merge_sort(cycles_t* xs, int l, int u)
{
	int m, n, w;

	if (u - l > 1) {
		m = l + (u - l) / 2;
		w = l + u - m;

		/* the last half contains sorted elements */
		__workarea_sort(xs, l, m, w);

		while (w - l > 2) {
			n = w;
			w = l + (n - l + 1) / 2;

			/* the first half of the previous working area contains sorted elements */
			__workarea_sort(xs, w, n, l);
			__workarea_merge(xs, l, l + n - w, n, u, w);
		}

		/*switch to insertion sort*/
		for (n = w; n > l; --n) {
			for (m = n; m < u && xs[m] < xs[m-1]; ++m) {
				__swap(xs, m, m - 1);
			}
		}
	}
}

static void
perfdata_calc(struct perfdata *pd)
{
	int i, j;

	__inplace_merge_sort(pd->values, 0, pd->sz);

	pd->min = pd->values[0];
	pd->max = pd->values[pd->sz - 1];
	pd->avg = pd->total / pd->sz;

	for (i = 0 ; i < pd->sz ; i++) pd->var += (pd->values[i] - pd->avg) * (pd->values[i] - pd->avg);
	pd->var /= pd->sz;

	pd->sd = __sqrt_ull(pd->var);

	pd->ptiles[PTILE_90] = pd->values[(int)((pd->sz * 90) / 100) - 1];
	pd->ptiles[PTILE_95] = pd->values[(int)((pd->sz * 95) / 100) - 1];
	pd->ptiles[PTILE_99] = pd->values[(int)((pd->sz * 99) / 100) - 1];
}

static int
perfdata_sz(struct perfdata *pd)
{ return pd->sz; }

static cycles_t
perfdata_min(struct perfdata *pd)
{ return pd->min; }

static cycles_t
perfdata_max(struct perfdata *pd)
{ return pd->max; }

static cycles_t
perfdata_avg(struct perfdata *pd)
{ return pd->avg; }

static cycles_t
perfdata_sd(struct perfdata *pd)
{ return pd->sd; }

static cycles_t
perfdata_90ptile(struct perfdata *pd)
{ return pd->ptiles[PTILE_90]; }

static cycles_t
perfdata_95ptile(struct perfdata *pd)
{ return pd->ptiles[PTILE_95]; }

static cycles_t
perfdata_99ptile(struct perfdata *pd)
{ return pd->ptiles[PTILE_99]; }

static void
perfdata_print(struct perfdata *pd)
{
	printc("PD: %s - sz:%d,SD:%llu,Mean:%llu,99%%:%llu, Max: %llu\n",
		pd->name, pd->sz, pd->sd, pd->avg, pd->ptiles[PTILE_99], pd->max);
}

static void
perfdata_all(struct perfdata *pd)
{
	int i;

	perfdata_print(pd);

	printc(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");

	printc("#Latency\n");
	for (i = 0 ; i < pd->sz ; i++) printc("V: %llu\n", pd->values[i]);

	printc("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");
}


static void
perfdata_raw(struct perfdata *pd)
{
	int i;

	printc("#PD:%s\n", pd->name);
	printc("#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n");

	printc("#Latency\n");
	for (i = 0 ; i < pd->sz ; i++) printc("V: %llu\n", pd->values[i]);

	printc("#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");
}

#endif /* PERFDATA_H */

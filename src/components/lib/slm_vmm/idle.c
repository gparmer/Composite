#include <cos_debug.h>

/* Override this to do initialization before idle computation */
CWEAKSYMB void slm_idle_comp_initialization(void) { return; }
/* Override this to do repetitive computation in idle */
CWEAKSYMB void slm_idle_iteration(void) { return; }

void
slm_idle(void *d)
{
	slm_idle_comp_initialization();

	while (1) {
		slm_idle_iteration();
	}

	BUG();
}

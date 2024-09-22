#include <cos_types.h>
#include <cos_debug.h>
#include <vmrt.h>
#include "vrtc.h"

/* NOTE: this is just to emulate those data indexed by the CMOS data adress, the functionality of rtc is not fully implemented */
static u8_t rtc_data_address[0x1A];
static u8_t curr_data_addr;

void
vrtc_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu)
{
	assert(sz == IO_BYTE);
	if (dir == IO_IN) {
		switch (port)
		{
		case CMOS_CMD_PORT:
			assert(0);
			break;;
		case CMOS_DATA_PORT:
			vcpu->shared_region->ax = rtc_data_address[curr_data_addr];
			break;
		default:
			assert(0);
			break;
		}
	} else {
		u8_t val = vcpu->shared_region->ax;
		switch (port)
		{
		case CMOS_CMD_PORT:
			if (val & 0x80) {
				printc("NMI disabled\n");
			} else {
				printc("NMI enabled\n");
			}
			curr_data_addr = val & 0x7f;
			if (curr_data_addr == 0x0f) {
				printc("shutdown status byte is set now\n");
			} else {
				/* NOTE: do nothing and don't include full functionality */
			}
			break;
		case CMOS_DATA_PORT:
			break;
		default:
			assert(0);
			break;
		}

	}
}

static void __attribute__((constructor))
init(void)
{
	memset(&rtc_data_address, 0, sizeof(rtc_data_address));
}

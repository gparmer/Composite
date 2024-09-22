#include <cos_component.h>
#include <cos_stubs.h>
#include <contigmem.h>


COS_CLIENT_STUB(cbuf_t, contigmem_shared_alloc_aligned, unsigned long num_pages, unsigned long align, vaddr_t *pgaddr)
{
	COS_CLIENT_INVCAP;
	word_t unused, addrret;
	cbuf_t ret;

	ret = cos_sinv_2rets(uc, num_pages, align, 0, 0, &addrret, &unused);
	*pgaddr = addrret;

	return ret;
}

COS_CLIENT_STUB(cbuf_t, contigmem_ro_shared_alloc_aligned, unsigned long num_pages, unsigned long align, vaddr_t *pgaddr)
{
	COS_CLIENT_INVCAP;
	word_t unused, addrret;
	cbuf_t ret;

	ret = cos_sinv_2rets(uc, num_pages, align, 0, 0, &addrret, &unused);
	*pgaddr = addrret;

	return ret;
}

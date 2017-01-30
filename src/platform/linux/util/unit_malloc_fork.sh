#!/bin/sh

./cos_loader \
"c0.o, ;llboot.o, ;*fprr.o, ;mm.o, ;print.o, ;boot.o, ;\
!cbuf.o,a5;!va.o, a2;!l.o,a1;!mpool.o, a3;!vm.o, a1;\
!cbboot.o,a6;!malloccomp.o, ;!mallocfork.o,a9:\
c0.o-llboot.o;\
print.o-llboot.o;\
fprr.o-print.o|[parent_]mm.o|[faulthndlr_]llboot.o;\
mm.o-[parent_]llboot.o|print.o;\
boot.o-print.o|fprr.o|mm.o|llboot.o;\
mpool.o-print.o|fprr.o|mm.o|va.o|l.o|llboot.o;\
vm.o-fprr.o|print.o|mm.o|l.o|llboot.o;\
va.o-fprr.o|print.o|mm.o|l.o|boot.o|vm.o|llboot.o;\
l.o-fprr.o|mm.o|print.o|llboot.o;\
cbuf.o-fprr.o|print.o|l.o|mm.o|va.o|llboot.o;\
cbboot.o-print.o|fprr.o|mm.o|boot.o|cbuf.o|[parent_]llboot.o;\
mallocfork.o-fprr.o|cbuf.o|malloccomp.o|print.o|cbboot.o;\
malloccomp.o-fprr.o|cbuf.o|va.o|print.o|cbboot.o\
" ./gen_client_stub

#!/bin/sh

./cos_loader \
"c0.o, ;llboot.o, ;*fprr.o, ;mm.o, ;print.o, ;boot.o, ;\
\
!l.o,a1;!mpool.o,a3;!te.o,a3;!sm.o,a4;!e.o,a4;!buf.o,a5;!bufp.o, ;!va.o,a2;!vm.o,a1;!cbboot.o,a6;!tp.o,a7;!ucbuf1.o,a10;!ucbuf2.o, ;!ucbufp.o,a9;!stat.o,a25:\
\
c0.o-llboot.o;\
fprr.o-print.o|[parent_]mm.o|[faulthndlr_]llboot.o;\
mm.o-[parent_]llboot.o|print.o;\
boot.o-print.o|fprr.o|mm.o|llboot.o;\
l.o-fprr.o|mm.o|print.o;\
te.o-sm.o|print.o|fprr.o|mm.o|va.o;\
e.o-sm.o|fprr.o|print.o|mm.o|l.o|va.o;\
stat.o-sm.o|te.o|fprr.o|l.o|print.o|e.o;\
sm.o-print.o|fprr.o|mm.o|boot.o|va.o|l.o|mpool.o;\
buf.o-boot.o|sm.o|fprr.o|print.o|l.o|mm.o|va.o|mpool.o;\
bufp.o-sm.o|fprr.o|print.o|l.o|mm.o|va.o|mpool.o|buf.o;\
mpool.o-print.o|fprr.o|mm.o|boot.o|va.o|l.o;\
cbboot.o-print.o|fprr.o|mm.o|boot.o;\
tp.o-sm.o|buf.o|print.o|te.o|fprr.o|mm.o|va.o|mpool.o;\
vm.o-fprr.o|print.o|mm.o|l.o|boot.o;\
va.o-fprr.o|print.o|mm.o|l.o|boot.o|vm.o;\
ucbuf1.o-fprr.o|sm.o|ucbuf2.o|ucbufp.o|print.o|mm.o|va.o|buf.o|bufp.o|l.o;\
ucbuf2.o-sm.o|print.o|mm.o|va.o|bufp.o|buf.o|l.o;\
ucbufp.o-fprr.o|sm.o|print.o|mm.o|va.o|bufp.o|buf.o|l.o\
" ./gen_client_stub

#mpd.o-sm.o|cg.o|fprr.o|print.o|te.o|mm.o|va.o;\
#!mpd.o,a5;
#[print_]trans.o

#!/bin/sh

# sh? between id 18<->39, 40->50 are base cases

./cos_loader \
"c0.o, ;*fprr.o, ;mm.o, ;printl.o, ;schedconf.o, ;st.o, ;bc.o, ;boot.o,a4;cg.o,a1;\
\
!mpool.o,a2;!l.o,a7;!te.o,a3;!e.o,a3;!sm.o,a2;!va.o,a1;!buf.o,a2;!tp.o,a4;\
\
(!p0.o=exe_cb_pt.o),a10'p3 e600 s0 d120';\
(!p1.o=exe_cb_pt.o),a11'p4 e400 s0 d120';\
(!p2.o=exe_cb_pt.o),a10'p3 e7500 s0 d120';\
(!p3.o=exe_cb_pt.o),a12'p6 e22800 s0 d120';\
(!p4.o=exe_cb_pt.o),a10'p3 e300 s0 d120';\
(!p5.o=exe_cb_pt.o),a13'p8 e800 s0 d120';\
(!p6.o=exe_cb_pt.o),a14'p9 e6300 s0 d120';\
(!p7.o=exe_cb_pt.o),a15'p10 e5000 s0 d120';\
(!p8.o=exe_cb_pt.o),a30'p0 e500000 s10 d40';\
\
(!sh0.o=exe_cb_sh.o),'s50000 n20000 a0';(!sh1.o=exe_cb_sh.o),'s5000 n20000 r2 a0';(!sh2.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
(!sh3.o=exe_cb_sh.o),'s5000 n20000 r32 a0';(!sh4.o=exe_cb_sh.o),'s50000 n20000 r125 a0';(!sh5.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
(!sh6.o=exe_cb_sh.o),'s50000 n20000 r32 a0';(!sh7.o=exe_cb_sh.o),'s50000 n20000 r96 a0';(!sh8.o=exe_cb_sh.o),'s500000 n20000 a0';\
\
(!sh18.o=exe_cb_sh.o),'s500000 n20000 r32 a0';\
(!sh19.o=exe_cb_sh.o),'s50000 n20000 r32 a0';\
(!sh15.o=exe_cb_sh.o),'s50000 n20000 r32 a0';\
(!sh16.o=exe_cb_sh.o),'s5000 n20000 r32 a0';\
\
(!sh9.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
(!sh10.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
(!sh11.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
(!sh12.o=exe_cb_sh.o),'s50000 n20000 r96 a0';\
\
!exe_cb_sbc.o, :\
\
c0.o-fprr.o;\
fprr.o-printl.o|mm.o|st.o|schedconf.o|[parent_]bc.o;\
cg.o-fprr.o;\
l.o-fprr.o|mm.o|printl.o;\
te.o-printl.o|fprr.o|mm.o|va.o;\
mm.o-printl.o;\
e.o-fprr.o|printl.o|mm.o|l.o|st.o|sm.o|va.o;\
st.o-printl.o;\
schedconf.o-printl.o;\
bc.o-printl.o;\
boot.o-printl.o|fprr.o|mm.o|schedconf.o|cg.o;\
va.o-printl.o|fprr.o|mm.o|boot.o|l.o;\
sm.o-printl.o|fprr.o|mm.o|boot.o|va.o|mpool.o|l.o;\
buf.o-fprr.o|printl.o|l.o|mm.o|boot.o|va.o|mpool.o;\
mpool.o-printl.o|fprr.o|mm.o|boot.o|va.o|l.o;\
tp.o-sm.o|buf.o|printl.o|te.o|fprr.o|schedconf.o|mm.o|va.o|mpool.o;\
\
p0.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p1.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p2.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p3.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p4.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p5.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p6.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p7.o-te.o|fprr.o|schedconf.o|printl.o|sh18.o|sm.o;\
p8.o-te.o|fprr.o|schedconf.o|printl.o|[calll_]sh10.o|[callr_]sh9.o|sm.o;\
\
sh9.o-fprr.o|schedconf.o|printl.o|[calll_]sh10.o|[callr_]sh11.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh10.o-fprr.o|schedconf.o|printl.o|[calll_]exe_cb_sbc.o|[callr_]sh12.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh11.o-fprr.o|schedconf.o|printl.o|[calll_]sh12.o|[callr_]sh0.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh12.o-fprr.o|schedconf.o|printl.o|[calll_]exe_cb_sbc.o|[callr_]sh1.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
\
sh18.o-fprr.o|schedconf.o|printl.o|[calll_]sh15.o|[callr_]sh19.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh19.o-fprr.o|schedconf.o|printl.o|[calll_]sh16.o|[callr_]exe_cb_sbc.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh15.o-fprr.o|schedconf.o|printl.o|[calll_]sh0.o|[callr_]sh16.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh16.o-fprr.o|schedconf.o|printl.o|[calll_]sh2.o|[callr_]exe_cb_sbc.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
\
sh0.o-fprr.o|schedconf.o|printl.o|[calll_]sh1.o|[callr_]sh2.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh1.o-fprr.o|schedconf.o|printl.o|[calll_]sh3.o|[callr_]sh4.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh2.o-fprr.o|schedconf.o|printl.o|[calll_]sh4.o|[callr_]sh5.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh3.o-fprr.o|schedconf.o|printl.o|[calll_]exe_cb_sbc.o|[callr_]sh6.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh4.o-fprr.o|schedconf.o|printl.o|[calll_]sh6.o|[callr_]sh7.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh5.o-fprr.o|schedconf.o|printl.o|[calll_]sh7.o|[callr_]exe_cb_sbc.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh6.o-fprr.o|schedconf.o|printl.o|[calll_]exe_cb_sbc.o|[callr_]sh8.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh7.o-fprr.o|schedconf.o|printl.o|[calll_]sh8.o|[callr_]exe_cb_sbc.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
sh8.o-fprr.o|schedconf.o|printl.o|[calll_]exe_cb_sbc.o|[callr_]exe_cb_sbc.o|sm.o|buf.o|va.o|mm.o|l.o|te.o;\
\
exe_cb_sbc.o-sm.o|va.o|mm.o|printl.o\
" ./gen_client_stub

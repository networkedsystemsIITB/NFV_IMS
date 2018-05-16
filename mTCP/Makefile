# TODO: Make this Makefile.in pretty

TARGETS = all
CC=g++ -fpermissive -std=c++11 -g -O3 -Wno-write-strings -Wall
CC1= g++ -std=c++11 -g
DPDK=0
PS=0
NETMAP=1
CFLAGS=-DMAX_CPUS=2

# DPDK LIBRARY and HEADER
DPDK_INC=/include
DPDK_LIB=/lib/

# mtcp library and header 
MTCP_FLD    =../../mtcp/
MTCP_INC    =-I${MTCP_FLD}/include
MTCP_LIB    =-L${MTCP_FLD}/lib
MTCP_TARGET = ${MTCP_LIB}/libmtcp.a

UTIL_FLD = ../../util
UTIL_INC = -I${UTIL_FLD}/include
UTIL_OBJ = ${UTIL_FLD}/http_parsing.o ${UTIL_FLD}/tdate_parse.o ${UTIL_FLD}/netlib.o


PS_DIR = ../../io_engine/
PS_INC = ${PS_DIR}/include
INC = -I./include/ ${UTIL_INC} ${MTCP_INC} -I${UTIL_FLD}/include
LIBS = ${MTCP_LIB}
ifeq ($(PS),1)
INC += -I{PS_INC}
LIBS += -lmtcp -L${PS_DIR}/lib -lps -lpthread -lnuma -lrt
endif

ifeq ($(NETMAP),1)
LIBS += -lmtcp -lpthread -lnuma -lrt
endif

# CFLAGS for DPDK-related compilation
INC += ${MTCP_INC}
ifeq ($(DPDK),1)
DPDK_MACHINE_FLAGS = $(shell cat /include/cflags.txt)
INC += ${DPDK_MACHINE_FLAGS} -I${DPDK_INC} -include $(DPDK_INC)/rte_config.h
endif

ifeq ($(shell uname -m),x86_64)
LIBS += -m64
endif

ifeq ($(DPDK),1)
DPDK_LIB_FLAGS = $(shell cat /lib/ldflags.txt)
#LIBS += -m64 -g -O3 -pthread -lrt -march=native -Wl,-export-dynamic ${MTCP_FLD}/lib/libmtcp.a -L../../dpdk/lib -Wl,-lnuma -Wl,-lmtcp -Wl,-lpthread -Wl,-lrt -Wl,-ldl -Wl,${DPDK_LIB_FLAGS}
LIBS += -g -O3 -pthread -lrt -march=native -export-dynamic ${MTCP_FLD}/lib/libmtcp.a -L../../dpdk/lib -lnuma -lmtcp -lpthread -lrt -ldl ${DPDK_LIB_FLAGS}
else
#LIBS += -m64 -g -O3 -pthread -lrt -march=native -Wl,-export-dynamic ${MTCP_FLD}/lib/libmtcp.a -L../../dpdk/lib -Wl,-lnuma -Wl,-lmtcp -Wl,-lpthread -Wl,-lrt -Wl,-ldl -Wl,${DPDK_LIB_FLAGS}
LIBS += -g -O3 -pthread -lrt -march=native -export-dynamic ${MTCP_FLD}/lib/libmtcp.a -L../../dpdk/lib -lnuma -lmtcp -lpthread -lrt -ldl ${DPDK_LIB_FLAGS}
endif

#LDFLAGS += -lboost_system

ifeq ($V,) # no echo
	export MSG=@echo
	export HIDE=@
else
	export MSG=@\#
	export HIDE=
endif

all: b c d e

utils.o: utils.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
packet.o: packet.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
sip.o: sip.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
uecontext.o: uecontext.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
telecom.o: telecom.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
sync.o: sync.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
security.o : security.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}
	
mtcp_pcscf.o: pcscf.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< -pthread  ${LIBS} ${CFLAGS} ${INC} -o mtcp_pcscf.o
mtcp_icscf.o: icscf.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< -pthread  ${LIBS} ${CFLAGS} ${INC} -o mtcp_icscf.o	
mtcp_hss.o: hss.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< -pthread  ${LIBS} ${CFLAGS} ${INC} -o mtcp_hss.o	
mtcp_scscf.o: scscf.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< -pthread  ${LIBS} ${CFLAGS} ${INC} -o mtcp_scscf.o	
#b: 
#	g++ -std=c++11 -o b.o lib.o libpacket.o utils.o ${MTCP_FLD}/lib/libmtcp.a -pthread -lboost_system
#B_P = b.o lib.o libpacket.o utils.o ${MTCP_FLD}/lib/libmtcp.a
#B_R = ${CC} -o b $(B_P) ${LIBS}  ${UTIL_OBJ} -lboost_system
B_P = sync.o telecom.o uecontext.o sip.o packet.o utils.o security.o mtcp_pcscf.o ${MTCP_FLD}/lib/libmtcp.a
B_R = ${CC} -o mtcp_pcscf $(B_P) ${LIBS}  ${UTIL_OBJ}  -lcrypto -pthread 

C_P = sync.o telecom.o uecontext.o sip.o packet.o utils.o security.o  mtcp_icscf.o ${MTCP_FLD}/lib/libmtcp.a
C_R = ${CC} -o mtcp_icscf $(C_P) ${LIBS}  ${UTIL_OBJ}  -lcrypto -pthread 

D_P = sync.o telecom.o uecontext.o sip.o packet.o utils.o security.o mtcp_hss.o ${MTCP_FLD}/lib/libmtcp.a
D_R = ${CC} -o mtcp_hss $(D_P) ${LIBS}  ${UTIL_OBJ}  -lcrypto -pthread

E_P = sync.o telecom.o uecontext.o sip.o packet.o utils.o security.o mtcp_scscf.o ${MTCP_FLD}/lib/libmtcp.a
E_R = ${CC} -o mtcp_scscf $(E_P) ${LIBS}  ${UTIL_OBJ}  -lcrypto -pthread

b:	$(B_P)
	$(B_R)

c:	$(C_P)
	$(C_R)

d:	$(D_P)
	$(D_R)

e: 	$(E_P)
	$(E_R)


#b: b.o lib.o libpacket.o utils.o ${MTCP_FLD}/lib/libmtcp.a
#	$(MSG) "   CC $<"
#	$(HIDE) ${CC} -o $@ $< ${LIBS} ${UTIL_OBJ} -lboost_system


clean:
	rm -f *~ *.o ${TARGETS} log_* mtcp_* ransim.out

distclean: clean
	rm -rf Makefile

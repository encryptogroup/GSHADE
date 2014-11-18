CC=g++
OT=ot
VLADOT=vladot
DISTANCE=dst
BOOST= #-I /usr/local/boost_1_49_0/
BOOST_LIBRARIES= #-lboost_system -lboost_thread
LIBRARIES=-lgmp -lgmpxx -lpthread util/Miracl/miracl.a -L /usr/lib  -lssl -lcrypto
MIRACL_PATH= -I./util/Miracl
SOURCES_UTIL=util/*.cpp
OBJECTS_UTIL=util/*.o
SOURCES_DST=mains/distance_framework.cpp
OBJECTS_DST=mains/distance_framework.o
SOURCES_OT=ot/*.cpp
OBJECTS_OT=ot/*.o
OBJECTS_MIRACL= util/Miracl/*.o
COMPILER_OPTIONS=-O3#-g
BATCH=
INCLUDE=-I.. 
CFLAGS=-fpermissive

all: ${DISTANCE}
	
dst: ${OBJECTS_DST} ${OBJECTS_UTIL} ${OBJECTS_MIRACL} ${OBJECTS_OT}
	${CC} -o dst.exe ${CFLAGS} ${OBJECTS_DST} ${OBJECTS_UTIL} ${OBJECTS_MIRACL} ${OBJECTS_OT} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS} 

	
${OBJECTS_DST}: ${SOURCES_DST}$
	@cd mains; ${CC} -c ${INCLUDE} ${CFLAGS} ${COMPILER_OPTIONS}  distance_framework.cpp 

${OBJECTS_UTIL}: ${SOURCES_UTIL}$  
	@cd util; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS}  *.cpp

${OBJECTS_OT}: ${SOURCES_OT}$
	@cd ot; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS}  *.cpp 
	
clean:
	rm -rf ${OBJECTS_UTIL} ${OBJECTS_DST} ${OBJECTS_OT} dst.exe





#
# CMPSC443 - F18 Assignment #2
# Makefile - makefile for the NS protocol assignment
#

# Locations
CMPSC311_LIBDIR=.
                    
# Make environment
INCLUDES=-I. -I$(CMPSC311_LIBDIR)
CC=gcc
CFLAGS=-I. -c -g -Wall $(INCLUDES) -Wno-pointer-sign
LINKARGS=-g
LIBS=-lm -lcmpsc311mini -L. -L$(CMPSC311_LIBDIR) -lgcrypt -lcurl -pthread
                    
# Suffix rules
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS)  -o $@ $<
	
# Files
TARGETS=    cmpsc443_ns_client

CLIENT_OBJECT_FILES=	cmpsc443_ns_client.o \
						cmpsc443_ns_util.o

# Productions
all : $(TARGETS)

cmpsc443_ns_client: $(CLIENT_OBJECT_FILES)
	$(CC) $(LINKARGS) $(CLIENT_OBJECT_FILES) -o $@ $(LIBS)

clean : 
	rm -f $(TARGETS) $(CLIENT_OBJECT_FILES)
	

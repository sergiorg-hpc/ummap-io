
BUILDDIR = ../build
BINDIR   = $(BUILDDIR)/bin
INCDIR   = $(BUILDDIR)/include
LIBDIR   = $(BUILDDIR)/lib
OBJDIR   = $(BUILDDIR)/obj
LIBPATH  = $(LIBDIR)/libummapio.a
CLIBS    = -lummapio
CFLAGS   = -DDEBUG_PRINT=$(or $(DEBUG_PRINT),0) -O2 -I. -L$(LIBDIR)

ifeq (,$(findstring Cray,$(shell cc -V 2>&1)))
    CLIBS  += -pthread -lrt
    CFLAGS += -Wall -Wno-unused-label -Wno-unused-function -std=c99
endif

all: setup $(LIBPATH) $(BINDIR)/example.out

$(BINDIR)/example.out: $(LIBPATH) example/main.c
	$(CC) $(CFLAGS) example/main.c -o $(BINDIR)/example.out $(CLIBS)

$(LIBPATH): $(OBJDIR)/ummap.o $(OBJDIR)/ummap_util.o \
			$(OBJDIR)/ummap_policy.o $(OBJDIR)/futex.o
	ar -cq $(LIBPATH) $(OBJDIR)/*.o

$(OBJDIR)/ummap.o: ummap.* common.h
	$(CC) $(CFLAGS) -c ummap.c -o $(OBJDIR)/ummap.o

$(OBJDIR)/ummap_util.o: ummap_util.* common.h
	$(CC) $(CFLAGS) -c ummap_util.c -o $(OBJDIR)/ummap_util.o

$(OBJDIR)/ummap_policy.o: ummap_policy.* common.h
	$(CC) $(CFLAGS) -c ummap_policy.c -o $(OBJDIR)/ummap_policy.o

$(OBJDIR)/futex.o: futex.* common.h
	$(CC) $(CFLAGS) -c futex.c -o $(OBJDIR)/futex.o

setup:
	@mkdir -p $(BINDIR) $(INCDIR) $(LIBDIR) $(OBJDIR) 2> /dev/null
	@cp ummap.h $(INCDIR) 2> /dev/null

clean:
	@rm -rf $(BUILDDIR)

rebuild: clean all


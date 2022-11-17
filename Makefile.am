bin_PROGRAMS = sse-server
noinst_PROGRAMS = cexport
man_MANS = sse-server.1
EXTRA_DIST = config.rpath $(man_MANS) export.h cexport.1 $(TESTS)
doc_DATA = COPYING
EXPORTS = connectsock.e logger.e memmem.e
BUILT_SOURCES = $(EXPORTS)
sse_server_SOURCES = sse-server.c connectsock.c logger.c memmem.c
cexport_SOURCES = cexport.c
LDADD = -lssl -lcrypto
SUFFIX = .c:sC .l:sC .y:sC .e:h .h:h
SUFFIXES = .1 .e .html

$(EXPORTS): $(cexport_SOURCES)

.c.e:
	$(MAKE) cexport
	$(top_builddir)/cexport -I. -I$(srcdir) $(CPPFLAGS) -c "@CPP@" <$< >$@

TESTS =

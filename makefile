PROC=wwcd
ADDITIONAL_LIBS= $(L)libcapstone$(A)
__CFLAGS=-std=gnu++11
include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)wwcd$(O)     : $(I)range.hpp $(I)bitrange.hpp $(I)bytes.hpp $(I)fpro.h     \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp wwcd.cpp

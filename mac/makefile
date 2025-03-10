IGNORED_FILES := $(shell test -f .makeignore && grep -v '^#' .makeignore || echo "")

CERTIFICATE	?= 
ifeq ($(strip $(CERTIFICATE)),)
$(error ❌ Please set the environment variable CERTIFICATE before running make. Example: export CERTIFICATE=your-cert-name)
endif

PREFIX		= $(CERTIFICATE).remote-action.macos.
CODESIGN	= codesign
CODESIGNFLAGS	= --timestamp --force
TAR		= tar
TARFLAGS	= zcvf

ALL_FILES       = $(wildcard *.sh)
FILES_TO_PROCESS = $(filter-out $(IGNORED_FILES), $(ALL_FILES))
REMOTE_ACTIONS  = $(FILES_TO_PROCESS:%.sh=%.sh.tar.gz)

#files		= $(wildcard *.sh)
#remote_actions	= $(files:%.sh=%.sh.tar.gz)

#ALL:		$(remote_actions)
ALL:		$(REMOTE_ACTIONS)

%.sh.tar.gz:	%.sh
	$(CODESIGN) -s $(CERTIFICATE) --prefix=$(PREFIX) $(CODESIGNFLAGS) $<
	$(TAR) $(TARFLAGS) $@ $< 
	@echo $@:  "\033[0;31mSigned with G2\033[0m"
	@echo


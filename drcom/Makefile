TOPSRCDIR = $(shell pwd)
DESTDIR = /usr/local/bin/

export TOPSRCDIR DESTDIR

#SUBDIRS = drcomc drcomd kmod 

.PHONY: all clean install

all: drcom.h drcom.c md5.h md5.c main.c
#	@for x in $(SUBDIRS); do (cd $$x && make all) || exit 1; done
	gcc drcom.h drcom.c main.c md5.h md5.c -o drcom

clean:
#	@for x in $(SUBDIRS); do (cd $$x && make clean) || exit 1; done
    @if [ -f /etc/drcom.conf ]; then \
	    rm -f /etc/drcom.conf
	fi
	@if [ -f /usr/local/bin/drcom ]; then \
	    rm -f /usr/local/bin/drcom
	fi

install:
#	@for x in $(SUBDIRS); do (cd $$x && make install) || exit 1; done
	@echo
	@echo
	@echo
	@if [ -f /etc/drcom.conf ]; then \
		echo "====================================" && \
		echo "" && \
		echo "/etc/drcom.conf exists.";\
		echo "" && \
		echo "You May Need to Edit /etc/drcom.conf" && \
		echo "" && \
		echo "====================================" \
		;\
	else\
		install -m 600 drcom.conf /etc/drcom.conf && \
		echo "====================================" && \
		echo "" && \
		echo "Do Not Forget To Edit /etc/drcom.conf" && \
		echo "" && \
		echo "====================================" \
		;\
	fi
	@echo
	@install -m 755 drcom $(DESTDIR)


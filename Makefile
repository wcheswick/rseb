LOCAL_SBIN=/usr/local/sbin
LOCAL_MAN=/usr/local/man/man8
LOCAL_RC=/usr/local/etc/rc.d

CFLAGS+=-g -static -Wall -pedantic -Wno-comment -O0

OBJS=main.o debug.o db.o util.o # proto.o

all::	rseb

rseb:	${OBJS}
	${CC} ${CFLAGS} ${OBJS} -lpcap -o rseb

main.o debug.o:	rseb.h


install::	${LOCAL_SBIN}/rseb ${LOCAL_MAN}/rseb.8 ${LOCAL_RC}/rseb

${LOCAL_SBIN}/rseb:	rseb
	sudo install -m 0755 -o root -g wheel rseb ${LOCAL_SBIN}

${LOCAL_MAN}/rseb.8:	rseb.8
	sudo cp rseb ${LOCAL_MAN}/rseb.8

${LOCAL_RC}/rseb:	rseb.rc
	sudo install -m 0755 -o root -g wheel rseb.rc ${LOCAL_RC}/rseb
	@echo
	@echo "On the server, add to /etc/rc.conf:"
	@echo 'rseb_enable="YES"'
	@echo

clean::
	rm -f *.o rseb *.core


test::	rseb
#	sudo ./rseb -d -d -D
	sudo ./rseb -d -e tunnel-garage.local	# client test

#	sudo ./rseb -d -d fd72:6574:6e65:7466::20
#	sudo ./rseb -d		# discover interface
#	-sudo ./rseb -d toad fd72:6574:6e65:7466::4 5001
#	echo
#	-sudo ./rseb -d - ferd
#	-sudo ./rseb -d - localhost 67000

push::
	rsync -a ../rseb/*.[hc] ../rseb/Makefile ../rseb/rseb.rc garage:src/rseb
	ssh garage "cd src/rseb; make clean install"

pushtest:	test
	rsync -a ../rseb/*.[hc] garage:src/rseb
	ssh garage "cd src/rseb; make clean test"

servertest::
	/usr/local/sbin/rseb -d -s -l

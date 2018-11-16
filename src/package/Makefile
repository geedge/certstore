SUBDIRS := cert  certstore  conf  r2_certstore  r3_certstore  rule  tool

install:
#	if [ ! -d "/usr/local/bin" ]; then mkdir -p "/usr/local/bin"; fi
#	if [ ! -d "/usr/local/lib" ]; then mkdir -p "/usr/local/lib"; fi
#
#	cp -f etc/cert_store.ini 	  /usr/local/etc/
#
#	cp -f bin/cert_store /usr/local/bin/
#	chmod +x certstore1.0
#
#	cp -f lib/*  /usr/local/lib/
#	sudo ldconfig
	if [ ! -d "/home/ceiec/certstore" ]; then mkdir -p "/home/ceiec/certstore"; fi
	
	chmod +x certstore r2_certstore r3_certstore
	chmod +x tool/signssl.sh  tool/x509

	for d in $(SUBDIRS); do \
	cp -rf $$d /home/ceiec/certstore; \
	done 

update:
	chmod +x certstore
	cp -f certstore /home/ceiec/certstore

#	cp -f bin/cert_server /usr/local/bin/

uninstall:
	rm -rf /home/ceiec/certstore



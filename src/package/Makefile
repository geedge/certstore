
install:
	if [ ! -d "/usr/local/bin" ]; then mkdir -p "/usr/local/bin"; fi
	if [ ! -d "/usr/local/lib" ]; then mkdir -p "/usr/local/lib"; fi
#
	cp -f etc/cert_store.yaml  	  /usr/local/etc/
#
	cp -f bin/cert_store /usr/local/bin/
	chmod +x /usr/local/bin/cert_store
#
	cp -f lib/*  /usr/local/lib/
	sudo ldconfig
update:
	cp -f bin/cert_server /usr/local/bin/
	chmod +x /usr/local/bin/cert_store

uninstall:
	rm -f  /usr/local/bin/cert_store
	rm -rf /usr/local/etc/cert_store.yaml  



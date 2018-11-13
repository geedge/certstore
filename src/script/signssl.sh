#!/bin/bash

type_name=$1
name=$2

caform=$3
caname=$4

cakeyform=$5
cakey=$6

do_help()
{
	echo "./signssl -type cert_name -cafrom ca_name -cakeyfrom key_name"
	echo "usage: ./signssl args"
	echo "  -type cert_name 	  - input type     (-middle, -entity)"
	echo "  -cafrom ca_name     - input ca_name  (root certificate)"
	echo "  -cakeyfrom key_name - input key_name (the root keys)"
	exit
}

do_mkdir()
{
	if [ ! -d "./demoCA" ]; then
		mkdir demoCA
        mkdir ./demoCA/newcerts
        touch ./demoCA/index.txt
        touch ./demoCA/serial
        echo 0001 >> ./demoCA/serial
    fi
}

do_check()
{
	if [ "$type_name" == "" ]||[ "$name" == "" ]; then
		echo "certificate type is unkone!"
		do_help
		exit
    fi
	if [ "$caform" != "-cafrom" ] || [ "$caname" == "" ]; then
		echo "root certificate name is unkone!"
		do_help
		exit
    fi
	if [ "$cakeyform" != "-cakeyfrom" ] || [ "$cakey" == "" ]; then
		echo "root certificate keys is unkone!"
		do_help
		exit
    fi
}

do_middle()
{
	if [ ! -d "./middle" ]; then
		mkdir middle
    fi
	openssl genrsa -out ${name}.key 1024
	openssl req -new -key ${name}.key -out ${name}.csr
	openssl ca -extensions v3_ca -in ${name}.csr -out ${name}.pem -cert ${caname} -keyfile ${cakey} -days 365 -policy policy_anything
	openssl pkcs12 -export -in ${name}.pem -inkey ${name}.key -chain -CAfile ${caname} -out ${name}.p12
    mv ${name}.*  middle
}

do_entity()
{
	if [ ! -d ".entity" ];then
		mkdir entity
	fi
	openssl genrsa -out ${name}.pem 1024
	openssl rsa -in ${name}.pem -out ${name}.key
	openssl req -new -key ${name}.pem -out ${name}.csr 
	openssl x509 -req -days 365 -sha256 -extfile /etc/pki/tls/openssl.cnf -extensions v3_req -CA ${caname} -CAkey ${cakey} -CAserial ca.srl -CAcreateserial -in ${name}.csr -out ${name}.cer
	
	openssl pkcs12 -export -in ${name}.cer -inkey ${name}.key -chain -CAfile ${caname} -out ${name}.p12
	
	mv ${name}.*  entity
}

do_signssl()
{
	if [ "$type_name" == "-middle" ]; then
		do_middle
		exit
    fi
	if [ "$type_name" == "-entity" ]; then
		do_entity
		exit
    fi
}

do_check 
do_mkdir
do_signssl


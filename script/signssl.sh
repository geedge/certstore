#!/bin/bash

type_name=$1
name=$2

if [ "${type_name}" == "-caroot" ]; then
    csrfrom=$3
    csrname=$4
    csrkey=$5
else
    cafrom=$3
    caname=$4
    cakey=$5

    csrfrom=$6
    csrname=$7
    csrkey=$8
fi

san_nam=$9

trap "do_signal" 2
do_signal()
{
    echo "\n"
    read -p "Terminate theprocess? (y/n): " input
}

do_clear()
{
	if [ -d "./demoCA" ]; then
        rm -rf ./demoCA
    fi

    if [ $1 -ne 0 ];then
	    if [ -d "./ca-middle/$2" ]; then
            rm -rf ./ca-middle/$2
        fi
	    if [ -d "./entity/$2" ]; then
            rm -rf ./entity/$2
        fi
	    if [ -d "./caroot/$2" ]; then
            rm -rf ./caroot/$2
        fi
        if [ -d "./csr/$2" ]; then
            rm -rf ./csr/$2
        fi
        exit
    fi
}

do_help()
{
    echo ""
    echo "./signssl -type cert_name -cafrom ca_name key_name -csr csr_name csr_key -san san_nam"
    echo "usage: ./signssl args"
    echo "  -type                       - input type      "-csr -caroot -camiddle -entity""
    echo "  cert_name                   - input cert_name "input output cert namae""
    echo "  -cafrom ca_name keyname     - input ca_name keyname "input the root cert name and key""
    echo "  -csrfrom csr_name csr_key   - input csr_name csr_key "input cert signs request file name and key"" 
    echo "  san_name                    - input san_name  "When it is an entity cert, input user alternate name""
    echo ""
    echo "exanple -csr"
    echo "./signssl.sh -csr csr_name"
    echo "example -caroot"
    echo "./signssl.sh -caroot root_name"
    echo "example -camiddle"
    echo "./signssl.sh -camiddle middle_name -cafrom ../cert/mesalab-ca-cert.cer ../cert/mesalab-ca-cert.key -csrfrom ./csr/csrname/csrname.csr ./csr/csrname/csrname.key"
    echo "exaple -entity"
    echo "./signssl.sh -entity entity_name -cafrom ../cert/mesalab-ca-cert.cer ../cert/mesalab-ca-cert.key -csrfrom ./csr/csrname/csrname.csr ./csr/csrname/csrname.key  163"
    echo ""
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
        echo "cert type is unkone!"
		do_help
		exit
    fi
    
    if [ "$type_name" == "-csr" ]; then
        return
    fi

    if [ "$type_name" == "-caroot" ]; then
        return
    fi


    if [ "$csrfrom" == "" ] || [ "$csrname" == "" ] || [ "$csrkey" == "" ]; then
        echo "input input cert signs request file name and key"
        do_help
        exit
    fi
 
    if [ "$cafrom" == "" ] || [ "$caname" == "" ] || [ "$cakey" == "" ]; then
		echo "input certificate name or key is unkone!"
		do_help
		exit
    fi
    
    if [ "$type_name" == "-entity" ];then
        if [ "$san_nam" == "" ];then
            echo "Please enter the san name!"
            do_help
            exit
        fi

    fi
}

do_middle()
{
	if [ ! -d "./ca-middle/${name}" ]; then
		mkdir -p  ca-middle/${name}
    fi
    outpath=ca-middle/${name}

	openssl ca -extensions v3_ca -in ${csrname} -out ${outpath}/${name}.cer -cert ${caname} -keyfile ${cakey} -days 365 -policy policy_anything
	openssl pkcs12 -export -in ${outpath}/${name}.cer -inkey ${csrkey} -chain -CAfile ${caname} -out ${outpath}/${name}.p12

    do_clear $? ${name} 
    cp ${csrkey} ${outpath}
}

do_entity()
{
	if [ ! -d "./entity/${name}" ];then
		mkdir -p  entity/${name}
	fi
    outpath=entity/${name}
    
    openssl ca -in ${csrname} -keyfile ${cakey} -cert ${caname} -extensions SAN -config <(cat /etc/pki/tls/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:*.${san_nam}.com,DNS:*.${san_nam}.cn")) -out ${outpath}/${name}.cer
    
    openssl pkcs12 -export -in ${outpath}/${name}.cer -inkey ${csrkey} -chain -CAfile ${caname} -out ${outpath}/${name}.p12
    
    do_clear $? ${name} 
    cp ${csrkey} ${outpath}
}

do_caroot()
{
	if [ ! -d ".caroot/${name}" ];then
		mkdir -p caroot/${name}
	fi
    outpath=caroot/${name}

	openssl genrsa -out  ${outpath}/${name}.key 1024   
    openssl req -new -key ${outpath}/${name}.key -out ${outpath}/${name}.csr 
    openssl x509 -req -days 365 -sha256 -extfile /etc/pki/tls/openssl.cnf -extensions v3_ca -signkey ${outpath}/${name}.key -in ${outpath}/${name}.csr -out ${outpath}/${name}.cer
    #openssl req -new -x509 -key ca.key -out ca.crt 
    do_clear $? ${name} 
}

do_csr()
{
    if [ ! -d "./csr/${name}" ];then
        mkdir -p csr/${name}
    fi
    outpath=csr/${name}

	openssl genrsa -out  ${outpath}/${name}.key 1024
	openssl req -new -key ${outpath}/${name}.key -out ${outpath}/${name}.csr
    do_clear $? ${name}
}

do_signssl()
{
	if [ "$type_name" == "-camiddle" ]; then
		do_middle
		exit
    fi
	if [ "$type_name" == "-entity" ]; then
		do_entity
		exit
    fi
	if [ "$type_name" == "-caroot" ]; then
		do_caroot
		exit
    fi
	if [ "$type_name" == "-csr" ]; then
        do_csr
        exit
    fi
    echo "unknow command"
}

do_check 
do_mkdir
do_signssl


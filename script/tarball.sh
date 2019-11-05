X=certstore-base
#X=certstore

typeset -l version
version=`lsb_release -i -s`
version_id=`lsb_release -r -s`
machine=`uname -m`
issue_date=`date "+%Y%m%d"`

tarball="$X-$2-$version$version_id-$machine-$issue_date".tar.gz

do_mkdir(){
    if [ ! -d "../package" ]; then
        mkdir ../package
    fi
    cd ../package
    rm $X -rf
    mkdir $X
    mkdir $X/cert
    mkdir $X/tool
}

do_copy(){
    cp ../resource/conf/ $X -rf
    cp ../resource/cert/* $X/cert
    #cp ../rule/ $X -rf
    cp ../build/program/certstore $X/certstore
    cp ../resource/package/* $X
    cp ../script/signssl.sh $X/tool
    cp ../script/x509 $X/tool   
}

do_tarball(){
    tar -zcvf $1 $X
    rm $X -rf
    echo "`date`  BUILD=$X  COMMIT=$2 ARCHIVE=$tarball" >> release.log
}

do_mkdir
do_copy $1
do_tarball $tarball

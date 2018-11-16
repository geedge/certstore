#X=CertStore-Base-$2
X=certstore

typeset -l version
version=`lsb_release -i -s`
version_id=`lsb_release -r -s`
machine=`uname -m`
issue_date=`date "+%Y%m%d"`

tarball="$X-$3-$version$version_id-$machine-$issue_date".tar.gz

do_mkdir(){
    cd ../release
    rm $X -rf
    mkdir $X
    mkdir $X/cert
    mkdir $X/tool
}

do_copy(){
    cp ../conf/ $X -rf
    cp ../ca/* $X/cert
    cp ../rule/ $X -rf
    cp ../src/cert_store $X/certstore
    cp ../src/package/* $X
    cp ../src/script/signssl.sh $X/tool
    cp ../src/script/x509 $X/tool   
}

do_tarball(){
    tar -zcvf $1 $X
    rm $X -rf
    echo "`date`  BUILD=$X  COMMIT=$3 ARCHIVE=$tarball" >> release.log
}

do_mkdir
do_copy $1
do_tarball $tarball


#!/usr/bin/env sh
set -evx

chmod +x ci/get-nprocessors.sh
. ci/get-nprocessors.sh

# if possible, ask for the precise number of processors,
# otherwise take 2 processors as reasonable default; see
# https://docs.travis-ci.com/user/speeding-up-the-build/#Makefile-optimization
if [ -x /usr/bin/getconf ]; then
    NPROCESSORS=$(/usr/bin/getconf _NPROCESSORS_ONLN)
else
    NPROCESSORS=2
fi

# as of 2017-09-04 Travis CI reports 32 processors, but GCC build
# crashes if parallelized too much (maybe memory consumption problem),
# so limit to 4 processors for the time being.
if [ $NPROCESSORS -gt 4 ] ; then
	echo "$0:Note: Limiting processors to use by make from $NPROCESSORS to 4."
	NPROCESSORS=4
fi

# Tell make to use the processors. No preceding '-' required.
MAKEFLAGS="j${NPROCESSORS}"
export MAKEFLAGS

env | sort

# Set default values to OFF for these variables if not specified.
: "${NO_EXCEPTION:=OFF}"
: "${NO_RTTI:=OFF}"
: "${COMPILER_IS_GNUCXX:=OFF}"

# Install dependency from YUM
yum install -y mrzcpd framework numactl-devel zlib-devel librdkafka-devel systemd-devel
mkdir build || true
cd build

cmake3 -DCMAKE_CXX_FLAGS=$CXX_FLAGS \
      -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
      -DTFE_VERSION_DAILY_BUILD=$TESTING_VERSION_BUILD \
      ..

make
#make test

if [ -n "${PACKAGE}" ]; then
	make package
	#cp ~/rpm_upload_tools.py ./
	#python3 rpm_upload_tools.py ${PULP3_REPO_NAME} ${PULP3_DIST_NAME} *.rpm
fi

if [ -n "${UPLOAD_SYMBOL_FILES}" ]; then
  rpm -i certstore*debuginfo*.rpm
  #cp /usr/lib/debug/opt/tsg/tfe/bin/tfe.debug /tmp/tfe.debuginfo.${CI_COMMIT_SHORT_SHA}
  #sentry-cli upload-dif -t elf /tmp/tfe.debuginfo.${CI_COMMIT_SHORT_SHA}
fi

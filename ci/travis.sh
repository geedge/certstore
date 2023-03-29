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

yum install -y libcjson-devel libmaat4-devel libMESA_field_stat2-devel libMESA_handle_logger-devel libbreakpad_mini-devel.x86_64
yum install -y libMESA_prof_load-devel libwiredcfg-devel libWiredLB-devel

mkdir build || true
cd build

cmake3 -DCMAKE_CXX_FLAGS=$CXX_FLAGS \
      -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
      -DENABLE_DEVEL=$ENABLE_DEVEL_SWITCH \
      ..

make

if [ -n "${PACKAGE}" ]; then
	make package
fi

if [ -n "${UPLOAD}" ]; then	
	cp ~/rpm_upload_tools.py ./
	python3 rpm_upload_tools.py ${PULP3_REPO_NAME} ${PULP3_DIST_NAME} *.rpm
	
	rpm -i $SYMBOL_TARGET*debuginfo*.rpm
	_symbol_file=`find /usr/lib/debug/ -name "$SYMBOL_TARGET*.debug"`
	cp $_symbol_file ${_symbol_file}info.${CI_COMMIT_SHORT_SHA}
	sentry-cli upload-dif -t elf ${_symbol_file}info.${CI_COMMIT_SHORT_SHA}
fi

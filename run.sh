#!/bin/bash
. /opt/safenet/protecttoolkit7/cprt/setvars.sh
export CLASSPATH=.:$PTKLIB/jcprov.jar

# LD_LIBRARY_PATH is set by setvars.sh
# Example Usage:
# ./run.sh -q -v -p 1111 -s 0 -kl k01 -dl test_dek_01_final -f dek.bin

java -cp $CLASSPATH -Djava.library.path=$PTKLIB StoreDekData "$@"

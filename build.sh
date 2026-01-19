#!/bin/bash
. /opt/safenet/protecttoolkit7/cprt/setvars.sh
export CLASSPATH=.:$PTKLIB/jcprov.jar

javac -cp $CLASSPATH StoreDekData.java
if [ $? -eq 0 ]; then
    echo "Compilation Successful."
    echo "Run with: ./run.sh"
else
    echo "Compilation Failed."
fi

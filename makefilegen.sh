#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DSOCKET_QUEUE=1"
    echo "LDFLAGS+=-lmceliece -lrandombytes"
    echo 

    # binaries
    i=0
    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        if [ $i -eq 0 ]; then
          echo "BINARIES=${x}"
        else
          echo "BINARIES+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    echo "all: \$(BINARIES)"
    echo 

    for file in `ls *.c`; do
      (
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done

    i=0
    for file in `ls *.c`; do
      if ! grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$/.o/'`
        if [ $i -eq 0 ]; then
          echo "OBJECTS=${x}"
        else
          echo "OBJECTS+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o \$(OBJECTS)"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS)"
        echo 
      fi
    done
    echo

    echo "test: all"
    echo "	sh pok-test.sh"
    echo 

    echo "clean:"
    echo "	rm -f *.o \$(BINARIES)"
    echo 

  ) > Makefile
)

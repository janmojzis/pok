#!/bin/sh

PATH="./:${PATH}"
export PATH

# change directory to $AUTOPKGTEST_TMP
cd "$AUTOPKGTEST_TMP"

# create server key directory
mkdir -p serverkeydir/server/

# create random datafile
dd if=/dev/urandom of=data.in bs=1 count=1M 2>/dev/null

# run server
pok-server -cvv -k serverkeydir 0.0.0.0 10000 cat data.in 2>server.log &
serverpid=$!

sleep 1

cleanup() {
  ex=$?
  # kill server
  kill -TERM "${serverpid}" 1>/dev/null 2>/dev/null || :
  sleep 1
  kill -KILL "${serverpid}" 1>/dev/null 2>/dev/null || :
  echo "=== server.log: ==="
  cat server.log
  rm -rf server.log client.log serverkeydir data.in data.out
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

#for mceliecelong in mceliece6688128 mceliece8192128 mceliece6960119 mceliece460896 mceliece348864; do
for mceliecelong in mceliece6688128 mceliece8192128; do
  # create server key
  rm -rf serverkeydir/server/public
  rm -rf serverkeydir/server/secret
  pok-makekey -fm "${mceliecelong}" serverkeydir

  # copy public-key to client
  mkdir -p clientkeydir/client/127.0.0.1/remote
  rm -f clientkeydir/client/127.0.0.1/remote/*
  rsync -a serverkeydir/server/public/* clientkeydir/client/127.0.0.1/remote/

  #for mcelieceshort in mceliece6688128 mceliece8192128 mceliece6960119 mceliece460896 mceliece348864; do
  for mcelieceshort in mceliece6688128 mceliece8192128; do
    # client
    rm -f data.out
    pok-client -cvv -m "${mcelieceshort}" -k clientkeydir 127.0.0.1 10000 sh -c 'cat > data.out' 2>client.log

    if [ x"`shasum < data.in`" != x"`shasum < data.out`" ]; then
      echo "=== long ${mceliecelong}: short ${mcelieceshort}: failed ==="
      cat client.log
      echo
      exit 111
    fi
    echo "=== long ${mceliecelong}: short ${mcelieceshort}: OK ==="
    cat client.log
    echo
  done
done
exit 0

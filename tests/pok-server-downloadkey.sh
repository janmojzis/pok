#!/bin/sh
exec 2>&1

(
  exec 2>&1
  ./pok-makekey -v pok-server-downloadkey-keydir
) | sed 's/{.*}$//'

./pok-server -vvvk pok-server-downloadkey-keydir 127.0.0.1 12345 cat 2> pok-server-downloadkey.log &

pid=$!
sleep 1

cleanup() {
  # cleanup
  rm -rf pok-server-downloadkey-keydir  pok-server-downloadkey.log
  #kill pok-server
  kill -TERM "${pid}" 1>/dev/null 2>/dev/null || :
  sleep 0.1
  kill -KILL "${pid}" 1>/dev/null 2>/dev/null || :
}
trap "cleanup" EXIT TERM INT

echo 3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa
./pok-server-downloadkey.py 127.0.0.1 12345 3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa
echo $?

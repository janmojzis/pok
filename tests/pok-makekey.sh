#!/bin/sh
exec 2>&1

cleanup() {
  # cleanup
  rm -rf keydir
}
trap "cleanup" EXIT TERM INT

pok_makekey() {
  echo "pok-makekey $@"
  ./pok-makekey $@
  echo $?
  echo
}

(
exec 2>&1

# usage
pok_makekey

# unable to create directory 'keydir'
rm -rf keydir
mkdir keydir
pok_makekey keydir

# unable to create directory 'keydir'
rm -rf keydir
touch keydir
pok_makekey -f keydir

# unable to make directory 'keydir/public'
rm -rf keydir
mkdir -p keydir
touch keydir/public
pok_makekey -f keydir

# unable to create file 'keydir/public/3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa'
rm -rf keydir
mkdir -p keydir/public/3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa
pok_makekey -f keydir

# unable to make directory 'keydir/secret'
rm -rf keydir
mkdir -p keydir
touch keydir/secret
pok_makekey -f keydir

# unable to create file 'keydir/secret/3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa'
rm -rf keydir
mkdir -p keydir/secret/3112a32c7de663bf09bc7a73ade7a662b1b8f22df7fbbf50a1eaa2dd814870fa
pok_makekey -f keydir

# ok
rm -rf keydir
pok_makekey -v keydir
pok_makekey -vf keydir

) | sed 's/{.*}$//'

exit 0

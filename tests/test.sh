#!/bin/sh

ls *.sh | sort | while read script
do
  name=`echo "${script}" | sed 's/.sh$//'`
  [ -f "${name}.exp" ] || continue
  sh "${script}" > "${name}.out"
  diff -Nur "${name}.exp" "${name}.out" && echo "${name} ok" || echo "${name}" failed
done

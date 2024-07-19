## to protect SSH connection
- run SSH server (tinysshd)
~~~bash
[ -d /etc/tinyssh/pokkeydir ] || /usr/bin/pok-makekey /etc/tinyssh/pokkeydir
[ -d /etc/tinyssh/sshkeydir ] || /usr/sbin/tinysshd-makekey /etc/tinyssh/sshkeydir
pok-server -k /etc/tinyssh/pokkeydir 0.0.0.0 22 /usr/sbin/tinysshd -v /etc/tinyssh/sshkeydir &
~~~

- update ssh client config '~/.ssh/config':
~~~
Host _YOUR_HOST_
ProxyCommand pok-client -k ~/.ssh/pokkeydir %h %p
~~~

- copy public-key from the servers /etc/tinyssh/pokkeydir/... to local ~/.ssh/pokkeydir/...
~~~
mkdir -p ~/.ssh/pokkeydir/client/_YOUR_HOST_/remote/
rsync -a _YOUR_HOST_:/etc/tinyssh/pokkeydir/server/public/* ~/.ssh/pokkeydir/client/_YOUR_HOST_/remote/
~~~

- try SSH connection
~~~
ssh _YOUR_HOST_
~~~

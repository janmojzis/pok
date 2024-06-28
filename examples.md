## to protect SSH connection
- ssh client config '~/.ssh/config':
~~~
Host your.host.com
ProxyCommand pok-client -k ~/.ssh/pokkeydir %h %p
~~~

- run SSH server (tinysshd)
~~~bash
[ -d /etc/tinyssh/pokkeydir ] || /usr/bin/pok-makekey /etc/tinyssh/pokkeydir
[ -d /etc/tinyssh/sshkeydir ] || /usr/sbin/tinysshd-makekey /etc/tinyssh/sshkeydir
pok-server -k /etc/tinyssh/pokkeydir 0.0.0.0 22 /usr/sbin/tinysshd -v /etc/tinyssh/sshkeydir &
~~~

# dnstt

Userspace DNS tunnel RoundTripper based on [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield.

## DNS zone setup

Because the server side of the tunnel acts like an authoritative name
server, you need to own a domain name and set up a subdomain for the
tunnel. Let's say your domain name is example.com and your server's IP
addresses are 203.0.113.2 and 2001:db8::2. Go to your name registrar and
add three new records:

```
A	tns.example.com	points to 203.0.113.2
AAAA	tns.example.com	points to 2001:db8::2
NS	t.example.com	is managed by tns.example.com
```

The labels `tns` and `t` can be anything you want, but the `tns` label
should not be a subdomain of the `t` label (that space is reserved for
the contents of the tunnel), and the `t` label should be short (because
there is limited space available in a DNS message, and the domain name
takes up part of that space).

Now, when a recursive DNS resolver receives a query for a name like
aaaa.t.example.com, it will forward the query to the tunnel server at
203.0.113.2 or 2001:db8::2.


## Tunnel server setup

Compile the server:
```
tunnel-server$ cd dnstt-server
tunnel-server$ go build
```

First you need to generate the server keypair that will be used to
authenticate the server and encrypt the tunnel.
```
tunnel-server$ ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
privkey written to server.key
pubkey  written to server.pub
```

Run the server. You need to provide an address that will listen for UDP
DNS packets (`:5300`), the private key file (`server.key`), the root of
the DNS zone (`t.example.com`), and a TCP address to which incoming
tunnel streams will be forwarded (`127.0.0.1:8000`).
```
tunnel-server$ ./dnstt-server -udp :5300 -privkey-file server.key t.example.com 127.0.0.1:8000
```

The tunnel server needs to be able to receive packets on an external
port 53. You can have it listen on port 53 directly using `-udp :53`,
but that requires the program to run as root. It is better to run the
program as an ordinary user and have it listen on an unprivileged port
(`:5300` above), and port-forward port 53 to it. On Linux, use these
commands to forward external port 53 to localhost port 5300:
```
tunnel-server$ sudo iptables -I INPUT -p udp --dport 5300 -j ACCEPT
tunnel-server$ sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
tunnel-server$ sudo ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT
tunnel-server$ sudo ip6tables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
```

You need to also run something for the tunnel server to connect to. It
can be a proxy server or anything else. For testing, you can use an
Ncat listener:
```
tunnel-server$ ncat -l -k -v 127.0.0.1 8000
```

## TODO

Modify the server component to add iptables rules and run as its own proxy

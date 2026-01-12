# dnstt

Userspace DNS tunnel RoundTripper based on [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield. 
As with David's DNSTT, this repository is all contributed to the public domain.

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


## Tunnel server

### Usage

```sh
dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
dnstt-server -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN
```

### Compile the server

```sh
dnstt$ cd server
dnstt$ go build -o dnstt-server
```

### Key Generation

First you need to generate the server keypair that will be used to
authenticate the server and encrypt the tunnel.
```sh
dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
```

### Running the Server

You need to provide an address that will listen for UDP
DNS packets (`:5300`), the private key file (`server.key`), and the root of
the DNS zone (`t.example.com`)
```sh
dnstt-server -udp :5300 -privkey-file server.key t.example.com
```

The tunnel server needs to be able to receive packets on an external
port 53. If it is not configured to listen on port 53 directly using 
`-udp :53`, it will automatically setup iptables rules to port-forward
port 53 to it.

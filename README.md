# PF_PACKET Socket Receive Packet Steering

When you are running heavy loaded networking application you need to rely on high performances software design to distribute the load. In late 2009, Tom Herbert makes it happen by introducing software Receive Packet Steering (RPS) to distribute load across multiple processors. In 2010, he introduced Receive Flow Steering (RFS) for distributing load at socket layer. Finally in 2013, he introduced SO_REUSEPORT socket option to fully benefit RFS for UDP & TCP sockets.

Concretely, modern Linux networking applications are spawning multiple pthread, potentially bound to a specific CPU, and create AF_INET(6) UDP or TCP protocol listener via socket API. Using SO_REUSEPORT socket option one pthread is able to listen on a UDP or TCP port on which another socket is already bound to. This simple syscall enable access to ingress packet distributed load.

Unfortunately this nice design is not available for PF_PACKET sockets, simply because RFS is hashing layer3+layer4 headers elements to steer packet across AF_INET(6) sockets. PF_SOCKET are low-level hook in Linux kernel mainly used for applications like tcpdump to watch traffic. When an application create multiple sockets via _socket(PF_PACKET, SOCK_RAW, proto)_ then each socket will receive a copy of every packets matching _proto_. This built-in feature enable you to run multiple tcpdump on the same host, and then application need to filter out unrelated traffic. This is where BPF took place, providing a set of instructions to create filter to attach to the socket to only grab pieces of interest.

Considering a layer2 application like an ethernet access-concentrator (BNG) or any other application on top of layer2. One simple design could be to create a PF_PACKET socket and re-distribute incoming packets across multiple pthread. This design introduce the need for synchronisation to feed each pthread processing queue which increase complexity of the application and create a bottleneck at this single ingress socket.

The proposed design here is an attempt to simplify application code and use the same design as RPS/RFS but for PF_PACKET socket to increase perfomances. An ethernet layer2 application will be offered as a PoC. Application will simply create multiple PF_PACKET sockets and process packet without any synchronisation needed by attaching an eBPF program filtering packet based on hashing ethernet source address.

This is a PoC code as an experiment candidate to be integrated into GTP-Guard.

## Network topology

Proposed application will apply to following topology built with qemu :

```
    -----------+-----------------------+----------------------
               | eno1                  | enp1s0
               | (MAC: ramdom)         | (MAC: 52:54:00:84:d7:ff)
          +----+-----+              +--+---+
          | injector |              | node |
          +----------+              +------+
```

## Building

3 directories are available :

	* inject/  : inject application
	* src/     : bpf_pfpacket_rps application
	* src/bpf/ : bpf_rps.bpf eBPF program

To build application run :

	$ git clone --recursive git@github.com:acassen/bpf_pfpacket_rps.git
	$ cd bpf_pfpacket_rps
	$ make
	$ ls bin/
	bpf_pfpacket_rps  bpf_rps.bpf  inject
	$

_injector_ will run `inject` and _node_ will run `bpf_pfpacket_rps + bpf_rps.bpf`

## Application discussion : _injector_

This application is forging simple PPPoE packets. It uses source ethernet address as specified via command line and destination ethernet address is built randomly.

## Application discussion : _bpf_pfpacket_rps_

This application spawn n pthread worker. Each worker creates one PF_PACKET socket and attach `bpf_rps.bpf` program to it. Each worker have its own uniq id, monotonically incremented. `bpf_rps.bpf` is exposing a _BPF_MAP_TYPE_ARRAY_ used as local options set by worker to identify its id, max_number_of_worker & hash_algo. This eBPF program will then perform a hash over ingress packet ethernet source address which will lead to PASSING or DROPING the packet according to local id match.

## Give it a try : _injector_ side
```
$ ./inject -h
Usage: ./inject [OPTION...]
-i, --bind-interface 	Interface to bind to
-d, --dest-mac	 	Destination MAC Address
-p, --pkt-count	 	Number of packet to send
-h, --help		Display this help message
$ sudo ./inject -i eno1 -d 52:54:00:84:d7:ff -p 25000
```
It will send out 25000 PPP packets over eno1 interface to remote ethernet address 52:54:00:84:d7:ff with randomly generated ethernet source address

## Give it a try : _node_ side
```
$ ./bpf_pfpacket_rps -h
Usage: ./bpf_pfpacket_rps [OPTION...]
  -i, --bind-interface		Interface to bind to
  -w, --worker-count		Number of thread workers
  -a, --hash-alg		0:mac_hash 1:mac_jhash 2:jhash_oaat
  -b, --ebpf-rps		eBPF RPS program
  -h, --help			Display this help message
$ sudo ./bpf_pfpacket_rps -i enp1s0 -b ./bpf_rps.bpf -w 8
#0:0000 #1:0000 #2:0000 #3:0000 #4:0000 #5:0000 #6:0000 #7:0000 (total:0 std_dev:0.000000)
#0:0000 #1:0000 #2:0000 #3:0000 #4:0000 #5:0000 #6:0000 #7:0000 (total:0 std_dev:0.000000)
#0:0232 #1:0237 #2:0262 #3:0246 #4:0230 #5:0233 #6:0236 #7:0246 (total:1922 std_dev:9.959292)
#0:1989 #1:1952 #2:1961 #3:1977 #4:1956 #5:1938 #6:1968 #7:1962 (total:15703 std_dev:14.563975)
#0:3165 #1:3155 #2:3061 #3:3157 #4:3123 #5:3109 #6:3116 #7:3114 (total:25000 std_dev:31.784430)
```

Default hash algorithm used is 0, every second application is displaying processing distribution stats calculation standard deviation to evaluate hash algorithm.

Enjoy,
Alexandre
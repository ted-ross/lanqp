lanqp
=====

To create a network interface called 'lanq0' with an address of 10.1.1.1/16:

$ sudo tunctl -t lanq0 -n -u <your-user-id>

$ sudo ifconfig lanq0 10.1.1.1 netmask 255.255.0.0 up

You will need to have a nexus-router process running in a location that is reachable from all
lanqp instances.

To run lanqp:

$ ./lanqp <host-of-router> <port-of-router> lanq0 <vlan-name> <ip-of-lanq0>

example:

$ ./lanqp router-host 5672 lanq0 my-vlan 10.1.1.1


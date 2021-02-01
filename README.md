# PRING -- ICMP Ping implemented in Rust

This project is just for fun, scratching an itch around fiddling with
ICMP and Rust.

The command supports a subset of the usual `ping` commands:

    -4, --ipv4-only    Use IPv4 only
    -6, --ipv6-only    Use IPv6 only
    -c, --count <count>                  Number of ECHO_REQUEST packets to send
    -I, --interface <interface>          Source interface name to use for sending packets
    -i, --interval <interval>            Interval in seconds between sending each packet [default: 1.0]
    -s, --payload-size <payload-size>    Packet paylod size [default: 56]
    -t, --ttl <ttl>                      Time-To-Live count [default: 128]

# Running PRING

The program uses raw sockets for ICMP, and therefor needs additional
permission to run for a normal user.  This adds the necessary
permissions:

    $ sudo setcap cap_net_raw=eip target/debug/pring

# Caveats

The IPv6 implementation is not perfect.  Occasionally on the
receiving end, the utility captures Router Solicitation and Router
Advertisement messages.

DO NOT MERGE

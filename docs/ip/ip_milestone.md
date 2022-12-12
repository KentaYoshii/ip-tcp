Struct definitions:
ip packet struct (this includes header)
    -

Node info
    - map of id to interface object
    - map of interface to higher layers
    - helper functions
        - register handler (interface to higher layers)

Link Interface ("Link Layer")
    - udp conn
    - status (activated, deactivated, etc.)
    - helper functions
        - forward packet
            - decrement ttl
            - recompute checksum
        - activate/deactivate interface

Interface to higher layers - where are the handlers registered?

RIP packet struct
uint16 command;
uint16 num_entries;
struct {
    uint32 cost;
    uint32 address;
    uint32 mask;
} entries[num_entries];
- go routine to send periodic updates
    - Split Horizon with Poisoned Reverse
- triggerred updates 
- update our routing table to only keep the lowest cost hops

command line interface - another goroutine

Routing table 
- hide underlying data structures, eg. map ip addresses to interfaces/next hop?
- interface represents a direct link with our node.
- maybe we have two maps, one mapping addresses to interface and another mapping addresses to next hop. 
    - next hop struct should contain
        - the ip address of next hop
        - who sent us this hop (so we don't send them back under poisoned reverse)
        - how many hops away
- our next hops could change because of RIP updates, but will our interfaces change?
- use helper functions to interact with the 'routing table' eg. getInterface
- how do we include the node in its routing table?
- race conditions protection

# TODOs
- Establishing new connections by properly following the TCP state diagram under ideal conditions.  
- Connection teardown is NOT required for this milestone.
- When creating new connections, you should allocate a data structure pertaining to the socket—be prepared to discuss what you need to include in this data structure for the rest of your implementation
- To test establishing new connections, you should implement the a, c, and (partially) ls commands in your TCP driver to listen for, create, and list connections, respectively. For the ls command, you need not list the window sizes for the milestone.
- You should be able to view your TCP traffic in Wireshark to confirm you are using the packet header correctly. However, you do not need to compute the TCP checksum yet. You can run the reference node with checksum validation disabled by passing the flag --disable-checksum.
- Correct operation even with another node in between the two endpoints. This should already be possible if your IP implementation is implementing forwarding properly—but you should check this at this stage to help rule out any lingering bugs.

# Things to Consider
- What does a “SYN” packet or a “FIN” packet do to the receiving socket (in general)?
- What data structures/state variables would you need to represent each TCP socket?
- How will you map incoming packets to sockets?
- What types of events do you need to consider that would affect each socket?
- How will you implement retransmissions?
- In what circumstances would a socket allocation be deleted? What could be hindering when doing so? Note that the state CLOSED would not be equivalent as being deleted.
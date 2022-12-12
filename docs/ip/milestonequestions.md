What objects will you use to abstract link layers, and what interface will it have?
- Refer to link.go

What fields in the IP packet are read to determine when to forward a packet?
- ttl
- checksum (How do we compute?)
- destination

What will you do with a packet destined for local delivery (ie, destination IP == your node’s IP)?
- We have a data structure that maps protocol numbers to handlers and handle appropriately
- Is there default?

What structures will you use to store routing information?
- We have two maps, one that maps ips to interfaces and another that maps ips to hops
- We also have a mutex to protect against concurrent read/updates

What happens on your node when the topology changes? In other words, when links go up down, how are forwarding and routing affected?
- If a link goes down, the interface is no longer valid and we cannot forward packets to that interface. We will also need to update the next hops to the node that went down, and if possible, replace it with another higher cost hop (Should we make a queue for possible replacements?). If not, the entries to the hops table should be removed. We also have to make sure that we have a next hop for the node that we no longer have a connection to. 
- If a link goes up, add it to interfaces, and update hops table if there are any new lower cost hops. 

Other questions
- What is ip addr is not found in the network?
- request routing, response immediately?
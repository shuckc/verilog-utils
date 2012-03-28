
pcap
----
Utility to replay a packets from Wireshark/tcpdump pcap file over a single-byte bus
for use in network handling test benches.

http://wiki.wireshark.org/Development/LibpcapFileFormat

bcd
---
Convertors to and from binary to numerical ascii/bcd

hash
----
`jenkins.v` - a framed byte-wise Jenkins hash-code calculator 

`serialMap.v` - a key-to-value map data structure. Implemented using a linear probe looked seeded by the key's hash. Module parameterised by k/v sizes.

altera
------
Code from the Altera cookbook modified to simulate in Icarus.

http://www.altera.com/literature/manual/stx_cookbook.pdf

testbench
---------
Test benches can be rebuilt with `make` assuming you have `ivp` and `iverilog` on your path. 

Simulation waveforms are written to lxt2 format and are opened with `gtkwave` when a bench/implementation is rebuilt. 

Save files for gtkwave (`gtksav/*.sav`) are included to setup zoom and signals. 

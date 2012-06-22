
Modules
=======

pcap (sim)
----------
Utility to replay a packets from Wireshark/tcpdump pcap file over a single-byte bus
for use in network handling test benches.  
http://wiki.wireshark.org/Development/LibpcapFileFormat

littletoe (synth)
-----------------
Basic line-speed read-only MAC/IP/TCP stack to follow a specific TCP session at the data level, from wire-format EthernetII packets.

bcd (synth)
-----------
Convertors to and from binary to numerical ascii/bcd

xml (synth)
-----------
A scanner/parser to parse XML documents. Tracks tag nesting stack (8 deep), tag key/value/data, comments/data/tag stream. Outpus control signals synchronised with delayed datastream. Uses an internal 4-byte look-ahead for processing, which can be flushed with EOM input.

hash
----
`jenkins.v` - a framed byte-wise Jenkins hash-code calculator  
`serialMap.v` - a key-to-value map data structure. Implemented using a linear probe looked seeded by the key's hash. Module parameterised by k/v sizes.

altera
------
Code from the Altera cookbook modified to simulate in Icarus.  
http://www.altera.com/literature/manual/stx_cookbook.pdf

Testbenches
===========
Test benches can be rebuilt with `make` assuming you have `ivp` and `iverilog` on your path.  
Simulation waveforms are written to lxt2 format and are opened with `gtkwave` when a bench/implementation is rebuilt.  
Save files for gtkwave (`gtksav/*.sav`) are included to setup zoom and signals.  


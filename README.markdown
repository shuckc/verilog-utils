
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
jenins.v - a framed byte-wise Jenkins hash-code calculator
serialMap.v - a key-to-value map data structure. Implemented using a l
inear probe looked seeded by the key's hash. Module parameterised by k/v sizes.

testbench
---------
Test benches can be rebuilt with $ make
Simulation waveforms are written to lxt2 format and are opened with gtkwave when a bench or implementation changes. gtkwave 'save' files (gtksav/*.sav) are included that setup zoom and add appropriate signals.

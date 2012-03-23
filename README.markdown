
pcap
----
Utility to replay a packets from Wireshark/tcpdump pcap file over a single-byte bus
for use in network handling test benches.
http://wiki.wireshark.org/Development/LibpcapFileFormat

bcd
---
Convertors to and from binary to numerical ascii/bcd


testbench
---------
Test benches can be rebuilt with $ make
Simulation waveforms are written to lxt2 format and are opened with gtkwave when a bench or implementation changes. gtkwave 'save' files (gtksav/*.sav) are included that setup zoom and add appropriate signals.



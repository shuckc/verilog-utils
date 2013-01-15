# verilog simulation makefile
# pattern rules
%.lxt : %.bin
	vvp -n $^ -lxt2
	gtkwave $@ gtksav/$(basename $(notdir $^)).sav &
%.bin: %.v
	iverilog -o $@ $^

# tagets
default: bin/pcap.lxt bin/pcap10gb.lxt bin/obin2bcd8.lxt bin/obin2bcdN.lxt bin/ohash.lxt bin/ohashmap.lxt bin/olittletoe.lxt \
	bin/oxml.lxt
clean: 
	RM bin/*

$(shell  mkdir -p bin)

# rules
bin/pcap.lxt: bin/pcap.bin
bin/pcap.bin: pcap/pcapparser_1gb*.v
	iverilog -o $@ $^

bin/pcap10gb.lxt: bin/pcap10gb.bin
bin/pcap10gb.bin: pcap/pcap*_10gb*.v
	iverilog -o $@ $^

bin/obin2bcd8.lxt: bin/obin2bcd8.bin
bin/obin2bcd8.bin: bcd/bin2bcd8*.v bcd/add3.v
	iverilog -o $@ $^

bin/obin2bcdN.lxt: bin/obin2bcdN.bin
bin/obin2bcdN.bin: bcd/bin2bcdN*.v
	iverilog -o $@ $^

bin/ohash.lxt: bin/ohash.bin
bin/ohash.bin: hash/jenkins*.v
	iverilog -o $@ $^

bin/ohashmap.lxt: bin/ohashmap.bin
bin/ohashmap.bin: hash/serialMap*.v hash/jenkins.v
	iverilog -o $@ $^

bin/olittletoe.lxt: bin/olittletoe.bin
bin/olittletoe.bin: littletoe/tcp.v littletoe/tcp_test.v pcap/pcapparser_1gb.v
	iverilog -Wall -o $@ $^

bin/oxml.lxt: bin/oxml.bin
bin/oxml.bin: xml/XMLdecoder*.v
	iverilog -Wall -o $@ $^


# verilog simulation makefile
# pattern rules
%.lxt : %.bin
	vvp -n $^ -lxt2
%.bin: %.v
	iverilog -o $@ $^

# tagets
default: bin/opcap.lxt
clean: 
	RM bin/*

# rules
bin/opcap.lxt: bin/opcap.bin
bin/opcap.bin: pcap/PcapParser*.v
	iverilog -o $@ $^

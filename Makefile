# verilog simulation makefile
# pattern rules
%.lxt : %.bin
	vvp -n $^ -lxt2
%.bin: %.v
	iverilog -o $@ $^

# tagets
default: bin/opcap.lxt bin/obin2bcd8.lxt bin/obin2bcdN.lxt 
clean: 
	RM bin/*

$(shell  mkdir -p bin)

# rules
bin/opcap.lxt: bin/opcap.bin
bin/opcap.bin: pcap/PcapParser*.v
	iverilog -o $@ $^

bin/obin2bcd8.lxt: bin/obin2bcd8.bin
bin/obin2bcd8.bin: bcd/bin2bcd8*.v bcd/add3.v
	iverilog -o $@ $^

bin/obin2bcdN.lxt: bin/obin2bcdN.bin
bin/obin2bcdN.bin: bcd/bin2bcdN*.v
	iverilog -o $@ $^

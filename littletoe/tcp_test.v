`timescale 1ns / 1ps
`define NULL 0

////////////////////////////////////////////////////////////////////////////////
// Engineer:		Chris Shucksmith
// Description:		basic TCP test bench
//	
//
////////////////////////////////////////////////////////////////////////////////

module Tcp_test;

	// Inputs
	reg CLOCK = 0;
	reg paused = 1;
	wire available;
	wire [7:0] pktcount;
	wire streamvalid;
	wire [7:0] stream;
	wire pcapfinished;
	wire newpkt;

	wire [7:0] tcpdata;
	wire tcpdataValid;

	// Instantiate the Unit Under Test (UUT)
	PcapParser #(
		.pcap_filename( "pcap/tcp-4846-connect-disconnect.pcap" )
	) pcap (
		.CLOCK(CLOCK),
		.pause(paused),
		.available(available),
		.datavalid(streamvalid),
		.data(stream),
		.pcapfinished(pcapfinished),
		.newpkt( newpkt )
	);

	Tcp #(
		.port( 80 ),
		.mac( 48'hC471FEC856BF )
	) tcp (
		.CLOCK(CLOCK),
		.dataValid( streamvalid ),
		.data( stream ),
		.outDataValid( tcpdataValid ),
		.outData( tcpdata ),
		.newpkt( newpkt )
	);

	always #10 CLOCK = ~CLOCK;

	integer i;

	initial begin
	
		$dumpfile("bin/olittletoe.lxt");
		$dumpvars(0,tcp);

		#100 
		paused = 0;

		// Add stimulus here
		while (~pcapfinished ) begin
			// $display("stream: %8d %x %d %x %x %c", i, paused, pktcount, streamvalid, stream, stream);
			#20
			i = i+1;
		end

		$finish;

	end

	always @(posedge CLOCK)	begin
		if (tcpdataValid) begin
			$display("tcp: %x ", tcpdata);
		end
	end

endmodule


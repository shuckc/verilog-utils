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
		.tcp_src_port(16'd57284),
		.tcp_src_ip( { 8'd10, 8'd210, 8'd50, 8'd28 } ),
		.tcp_dst_port(16'd4846),
		.tcp_dst_ip( { 8'd10, 8'd210, 8'd144, 8'd11 } ),
		.dataValid( streamvalid ),
		.data( stream ),
		.outDataValid( tcpdataValid ),
		.outData( tcpdata ),
		.newpkt( newpkt )
	);

	always #10 CLOCK = ~CLOCK;

	integer i;
	integer rcount;

	initial begin

		$dumpfile("bin/olittletoe.lxt");
		$dumpvars(0,tcp);
		rcount = 0;

		#100
		paused = 0;

		// Add stimulus here
		while (~pcapfinished ) begin
			// $display("stream: %8d %x %d %x %x %c", i, paused, pktcount, streamvalid, stream, stream);
			#20
			i = i+1;
		end

		if (rcount != 1) begin
			$display(" tcp - expected one output byte, got %d values last %x", rcount, tcpdata );
			$finish_and_return(-1);
		end

		$finish;

	end

	always @(posedge CLOCK)	begin
		if (tcpdataValid) begin
			$display("tcp: %x ", tcpdata);
			rcount = rcount + 1;
			if (rcount > 1 || tcpdata != 8'h20 ) begin
				$display(" tcp - expected one output byte, value 0x20, got %d values last %x", rcount, tcpdata );
				$finish_and_return(-1);
			end
		end
	end

endmodule


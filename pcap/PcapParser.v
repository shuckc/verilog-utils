`timescale 1ns / 1ps
`define NULL 0

////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:	Chris Shucksmith
// Description:
//	Utility to replay a packets from a pcap file over a single-byte bus
//  for use in network handling test benches.
//    http://wiki.wireshark.org/Development/LibpcapFileFormat
//
//  $fread(mem, fid) parameter ordering seems Icarus specific :-/
//
////////////////////////////////////////////////////////////////////////////////

module PcapParser(
	input CLOCK,
	input pause,
	output available,
	output datavalid,
	output [7:0] data,
	output [7:0] pktcount,
	output pcapfinished
	);

	// regs
	reg available = 0;
	reg datavalid = 0;
	reg [7:0] pktcount = 1;	// line up with Wireshark GUI
	reg [7:0] data = 0;
	reg pcapfinished = 0;

	// buffers for message
	reg [7:0] global_header [0:23];
	reg [7:0] packet_header [0:15];

	integer swapped = 0;
	integer file = 0;
	integer r    = 0;
	integer eof  = 0;
	integer i    = 0;
	integer pktSz  = 0;
	integer diskSz = 0;

	initial begin

		// open pcap file
		file = $fopen("pcap/tcp-4846-connect-disconnect.pcap", "r");
		if (file == `NULL) begin
			$display("can't read pcap input");
			$finish_and_return(1);
		end

		// read binary global_header
		// r = $fread(file, global_header);
		r = $fread(global_header,file);

		// check magic signature to determine byte ordering
		if (global_header[0] == 8'hD4 && global_header[1] == 8'hC3) begin
			$display(" pcap endian: swapped");
			swapped = 1;
		end else if (global_header[0] == 8'hA1 && global_header[1] == 8'hB2) begin
			$display(" pcap endian: native");
			swapped = 0;
		end else begin
			$display(" pcap endian: unrecognised format");
			$finish_and_return(1);
		end

		while ( eof == 0 ) begin
			#20
			// read packet header
			// fields of interest are U32 so bear in mind the byte ordering when assembling
			// multibyte fields
			r = $fread(packet_header, file);
			if (swapped == 1) begin
				pktSz  = {packet_header[11],packet_header[10],packet_header[9] ,packet_header[8] };
				diskSz = {packet_header[15],packet_header[14],packet_header[13],packet_header[12]};
			end else begin
				pktSz =  {packet_header[ 8],packet_header[ 9],packet_header[10],packet_header[11]};
				diskSz = {packet_header[12],packet_header[13],packet_header[14],packet_header[15]};
			end

			$display("  packet %0d: incl_length %0d orig_length %0d", pktcount, pktSz, diskSz );

			// optional inter-packet delay - make it a multiple of the clock!
			available <= 1;

			// packet content is byte-aligned, no swapping required
			while (diskSz > 0) begin
				if (~pause) begin
					eof = $feof(file);
					diskSz <= diskSz - 1;
					data <= $fgetc(file);
					if ( eof != 0 || diskSz == 1) begin
						available <= 0;
					end else begin
						datavalid <= 1;
					end
				end else begin
					datavalid <= 0;
				end
				#20
				i = i+1;
			end
			pktcount <= pktcount + 1;

		end
		pcapfinished <= 1;

	end

endmodule

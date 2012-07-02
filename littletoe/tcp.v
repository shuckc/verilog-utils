`timescale 1ns / 1ps
`define NULL 0

////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:	Chris Shucksmith
// Description:
//	Pull out TCP payload bytes from packet-orientated TCP/IP frames.
//  Follows a single TCP session/stream
//
////////////////////////////////////////////////////////////////////////////////

module Tcp
	#(
		parameter mac  = 48'h000000000000,
		parameter ip   = 32'h11223344,
		parameter port = 16'd80
	) (
		input CLOCK,
		input newpkt,
		input dataValid,
		input [7:0] data,
		input [15:0] tcp_src_port,
		input [31:0] tcp_src_ip,
		input [15:0] tcp_dst_port,
		input [31:0] tcp_dst_ip,

		output reg outDataValid = 0,
		output reg [7:0] outData = 0,
		output reg outnewpkt = 0,
		output reg [7:0] mss = 0,
		output reg gapped = 0
	);

	localparam  [6:0]  sIDLE      = 6'd000;
	localparam  [6:0]  sETH_MACD0 = 6'd002;
	localparam  [6:0]  sETH_MACD1 = 6'd003;
	localparam  [6:0]  sETH_MACD2 = 6'd004;
	localparam  [6:0]  sETH_MACD3 = 6'd005;
	localparam  [6:0]  sETH_MACD4 = 6'd006;
	localparam  [6:0]  sETH_MACD5 = 6'd007;
	localparam  [6:0]  sETH_MACS0 = 6'd008;
	localparam  [6:0]  sETH_MACS1 = 6'd009;
	localparam  [6:0]  sETH_MACS2 = 6'd010;
	localparam  [6:0]  sETH_MACS3 = 6'd011;
	localparam  [6:0]  sETH_MACS4 = 6'd012;
	localparam  [6:0]  sETH_MACS5 = 6'd013;
	localparam  [6:0]  sETH_BADMAC= 6'd014;
	localparam  [6:0]  sETH_TYPE0 = 6'd015;	// type or -> 802.1Q header (TPID)
	localparam  [6:0]  sETH_TYPE1 = 6'd016;	// type

	localparam  [6:0]  sETH_802Q1 = 6'd017;	// 802.1Q header (TPID)
	localparam  [6:0]  sETH_802Q2 = 6'd018;	//   vlan  (TCI)
	localparam  [6:0]  sETH_802Q3 = 6'd019;	//   vlan  (TCI)  => sETH_TYPE0

	// ethertypes
	//  0x0800 IPv4
	//	0x0806 ARP
	//	0x8100 802.1Q frame
	//  0x86DD IPV6
	//
	// error/counter states
	localparam  [6:0]  sETH_TYPE_ERR   = 6'd020;
	localparam  [6:0]  sETH_TYPE_ARP_0 = 6'd021;
	localparam  [6:0]  sETH_TYPE_IPV6  = 6'd022;
	
	// IPV4 handing
	localparam  [6:0]  sIPV4_VER_SZ	= 6'd030;
	localparam  [6:0]  sIPV4_DSCP	= 6'd031;
	localparam  [6:0]  sIPV4_LEN0	= 6'd032;
	localparam  [6:0]  sIPV4_LEN1	= 6'd033;
	localparam  [6:0]  sIPV4_ID0		= 6'd034;
	localparam  [6:0]  sIPV4_ID1		= 6'd035;
	localparam  [6:0]  sIPV4_FRAG0	= 6'd036;
	localparam  [6:0]  sIPV4_FRAG1	= 6'd037;
	localparam  [6:0]  sIPV4_TTL		= 6'd038;
	localparam  [6:0]  sIPV4_PCOL	= 6'd039;
	localparam  [6:0]  sIPV4_CHK0	= 6'd040;
	localparam  [6:0]  sIPV4_CHK1	= 6'd041;
	localparam  [6:0]  sIPV4_IPSRC0	= 6'd042;
	localparam  [6:0]  sIPV4_IPSRC1	= 6'd043;
	localparam  [6:0]  sIPV4_IPSRC2	= 6'd044;
	localparam  [6:0]  sIPV4_IPSRC3	= 6'd045;
	localparam  [6:0]  sIPV4_IPDST0	= 6'd046;
	localparam  [6:0]  sIPV4_IPDST1	= 6'd047;
	localparam  [6:0]  sIPV4_IPDST2	= 6'd048;
	localparam  [6:0]  sIPV4_IPDST3	= 6'd049;
	localparam  [6:0]  sIPV4_OPTION0		= 6'd050;	// ipv4 options repeat 4bytes
	localparam  [6:0]  sIPV4_OPTION1		= 6'd051;
	localparam  [6:0]  sIPV4_OPTION2		= 6'd052;
	localparam  [6:0]  sIPV4_OPTION3		= 6'd053;

	// IPV4 protocol types
	localparam  [7:0]  IPV4_PCOL_ICMP	= 8'h01;	// ICMP
	localparam  [7:0]  IPV4_PCOL_IGMP	= 8'h02;	// IGMP
	localparam  [7:0]  IPV4_PCOL_TCP		= 8'h06;	// TCP
	localparam  [7:0]  IPV4_PCOL_UDP		= 8'h11;	// UDP
	localparam  [7:0]  IPV4_PCOL_ENCAP	= 8'h62;	// ENCAP
	localparam  [7:0]  IPV4_PCOL_OSPF	= 8'h59;	// OSPF

	// states to handle
	localparam  [6:0]  sICMP0			= 6'd055;
	localparam  [6:0]  sIGMP0			= 6'd056;
	localparam  [6:0]  sUDP0				= 6'd057;
	localparam  [6:0]  sIPV4_TYPE_ERR	= 6'd058;
	localparam  [6:0]  sENCAP0			= 6'd059;
	localparam  [6:0]  sOSPF				= 6'd060;
	localparam  [6:0]  sARP0				= 6'd061;

	localparam  [6:0]  sTCP_SRCP0		= 7'd070;
	localparam  [6:0]  sTCP_SRCP1		= 7'd071;
	localparam  [6:0]  sTCP_DSTP0		= 7'd072;
	localparam  [6:0]  sTCP_DSTP1		= 7'd073;
	localparam  [6:0]  sTCP_SEQ0			= 7'd074;
	localparam  [6:0]  sTCP_SEQ1			= 7'd075;
	localparam  [6:0]  sTCP_SEQ2			= 7'd076;
	localparam  [6:0]  sTCP_SEQ3			= 7'd077;
	localparam  [6:0]  sTCP_ACK0			= 7'd078;
	localparam  [6:0]  sTCP_ACK1			= 7'd079;
	localparam  [6:0]  sTCP_ACK2			= 7'd080;
	localparam  [6:0]  sTCP_ACK3			= 7'd081;
	localparam  [6:0]  sTCP_DATAOFF		= 7'd082;
	localparam  [6:0]  sTCP_FLAGS		= 7'd083;
	localparam  [6:0]  sTCP_WINSZ0		= 7'd084;
	localparam  [6:0]  sTCP_WINSZ1		= 7'd085;
	localparam  [6:0]  sTCP_CHK0			= 7'd086;
	localparam  [6:0]  sTCP_CHK1			= 7'd087;
	localparam  [6:0]  sTCP_URG0			= 7'd088;
	localparam  [6:0]  sTCP_URG1			= 7'd089;
	localparam  [6:0]  sTCP_OPT0			= 7'd090;
	localparam  [6:0]  sTCP_OPT1			= 7'd091;
	localparam  [6:0]  sTCP_OPT2			= 7'd092;
	localparam  [6:0]  sTCP_OPT3			= 7'd093;

	localparam  [6:0]  sTCP_DATA			= 7'd095;


	// fixed size of an IP header (20) and TCP header (20) without any optional headers
	localparam  [15:0]  SZ_IP_TCP_NOOPTIONS	= 16'd20 + 16'd20;

	// hot state
	reg [7:0] pos = 0;

	// Ethernet state
	reg [12:0] eth_vlan = 0;
	reg macdest = 1;
	reg runt = 0;

	// IPv4 state
	reg [3:0] IPV4_IHeaderLen = 0; 	// decremented at the first byte of each 32 word
									// except first, since value in [4:7] byte 0 so
									// defer decrement until byte 2.
	reg [15:0] IPV4_Size = 0;
	reg [6:0]  IPV4_PCOL = 0;

	// TCP handling
	reg tcpFlagSYN = 0;
	reg tcpFlagACK = 0;
	reg tcpFlagRST = 0;
	reg tcpFlagPSH = 0;
	reg tcpFlagFIN = 0;
	reg [15:0] tcpData = 0;
	reg [3:0] tcpDataOff = 0;
	reg [31:0] tcpSeq = 0;
	reg [31:0] tcpSeqBuf = 0;

	reg ms0=0,ms1=0,ms2=0,ms3=0,ms4=0,ms5=0; // match src ip+port
	reg md0=0,md1=0,md2=0,md3=0,md4=0,md5=0; // match src ip+port

	wire tcp_matches = ms0 && ms1 && ms2 && ms3 && ms4 && ms5 &&
						md0 && md1 && md2 && md3 && md4 && md5;

	// counters
	reg [7:0] counterEthTypeARP = 0;
	reg [7:0] counterEthTypeIPV6 = 0;
	reg [7:0] counterEthTypeIPV4 = 0;
	reg [7:0] counterEthTypeErr = 0;
	reg [7:0] counterEthMACNotUs = 0;
	reg [7:0] counterEthIPTypeICMP = 0;
	reg [7:0] counterEthIPTypeIGMP = 0;
	reg [7:0] counterEthIPTypeUDP = 0;
	reg [7:0] counterEthIPTypeTCP = 0;
	reg [7:0] counterEthIPTypeOSPF = 0;
	reg [7:0] counterEthIPTypeErr = 0;

	always @(posedge CLOCK)	begin

		if (newpkt) begin
			pos 	<=  sETH_MACD0;
			macdest <= 1;
			outDataValid <= 0;
			outnewpkt <= 0;
			ms0 <= 0; ms1 <= 0; ms2 <= 0; ms3 <= 0; ms4 <= 0; ms5 <= 0; // match src ip+port
			md0 <= 0; md1 <= 0; md2 <= 0; md3 <= 0; md4 <= 0; md5 <= 0; // match dest ip+port
		end else if (dataValid) begin
			case (pos)
			sIDLE:	begin pos <= sIDLE;
					outDataValid <= 0;
					outnewpkt <= 0;
					ms0 <= 0; ms1 <= 0; ms2 <= 0; ms3 <= 0; ms4 <= 0; ms5 <= 0; // match src ip+port
					md0 <= 0; md1 <= 0; md2 <= 0; md3 <= 0; md4 <= 0; md5 <= 0; // match dest ip+port
					end
			sETH_MACD0:	begin
						pos <= sETH_MACD1;
						macdest <= data == mac[47:40];
					end
			sETH_MACD1:	begin
						pos <= sETH_MACD2;
						macdest <= macdest & (data == mac[39:32]);
					end
			sETH_MACD2:	begin
						pos <= sETH_MACD3;
						macdest <= macdest & (data == mac[31:24]);
					end
			sETH_MACD3:	begin
						pos <= sETH_MACD4;
						macdest <= macdest & (data == mac[23:16]);
					end
			sETH_MACD4:	begin
						pos <= sETH_MACD5;
						macdest <= macdest & (data == mac[15:8]);
					end
			sETH_MACD5:	begin
						pos <= sETH_MACS0;
						macdest <= macdest & (data == mac[7:0]);
					end
			sETH_MACS0:	begin
						pos <= sETH_MACS1;
					end
			sETH_MACS1:	begin
						pos <= sETH_MACS2;
					end
			sETH_MACS2:	begin
						pos <= sETH_MACS3;
					end
			sETH_MACS3:	begin
						pos <= sETH_MACS4;
					end
			sETH_MACS4:	begin
						pos <= sETH_MACS5;
					end
			sETH_MACS5:	begin
						pos <= sETH_TYPE0;
					end
			sETH_BADMAC: begin
						pos <= sIDLE;
						counterEthMACNotUs <= counterEthMACNotUs + 1;
					end
			sETH_TYPE0: begin
						// can tell if we are vlan/IPV6 ethertypes, so fork
						// to avoid storing upper type byte for later parsing
						pos <=  (data == 8'h81) ? sETH_802Q1 :
							   ((data == 8'h86) ? sETH_TYPE_IPV6 :
							   ((data == 8'h08) ? sETH_TYPE1 : sETH_TYPE_ERR));
					end
			sETH_TYPE_ERR: begin
						pos <= sIDLE;
						counterEthTypeErr <= counterEthTypeErr + 1;
					end
			sETH_TYPE_IPV6: begin
						pos <= sIDLE;
						counterEthTypeIPV6 <= counterEthTypeIPV6 + 1;
					end
			sETH_TYPE1: begin
						// can now fork lower byte of ethertype decoding
						pos <= (data == 8'h00) ? sIPV4_VER_SZ :
							   ((data == 8'h06) ? sARP0 :
							   sETH_TYPE_ERR);
					end
			// extended VLAN tag decoding states
			sETH_802Q1: begin
						pos <= sETH_802Q2;	// data = 00
					end
			sETH_802Q2: begin
						pos <= sETH_802Q3;	// data = TCI high byte
						eth_vlan[12:9] <= data[3:0];
					end
			sETH_802Q3: begin
						// TRICK: after soaking up the VLAN header, jump
						// back to the ethertype states
						pos <= sETH_TYPE0;	// data = TCI low byte (vlan TCI[12:0])
						eth_vlan[7:0] <= data[7:0];
					end

			// content states
			sARP0:		begin
						pos <= sIDLE;
						counterEthTypeARP <= counterEthTypeARP + 1;
					end

			// IPv4
			sIPV4_VER_SZ:	begin
						pos <= sIPV4_DSCP;
						counterEthTypeIPV4 <= counterEthTypeIPV4 + 1;
						IPV4_IHeaderLen <= data[3:0];
					end
			sIPV4_DSCP:	begin
						pos <= sIPV4_LEN0;
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub1 4bytes
					end
			sIPV4_LEN0:	begin
						pos <= sIPV4_LEN1;
						IPV4_Size[15:8] <= data;
					end
			sIPV4_LEN1:	begin
						pos <= sIPV4_ID0;
						IPV4_Size[7:0] <= data;
					end
			sIPV4_ID0:	begin
						pos <= sIPV4_ID1;
						tcpData <= IPV4_Size - SZ_IP_TCP_NOOPTIONS;	// TCP data size assuming no IPV4 options, no TCP options
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub2 4bytes
					end
			sIPV4_ID1:	begin
						pos <= sIPV4_FRAG0;
					end
			sIPV4_FRAG0:	begin
						pos <= sIPV4_FRAG1;
					end
			sIPV4_FRAG1:	begin
						pos <= sIPV4_TTL;
					end
			sIPV4_TTL:	begin
						pos <= sIPV4_PCOL;
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub3 4bytes
					end
			sIPV4_PCOL:	begin
						pos <= sIPV4_CHK0;
						IPV4_PCOL <= (data == IPV4_PCOL_ICMP) ? sICMP0 :
							  	 	(data == IPV4_PCOL_IGMP) ? sIGMP0 :
							  	 	(data == IPV4_PCOL_TCP)  ? sTCP_SRCP0 :
							  	 	(data == IPV4_PCOL_UDP)  ? sUDP0 :
							  	 	(data == IPV4_PCOL_ENCAP)? sIPV4_TYPE_ERR :
							  	 	(data == IPV4_PCOL_OSPF) ? sOSPF :
							   		sIPV4_TYPE_ERR;
					end
			sIPV4_CHK0:	begin
						pos <= sIPV4_CHK1;
					end
			sIPV4_CHK1:	begin
						pos <= sIPV4_IPSRC0;
					end
			sIPV4_IPSRC0: begin
						pos <= sIPV4_IPSRC1;
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub4 4bytes
						ms0 <= (data == tcp_src_ip[31:24]);
					end
			sIPV4_IPSRC1: begin
						pos <= sIPV4_IPSRC2;
						ms1 <= (data == tcp_src_ip[23:16]);
					end
			sIPV4_IPSRC2: begin
						pos <= sIPV4_IPSRC3;
						ms2 <= (data == tcp_src_ip[15:8]);
					end
			sIPV4_IPSRC3: begin
						pos <= sIPV4_IPDST0;
						ms3 <= (data == tcp_src_ip[7:0]);
					end
			sIPV4_IPDST0: begin
						pos <= sIPV4_IPDST1;
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub5 4bytes
						md0 <= (data == tcp_dst_ip[31:24]);
					end
			sIPV4_IPDST1: begin
						pos <= sIPV4_IPDST2;
						md1 <= (data == tcp_dst_ip[23:16]);
					end
			sIPV4_IPDST2: begin
						pos <= sIPV4_IPDST3;
						md2 <= (data == tcp_dst_ip[15:8]);
					end
			sIPV4_IPDST3: begin
						// if options, loop through OPTIONS0-3 to skip 32bit words, or
						// jump to state from pcol decoder
						pos <= (IPV4_IHeaderLen == 0) ? IPV4_PCOL : sIPV4_OPTION0;
						md3 <= (data == tcp_dst_ip[7:0]);
					end
			 // IPv4 OPTIONS loop
			 sIPV4_OPTION0: begin
						pos <= sIPV4_OPTION1;
						IPV4_IHeaderLen <= IPV4_IHeaderLen - 1;	// pipelined sub2 4bytes
						tcpData <= tcpData - 1;
					end
			 sIPV4_OPTION1: begin
						pos <= sIPV4_OPTION2;
						tcpData <= tcpData - 1;
					end
			 sIPV4_OPTION2: begin
						pos <= sIPV4_OPTION3;
						tcpData <= tcpData - 1;
					end
			 sIPV4_OPTION3: begin
						// fork back to OPTION0 or IPV4_PCOL
						pos <= (IPV4_IHeaderLen == 0) ? IPV4_PCOL : sIPV4_OPTION0;
						tcpData <= tcpData - 1;
					end

			// TCP states

			sICMP0:	begin
						pos <= sIDLE;
						counterEthIPTypeICMP <= counterEthIPTypeICMP + 1;
					end
			sIGMP0:	begin
						pos <= sIDLE;
						counterEthIPTypeIGMP <= counterEthIPTypeIGMP + 1;
					end

			sUDP0:	begin
						pos <= sIDLE;
						counterEthIPTypeUDP <= counterEthIPTypeUDP + 1;
					end
			sIPV4_TYPE_ERR: begin
						pos <= sIDLE;
						counterEthIPTypeErr <= counterEthIPTypeErr + 1;
					end
			sOSPF: begin
						pos <= sIDLE;
						counterEthIPTypeOSPF <= counterEthIPTypeOSPF + 1;
					end

			sTCP_SRCP0: begin
						pos <= sTCP_SRCP1;
						counterEthIPTypeTCP <= counterEthIPTypeTCP + 1;
						ms4 <= (data == tcp_src_port[15:8]);
					end
			sTCP_SRCP1: begin
						pos <= sTCP_DSTP0;
						ms5 <= (data == tcp_src_port[7:0]);
					end
			sTCP_DSTP0: begin
						pos <= sTCP_DSTP1;
						md4 <= (data == tcp_dst_port[15:8]);
					end
			sTCP_DSTP1: begin
						pos <= sTCP_SEQ0;
						md5 <= (data == tcp_dst_port[7:0]);
					end
			// it's mandatory to buffer the SEQuence number as we don't know whether to latch
			// to tcpSeqNum (SYN) or compare for gaploss (!SYN)
			sTCP_SEQ0: begin
						pos <= sTCP_SEQ1;
						tcpSeqBuf[31:24] <= data;
					end
			sTCP_SEQ1: begin
						pos <= sTCP_SEQ2;
						tcpSeqBuf[23:16] <= data;
					end
			sTCP_SEQ2: begin
						pos <= sTCP_SEQ3;
						tcpSeqBuf[15:8] <= data;
					end
			sTCP_SEQ3: begin
						pos <= sTCP_ACK0;
						tcpSeqBuf[7:0] <= data;
					end
			sTCP_ACK0: begin
						pos <= sTCP_ACK1;
					end
			sTCP_ACK1: begin
						pos <= sTCP_ACK2;
					end
			sTCP_ACK2: begin
						pos <= sTCP_ACK3;
					end
			sTCP_ACK3: begin
						pos <= sTCP_DATAOFF;
					end
			sTCP_DATAOFF: begin
						pos <= sTCP_FLAGS;
						tcpDataOff <= data[7:4];
					end
			sTCP_FLAGS: begin
						pos <= sTCP_WINSZ0;
						tcpFlagFIN <= data[0];
						tcpFlagSYN <= data[1];
						tcpFlagRST <= data[2];
						tcpFlagPSH <= data[3];
						tcpFlagACK <= data[4];
					end
			sTCP_WINSZ0: begin
						pos <= sTCP_WINSZ1;
					end
			sTCP_WINSZ1: begin
						pos <= sTCP_CHK0;
					end
			sTCP_CHK0: begin
						pos <= sTCP_CHK1;
					end
			sTCP_CHK1: begin
						pos <= sTCP_URG0;
					end
			sTCP_URG0: begin
						pos <= sTCP_URG1;
					end
			sTCP_URG1: begin
						pos <= (tcpDataOff != 5) ? sTCP_OPT0 : 	// 5 words in TCP if no options
								(tcpData != 0) ? sTCP_DATA:		// 0 if this last byte (ie. no data)
								sIDLE;
						outnewpkt <= (tcpData != 0) && (tcpDataOff != 5) && tcp_matches;  // don't raise outnewpkt for SYN/ACK (packets with no data payload)
					end
			sTCP_OPT0: begin
						pos <= sTCP_OPT1;
						tcpDataOff <= tcpDataOff - 1;
						tcpData <= tcpData - 1;
					end
			sTCP_OPT1: begin
						pos <= sTCP_OPT2;
						tcpData <= tcpData - 1;
					end
			sTCP_OPT2: begin
						pos <= sTCP_OPT3;
						tcpData <= tcpData - 1;
					end
			sTCP_OPT3: begin
						pos <= (tcpDataOff != 5) ? sTCP_OPT0 :
								(tcpData != 1) ? sTCP_DATA : 		// 1 if this is last byte
								 sIDLE;
						tcpData <= tcpData - 1;
						outnewpkt <= (tcpData != 1) && tcp_matches;  // don't raise outnewpkt for SYN/ACK (packets with no data payload)
					end
			sTCP_DATA: begin
						pos <= (tcpData != 1) ? sTCP_DATA : sIDLE;	// 1 if this is last byte
						outDataValid <= tcp_matches;
						outData <= data;
						outnewpkt <= 0;
					end
			endcase
		end else begin
			// !dataValid
			outDataValid <= 0;
		end
	end

	always @(posedge CLOCK)	begin
		// some elements of the design are idempotent so can be repeated while a state is held
		// waiting for dataValid. Bring out to this block to avoid holding up the critical path.

		case (pos)
			sTCP_WINSZ0: begin
					if (tcpFlagSYN) begin
						tcpSeq <= tcpSeqBuf;
					end else begin
						// no SYN... so tcpSeqBuf should match our "calculated" tcpSeq which has been
						// incremented by the last data payload
						gapped <= (tcpSeqBuf != tcpSeq);
					end
				end
		endcase
	end

endmodule



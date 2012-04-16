`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:    Chris Shucksmith
// Module:		Scanning XML decoder, like a physical sax parser
//////////////////////////////////////////////////////////////////////////////////
module XMLDecoder(
    input CLOCK,
    input reset,
    input inValid,
    input [7:0] in,
    input newMsg,

    output outValid,
    output [7:0] out,
    output outNewMsg,
    output isData,
    output isTag,
    output isTagName,
    output isTagKey,
    output isTagValue,
    output isComment,

    output [3:0] tagDepth,
    output depthPush,
    output depthPop,

    output [7:0] s0,
    output [7:0] s1,
    output [7:0] s2,
    output [7:0] s3,
    output [7:0] s4,
    output [7:0] s5,
    output [7:0] s6,
    output [7:0] s7
    );

	reg rnnn = 1;
	reg rnn  = 0;
	reg rn   = 0;
	reg r    = 0;

	reg vnnn = 0;
 	reg vnn  = 0;
	reg vn   = 0;
	reg v    = 0;
	reg vp   = 0;

	reg [7:0] snnn = 0;
	reg [7:0] snn  = 0;
	reg [7:0] sn   = 0;
	reg [7:0] s    = 0;
	reg [7:0] sp   = 0;
	reg [7:0] spp  = 0;
	reg [7:0] sppp = 0;

	reg _isTagName        = 0;
	reg _isTagKey         = 0;
	reg _isTagValue       = 0;
	reg _isClosingTag     = 0;
	reg _isSelfClosingTag = 0;
	reg _isComment        = 0;

	reg intag             = 0;
	reg [3:0] tagdepth    = 0;
	reg [7:0] tagno [0:7];  // tag position at depth N.. if large enough will instantiate a block ram
	reg _isDepthPush      = 0;
	reg _isDepthPop       = 0;

	// XML comment is <!--
	wire onTagStartNext = sn == "<" && !(snn=="!" && snnn=="-");  //  '<' but not <!-
	wire onTagClose = (s == ">");		   //  '>'
	wire onSelfCloseTag = (s =="/" || s == "?") && sn == ">";   // consider XML doctype self-closing
	wire onCloseThenData = onTagClose && sn != "<";

	wire _isOpeningTag = intag && !_isSelfClosingTag && !_isClosingTag;
	wire _isData = outValid && !intag && !_isComment;

	// export the stack depth positions
	wire [7:0] s0 = tagno[0];
	wire [7:0] s1 = tagno[1];
	wire [7:0] s2 = tagno[2];
	wire [7:0] s3 = tagno[3];
	wire [7:0] s4 = tagno[4];
	wire [7:0] s5 = tagno[5];
	wire [7:0] s6 = tagno[6];
	wire [7:0] s7 = tagno[7];

	// This will be replaced in synthesis with EBR reset vector
	integer k;
	initial begin
		for (k = 0; k < 9; k = k + 1) begin
			tagno[k] <= 0;
		end
	end
	// END

	always @(posedge CLOCK) begin
		if (inValid || vnn || vn || v) begin
			// ripple for valid signal
			vnnn <= inValid;
			vnn <= vnnn;
			vn  <= vnn;
			v   <= vn;
			vp  <= v;
			// ripple for data look ahead/behind
			snnn <= in;
			snn <= snnn;
			sn  <= snn;
			s   <= sn;
			sp  <= s;
			spp <= sp;
			sppp<= spp;
			// ripple for newMsg
			rnnn <= newMsg;
			rnn  <= rnnn;
			rn   <= rnn;
			r    <= rn;
		end
		if (reset || rn) begin
			tagdepth <= 0;
			tagno[0] <= 0;
			tagno[1] <= 0;
			tagno[2] <= 0;
			tagno[3] <= 0;
			tagno[4] <= 0;
			tagno[5] <= 0;
			tagno[6] <= 0;
			intag             <= 0;
			_isClosingTag     <= 0;
			_isSelfClosingTag <= 0;
			_isTagName        <= 0;
			_isTagKey         <= 0;
			_isTagValue       <= 0;
			_isComment        <= 0;
			_isDepthPush      <= 0;
			_isDepthPop       <= 0;
		end else if (vn || v) begin
			// handle comments, look ahead to start, look behind to end
			_isComment <=  ( (sn == "<" && snn == "!" && snnn == "-" && in == "-") || _isComment )
						&& !(s == ">" && sp == "-" && spp == "-");

			// if we are not in a comment, stream is either a tag or data
			if (!_isComment) begin
				intag <= (intag || onTagStartNext) && !(onTagClose && !onTagStartNext);
				_isTagName <= ((s == "<" && sn != "/") || (s=="/" && sp == "<") || _isTagName)
				               && !(sn == " " || sn == ">");

				// for tag key/value logic, enable the alternator when intag & !isTagName
				//   <tagname key=value key=value key=value>
				_isTagKey <= (intag && s==" " || _isTagKey) && sn!="=";
				_isTagValue <= (intag && s=="=" || _isTagValue) && !(sn == " " || sn == ">");

				_isClosingTag <= (s != ">" && _isClosingTag) || (s == "<" && sn == "/");
				_isSelfClosingTag <= (_isSelfClosingTag || onSelfCloseTag) && !onTagStartNext;

				// a tag is either opening, closing or self-closing. At the end of the tag
				// (onTagClose) we adjust and flag changes to depth based on the three possibilities.
				tagdepth <= tagdepth + (onTagClose && _isOpeningTag)
							- (onTagClose && _isClosingTag);

				_isDepthPush <= onTagClose && _isOpeningTag;
				_isDepthPop  <= onTagClose && _isClosingTag;

				if (onTagClose) begin
					if (_isClosingTag || _isSelfClosingTag) begin
						tagno[tagdepth] <= tagno[tagdepth] + 1;
						tagno[tagdepth+1] <= 0;
					end
				end
			end
		end
	end

    assign outNewMsg  = r;
	assign out        = s;
	assign outValid   = v;
	assign isComment  = _isComment;
	assign isTag      = intag && !_isComment;
	assign isData     = _isData;
	assign tagDepth   = tagdepth;
	assign isTagKey   = _isTagKey;
	assign isTagValue = _isTagValue;
	assign isTagName  = _isTagName;
	assign depthPush  = _isDepthPush;
	assign depthPop   = _isDepthPop;

endmodule


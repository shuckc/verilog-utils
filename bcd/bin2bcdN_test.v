`timescale 1ns / 1ps

////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:  Chris Shucksmith
//
////////////////////////////////////////////////////////////////////////////////

module bin2bcdN_test;

	// Inputs
	reg CLOCK;
	reg reset;
	reg [15:0] value;	// 4 digits
	reg start;
	// Outputs
	wire [32:0] out;
	wire done;

	reg [31:0] i;

	// Instantiate the Unit Under Test (UUT)
	bin2bcdN uut (
	    .clk_i(CLOCK),
		.ce_i(1),
		.rst_i(reset),
		.start_i(start),
		.dat_binary_i(value),
		.dat_bcd_o(out),
		.done_o(done)
	);
	always #10 CLOCK = ~CLOCK;

	initial begin

		 $dumpfile("bin/obin2bcdN.lxt");
		 $dumpvars(0,uut);

		// Initialize Inputs
		value = 0;
		CLOCK = 0;

		// Wait 100 ns for global reset to finish
		#100;
		reset <= 1;
		#20 reset <= 0;

        #20 $display("starting");
		// Add stimulus here
		for (i = 0; i <= 10010; i = i + 7) begin
    		#20
    		value <= i;
    		start <= 1;
    		#20
    		start <= 0;
    		#20 wait(done);
    		$display(" %d  : %d == %d %d %d %d", i, value, out[15:12], out[11:8], out[7:4], out[3:0] );
    		#20 start <= 0;
    		// check that the concatenation of the ascii bytes above is
    		// the same as fprintf to an array

    	end
    	#100 $finish;

	end

endmodule


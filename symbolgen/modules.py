
import verilogParse
import os, time, pprint
import gc
from pyparsing import ParseException

def test( strng ):
    tokens = []
    try:
        tokens = verilogParse.Verilog_BNF().parseString( strng )
    except ParseException, err:
        print err.line
        print " "*(err.column-1) + "^"
        print err
    return tokens

if __name__ == "__main__":
        print "Verilog module scanner" 

        failCount = 0
        verilogParse.Verilog_BNF()
        numlines = 0
        startTime = time.clock()
        fileDir = "verilog"
        #~ fileDir = "verilog/new"
        #~ fileDir = "verilog/new2"
        #~ fileDir = "verilog/new3"
        allFiles = filter( lambda f : f.endswith(".v"), os.listdir(fileDir) )
        #~ allFiles = [ "list_path_delays_test.v" ]
        #~ allFiles = filter( lambda f : f.startswith("a") and f.endswith(".v"), os.listdir(fileDir) )
        #~ allFiles = filter( lambda f : f.startswith("c") and f.endswith(".v"), os.listdir(fileDir) )
        #~ allFiles = [ "ff.v" ]

        pp = pprint.PrettyPrinter( indent=2 )
        
        for vfile in allFiles:
            gc.collect()
            fnam = fileDir + "/"+vfile
            infile = file(fnam)
            filelines = infile.readlines()
            infile.close()
	    print
            print fnam, len(filelines),
            numlines += len(filelines)
            teststr = "".join(filelines)
            
            tokens = test( teststr )
            
            if ( len( tokens ) ):
                print "OK"
                #~ print "tokens="
                #~ pp.pprint( tokens.asList() )
                #~ print

                ##ofnam = fileDir + "/parseOutput/" + vfile + ".parsed.txt"
                #outfile = file(ofnam,"w")
                #outfile.write( teststr )
                #outfile.write("\n")
                #outfile.write("\n")
                print(pp.pformat(tokens.asList()))
                #outfile.write("\n")
                #outfile.close()
            else:
                print "failed"
        
        
        


            

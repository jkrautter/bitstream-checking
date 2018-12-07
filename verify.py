#!/usr/bin/env python3
#
#   Copyright 2018 Jonas Krautter <jonas.krautter@kit.edu>
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
#   and associated documentation files (the "Software"), to deal in the Software without restriction, 
#   including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
#   and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
#   subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all copies or substantial 
#   portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
#   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
#   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
#   FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
#   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
#   DEALINGS IN THE SOFTWARE.
#
#   This program is a compilation of multiple bitstream checking methodologies into a single verification
#   script. To use it, you need the following software installed: 
#   A modified version of the yosys synthesis tool: https://github.com/jkrautter/yosys
#   A modified version of the icestorm bitstream reversal tools: https://github.com/jkrautter/icestorm
#   The graph_tool python library: https://graph-tool.skewed.de/
#   The iCEcube2 development environment: http://www.latticesemi.com/en/Products/DesignSoftwareAndIP/FPGAandLDS/iCEcube2
#   From iCEcube2, the commandline tools synpwrap and tclsh must be in the PATH (and required libraries in LD_LIBRARY_PATH)
#

from graph_tool.all import *
from graph_tool import topology
import os
from subprocess import call
import shutil
import argparse
import numpy as np
import re
import sys
import time

# Temporary string with replacement variables to create an iCEcube2 project file:
prjstr = "add_file -verilog -lib work \"$VFILE$\"\n" \
"add_file -constraint -lib work \"tmp.sdc\"\n" \
"impl -add tmp -type fpga\n" \
"set_option -vlog_std v2001\n" \
"set_option -project_relative_includes 1\n" \
"set_option -technology SBTiCE40\n" \
"set_option -part iCE40HX8K\n" \
"set_option -package CT256\n" \
"set_option -speed_grade\n" \
"set_option -part_companion \"\"\n" \
"set_option -frequency auto\n" \
"set_option -write_verilog 0\n" \
"set_option -write_vhdl 0\n" \
"set_option -maxfan 10000\n" \
"set_option -disable_io_insertion 0\n" \
"set_option -pipe 1\n" \
"set_option -retiming 0\n" \
"set_option -update_models_cp 0\n" \
"set_option -fixgatedclocks 2\n" \
"set_option -fixgeneratedclocks 0\n" \
"set_option -popfeed 0\n" \
"set_option -constprop 0\n" \
"set_option -createhierarchy 0\n" \
"set_option -symbolic_fsm_compiler 1\n" \
"set_option -compiler_compatible 0\n" \
"set_option -resource_sharing 1\n" \
"set_option -write_apr_constraint 1\n" \
"project -result_format \"edif\"\n" \
"project -result_file chip.edf\n" \
"impl -active \"tmp\"\n"

# Temporary string with replacement variables to create a TCL file for iCEcube2 compilation:
tclstr = "set device iCE40HX8K-CT256\n" \
"set top_module chip\n" \
"set proj_dir \"$TMPDIR$\"\n" \
"set output_dir \"/tmp\"\n" \
"set edif_file \"chip\"\n" \
"set tool_options \":edifparser -y $PCFFILE$\"\n" \
"set sbt_root \"~/lscc/iCEcube2.2017.08/sbt_backend\"\n" \
"append sbt_tcl $sbt_root \"/tcl/sbt_backend_synpl.tcl\"\n" \
"source $sbt_tcl\n" \
"run_sbt_backend_auto $device $top_module $proj_dir $output_dir $tool_options $edif_file\n" \
"exit\n"

# Temporary string to create timing constraints for the J3 board clock pin on the iCE40-HX8K breakout board:
sdcstr = "create_clock -period 83.33 -name {clkin} [get_ports {pin_J3}]"

# Helper functions for colored output:
def err(str):
   print("\033[101;97m" + str + "\033[0m")
def warn(str):
   print("\033[103;30m" + str + "\033[0m")
def ok(str):
   print("\033[102;30m" + str + "\033[0m")  

parser = argparse.ArgumentParser(description="Checks a bitstream for malicious attacker logic.")
parser.add_argument("infile", type=argparse.FileType("r"), nargs="?", help="Input bitstream file.")
parser.add_argument("--nc", default=False, action="store_true", help="Skip check for combinational cycles.")
parser.add_argument("--nf", default=False, action="store_true", help="Skip check for highest fanout nodes.")
parser.add_argument("--nd", default=False, action="store_true", help="Skip check for data-to-clock paths.")
parser.add_argument("--nt", default=False, action="store_true", help="Skip check for timing violations.")
parser.add_argument("--o", type=argparse.FileType("a+"), nargs="?", help="Report output file.")
parser.add_argument("--otex", type=argparse.FileType("a+"), nargs="?", help="Report latex table output file.")
args = parser.parse_args()

bitmap = args.infile.name # The input bitmap file
match = re.search("/([^/]+)\.bin", bitmap)
designname = match.group(1) # Filename without path and .bin
tmpdir = "./" + match.group(1) + "_tmp/" # Temporary directory name for an iCEcube project
shutil.rmtree(tmpdir, ignore_errors=True) # Remove any existing files in the temporary directory
os.mkdir(tmpdir) # (Re)Create the tmpdir
asc = tmpdir + match.group(1) + ".asc" # Filename for the .asc file (after iceunpack)
verilog = tmpdir + match.group(1) + ".v" # Filename for the .v file (after icebox_vlog)
verilog_fname = match.group(1) + ".v" # Filename without path for the project file
dot = tmpdir + match.group(1) + ".dot" # GraphViz file for structural evaluation
verilogfile = open(verilog, "w")
pcf = tmpdir + match.group(1) + ".pcf" # Placement constraint filename as reconstructed by the modified icebox_vlog
csv = tmpdir + match.group(1) + ".csv" # CSV graph file for import into graph_tool


start = time.time()

print("Unpacking bitstream...")

call(["iceunpack", bitmap, asc]) # Unpacking the .bin file into an .asc file

print("done!")

print("Generating verilog source...")

call(["icebox_vlog", "-k", "-c", "-l", "-s", "-S", "-g", "-O", "-o", pcf, asc], stdout=verilogfile) # Generating a verilog source file and a .pcf placement file from the unpacked bitmap
verilogfile.close()

# Here we get all input variables for each SB_LUT4 primitive to evaluate combinational loops later
# The modified icebox_vlog generates the LUT expressions in a way we can easily parse them
lut_inputs = dict() 
verilogfile = open(verilog, "r")
for line in verilogfile:
    if "SB_LUT4" in line:
        match = re.search("\s(n\d+)_inst", line)
        lut_out = match.group(1)
        match = re.search("// expr: (.+)$", line)
        if match:
            expr = match.group(1)
            lut_inputs[lut_out] = set(re.findall("\(([^\(]+)\)", expr))
verilogfile.close()

print("done!")

if not args.nd:
    # Check for data-to-clock paths which can be used to create shifted clock inputs for sensors or oscillation
    print("Checking for data-to-clock paths...")

    dtclock = False
    verilogfile = open(verilog, "r")
    verilogtxt = verilogfile.read()
    clockins = set(re.findall("\.C\(([^\)]+)\)", verilogtxt)) # Get all clock inputs to flip flops
    clocks = set(re.findall("\.PLLOUT(?:(?:GLOBAL)|(?:CORE))\(([^\)]+)\)", verilogtxt)) # Get all clocks
    clocks.add("pin_J3") # Add the board clock pin
    verilogfile.close()
    for ci in clockins:
        if ci not in clocks:
            dtclock = True
            break

    print("done!")
    print(str(clockins))
    print(str(clocks))
    if dtclock:
        err("Design has data-to-clock paths!")
    else:
        ok("Design has no data-to-clock paths!")

if not args.nc or not args.nf:
    # Here we generate a netlist graph from the verilog file using the modified yosys tool
    print("Generating graph...")

    call(["yosys", "-qq", "-p", "show -format dot -plain -prefix " + verilog[:-2], verilog])
    dotfile = open(dot, "r")
    csvfile = open(csv, "w")
    nodetype = dict()
    for line in dotfile: # The graphviz .dot file is converted into an edgelist csv file to be used with graph-tool
        if "->" in line:
            line = re.sub("\s\[.+\];", "", line)
            line = re.sub("\s->\s", ",", line)
            csvfile.write(line)
        else:
            match = re.match("([acnvx]\d+)\s.+label=\"([^\"]+)\"", line) # Find the node types (DFF/LUT)
            if match:
                nodetype[match.group(1)] = match.group(2)
    csvfile.close()
    g = load_graph_from_csv(csv)
    g.vp["type"] = g.new_vertex_property("string") # For each node(vertex) of the netlist graph we store its type as a property
    for v in g.vertices():
        g.vp["type"][v] = nodetype[g.vp["name"][g.vertex_index[v]]]

    print("done!\n")

if not args.nc:
    # The netlist graph is checked for combinational cycles and the detected cycles
    # are filtered for ineffective (non-oscillating) cycles using the lut_inputs data,
    # which we extracted from the verilog file earlier
    print("Checking for combinational cycles...")

    combprop, hist = topology.label_components(g)
    g.vp["component"] = combprop

    print("Found " + str(len(hist)) + " strongly connected components.")

    comp = dict()
    for v in g.vertices():
        if g.vp["component"][v] not in comp:
            comp[g.vp["component"][v]] = []
        comp[g.vp["component"][v]].append(v)
    combcycles = False
    num_cyc = 0
    for vs in comp.values():
        if (len(vs) > 1):
            combcycles = True
            for vi in vs:
                if g.vp["type"][vi].startswith("SB_DFF"):
                    # If the SCC contains a flip flop, it's not a combinational cycle
                    combcycles = False
                    break
                elif g.vp["type"][vi] in lut_inputs:
                    combcycles = False
                    for vj in vs:
                        if g.vp["type"][vj] in lut_inputs[g.vp["type"][vi]]:
                            # If we found a combinational cycle _and_ the outputs are actually relevant to the lut input, 
                            # then the cycle is potentially malicious
                            combcycles = True 
                            break                         
                if not combcycles:
                    break
            if combcycles:
                print(str(list(map(lambda v: g.vp["type"][v], vs))))
                num_cyc += 1

    print("done!\n")

    if num_cyc > 0:
        err("Design has %d combinational cycles!" % (num_cyc))
    else:
        ok("Design has no combinational cycles!")

if not args.nf:
    # With graph-tool we can determine the maximum out-degree (node fanout) in the netlist graph

    print("Analyzing graph degree...")

    ids = np.arange(g.num_vertices())
    degrees = g.get_out_degrees(ids)
    sids_degs = sorted(zip(ids, degrees), key=lambda x: x[1], reverse=True)
    warn("Five highest outdegree nodes: ")
    for i in range(min(5, g.num_vertices())):
        warn("Node: " + g.vp["name"][sids_degs[i][0]] + ", Outdegree: " + str(sids_degs[i][1]))

elapsed_nt = time.time() - start # Capture timing without iCEcube2 timing analysis

if not args.nt:    
    # For timing analysis we need to recompile the reversed design in iCEcube2.
    # Therefore, the project, constraint and .tcl files are created and we call
    # the synpwrap and tclsh tools from iCEcube2 to compile the design
  
    print("Analyzing timing...")

    prj = tmpdir + "tmp.prj"
    tcl = tmpdir + "tmp.tcl"
    sdc = tmpdir + "tmp.sdc"
    prjfile = open(prj, "w")
    tclfile = open(tcl, "w")
    sdcfile = open(sdc, "w")
    prjstr = re.sub("\$VFILE\$", verilog_fname, prjstr)
    prjstr = re.sub("\$TMPDIR\$", tmpdir[:-1], prjstr)
    tclstr = re.sub("\$TMPDIR\$", tmpdir[:-1], tclstr)
    tclstr = re.sub("\$PCFFILE\$", pcf, tclstr)
    prjfile.write(prjstr)
    tclfile.write(tclstr)
    sdcfile.write(sdcstr)
    prjfile.close()
    tclfile.close()
    sdcfile.close()

    call(["synpwrap", "-prj", prj])
    call(["tclsh", tcl])

    print("done!\n")

    # After compilation, the timing report from iCEcube2 in the
    # temporary directory is evaluated for timing violations.
    timing = tmpdir + "tmp/sbt/outputs/router/chip_timing.rpt"
    timingrpt = open(timing, "r")
    line = timingrpt.readline()
    while line != "" and "2::Clock Relationship Summary" not in line:
        line = timingrpt.readline()
    if line != "":
        line = timingrpt.readline()
        while "2::Clock Relationship Summary" not in line:
            line = timingrpt.readline()
        for _ in range(5):
            line = timingrpt.readline()
        match = re.match("([^\s]+)\s+([^\s]+)\s+([\.\-\d]+)\s+([\.\-\d]+)", line)
        timing_violation = False
        while match:
            slack = float(match.group(4))
            if slack < 0:
                timing_violation = True
            warn("Launch clock %s, Capture clock %s, Constraint %sps, Slack %sps" % (match.group(1), match.group(2), match.group(3), match.group(4)))
            line = timingrpt.readline()
            match = re.match("([^\s]+)\s+([^\s]+)\s+([\.\-\d]+)\s+([\.\-\d]+)", line)
    else:
        timing_violation = False
        warn("No clocks present!")

elapsed = time.time() - start # Capture the total elapsed time


# Print a summary of all findings:
print("Summary for " + bitmap + ":")
if not args.nd and dtclock:
    err("Design has data-to-clock paths!")
elif not args.nd:
    ok("Design has no data-to-clock paths!")

if not args.nc and num_cyc > 0:
    err("Design has %d combinational cycles!" % (num_cyc))
elif not args.nc:
    ok("Design has no combinational cycles!")

if not args.nf:
    warn("Highest fanout: " + g.vp["name"][sids_degs[0][0]] + ", Outdegree: " + str(sids_degs[0][1]))

if not args.nt and timing_violation:
    err("Design has timing violations!")
elif not args.nt:
    ok("Design has no timing violations!")
print("Time elapsed: " + str(elapsed) + "s")

if args.o is not None:
    # Append the output to a file (for batch processing of designs)
    outfile = open(args.o.name, "a+")
    outfile.write("Summary for " + bitmap + ":\n")
    if not args.nd and dtclock:
        outfile.write("Design has data-to-clock paths!\n")
    elif not args.nd:
        outfile.write("Design has no data-to-clock paths!\n")
    if not args.nc and num_cyc > 0:
        outfile.write("Design has %d combinational cycles!\n" % (num_cyc))
    elif not args.nc:
        outfile.write("Design has no combinational cycles!\n")

    if not args.nf:
        outfile.write("Highest fanout: " + g.vp["name"][sids_degs[0][0]] + ", Outdegree: " + str(sids_degs[0][1]) + "\n")
    
    if not args.nt and timing_violation:
        outfile.write("Design has timing violations!\n")
    elif not args.nt:
        outfile.write("Design has no timing violations!\n")
    outfile.write("Time elapsed without timing analysis: " + str(elapsed_nt) + "s\n")
    outfile.write("Time elapsed: " + str(elapsed) + "s\n\n")
    outfile.close()

if args.otex is not None:
    # Append the output as a latex table line
    outfile = open(args.otex.name, "a+")
    outfile.write(designname + " &\t\t\t \\(\\) & \t\t\t")
    outfile.write(("\\(" + str(num_cyc) + "\\)") if num_cyc > 0 else "\\(\\times\\)" + " &\t\t\t")
    outfile.write("\\checkmark" if dtclock else "\\(\\times\\)" + " &\t\t\t")
    outfile.write("\\(" + str(sids_degs[0][1]) + "\\)"  + " &\t\t\t")
    outfile.write("\\checkmark" if timing_violation else "\\(\\times\\)" + " &\t\t\t")
    outfile.write("\\(" + "{:10.2f}s".format(elapsed_nt) + "\\)"  + " &\t\t\t")
    outfile.write("\\(" + "{:10.2f}s".format(elapsed - elapsed_nt) + "\\)"  + "\\\\\n")
    outfile.close()

shutil.rmtree(tmpdir[:-1]) # Remove the temporary directory

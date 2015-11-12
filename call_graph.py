import idc
import idautils
import idaapi

import time
from sets import Set
import pydot

out_file = "call_graph.png"

def generate_graph():
	callees = dict()

	# Loop through all the functions in the binary
	for function_ea in idautils.Functions():

		f_name = GetFunctionName(function_ea)
		# For each of the incoming references
		for ref_ea in CodeRefsTo(function_ea, 0):
		
			# Get the name of the referring function
			caller_name = GetFunctionName(ref_ea)
			
			# Add the current function to the list of functions
			# called by the referring function
			callees[caller_name] = callees.get(caller_name, Set())

			callees[caller_name].add(f_name)
	return callees

#Visit functions called by our starting point recursively 
def walk_graph(g,seen,callees,start):
	if start in callees.keys() and start not in seen: #Who needs recursion?
		seen.add(start)
		next = callees[start]
		for i in next:
			g.add_edge(pydot.Edge(start, i))
			walk_graph(g,seen,callees,i)

start_time = time.time()			
print "---- Generating Callgraph ----"
# Create graph        
g = pydot.Dot(type='"digraph"')

# Set some defaults
g.set_rankdir('LR')
g.set_size('100,100')
g.add_node(pydot.Node('node', shape='ellipse', color='lightblue', style='filled'))
g.add_node(pydot.Node('edge', color='lightgrey'))

#Generate full control flow graph
callees = generate_graph()
seen = Set()
#walk the graph from start/main/_main/whatever so that only functions which are actually reachable are included
walk_graph(g,seen,callees,'start')
#write_ps to write postscript, write to write a dot file etc
g.write_png(out_file)
print("---- Callgraph complete - saved as: " + out_file +" ----")
print("---- Ran in: %s seconds ----" % (time.time() - start_time))
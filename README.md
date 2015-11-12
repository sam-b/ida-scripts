# ida-scripts
Dumping ground for whatever IDA Pro scripts I write.

##most_refs.py
Prints a list of the ten functions which are called by other functions the most.
![Screenshot](images/ref_count_list.PNG?raw=true)
##mem_complexity.py
Highlights functions which include a lot of control flow and calls to functions that are on Microsofts banned list (https://msdn.microsoft.com/en-us/library/bb288454.aspx),
this is designed as a very rough way of highlighting interesting functions - colors go Red to Blue for least to most interesting.
![Screenshot](images/mem_complex.PNG?raw=true)
##control_flow.py
Renders a .png from a dot graph of the Control Flow Graph of a binary - works by building a full graph of the binaries function calls and then walking the graph from the entry point,
in order to find all reachable function calls. Requires pydot and Grapviz to be installed.
![Screenshot](images/call_graph.png?raw=true)
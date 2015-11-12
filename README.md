# ida-scripts
Dumping ground for whatever IDA Pro scripts I write.

##most_refs.py
Prints a lot of the ten functions which are called by other functions the most.
![Screenshot](images/most_refs.png?raw=true)
##mem_complexity.py
Highlights functions which include a lot of control flow and calls to functions that are on Microsofts banned list (https://msdn.microsoft.com/en-us/library/bb288454.aspx),
this is just designed a very rough way of highlighting interesting functions - colors go Red to Blue for least to most interesting.
![Screenshot](images/mem_complex.png?raw=true)
##control_flow.py
Renders a dot graph png of the Control Flow Graph of a binary - works by building a full graph of the binary and then walking the graph from the entry point,
in order to find all reachable function calls. Requires pydot and Grapviz to be installed.
![Screenshot](images/control_flow.png?raw=true)
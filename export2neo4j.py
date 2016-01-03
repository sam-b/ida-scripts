import idc
import idautils
import idaapi
from py2neo import authenticate, Graph, Node, Relationship

neo_instance = "192.168.1.4:7474"
neo_username = "neo4j"
neo_password = "password"

authenticate(neo_instance,neo_username,neo_password)
neo = Graph("http://192.168.1.4:7474/db/data")
try:
	neo.schema.create_uniqueness_constraint("Function", "name")
except:
	pass
	
target = idaapi.get_root_filename()
for f in Functions():
	callee_name = GetFunctionName(f)
	callee = neo.merge_one("Function","name",callee_name)
	if target not in callee.labels:
		callee.labels.add(target)
		callee.push()
	for xref in XrefsTo(f):
		caller_name = GetFunctionName(xref.frm)
		if caller_name == '':
			print "Indirect call to " + callee_name + " ignored."
			continue
		caller = neo.merge_one("Function","name",caller_name)
		if target not in callee.labels:
			callee.labels.add(target)
			callee.push()
		caller_callee = Relationship(caller, "CALLS", callee)
		neo.get_or_create(caller_callee)
print "Export finished"
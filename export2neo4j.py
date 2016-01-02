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
	
def upload(self,ctx):
	target = idaapi.get_root_filename()
	for f in Functions():
		callee_name = GetFunctionName(f)
		callee = self.neo.merge_one("Function","name",callee_name)
		callee.labels.add(target)
		for xref in XrefsTo(f):
			caller_name = GetFunctionName(xref.frm)
			if caller_name == '':
				print "Indirect call to " + callee_name + " ignored."
				continue
			caller = self.neo.merge_one("Function","name",caller_name)
			caller.labels.add(target)
			caller_callee = Relationship(caller, "CALLS", callee)
			neo.create(caller_callee)
print "Export finished"
import idc
import idautils
import idaapi
from py2neo import authenticate, Graph, Node, Relationship

class UiAction(idaapi.action_handler_t):
    def __init__(self, id, name, tooltip, menuPath, callback):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.tooltip = tooltip
        self.menuPath = menuPath
        self.callback = callback

    def registerAction(self):
        action_desc = idaapi.action_desc_t(
        self.id,
        self.name,
        self,
        self.tooltip,
		)      
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        return True

    def unregisterAction(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        self.callback(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class neo4ida_t(idaapi.plugin_t):
	flags = 0
	comment = "Neo4j graph export and query interface"
	help = "Neo4j graph export and query interface"
	wanted_name = "Neo4IDA"
	wanted_hotkey = ""

	def init(self):
		authenticate("192.168.1.4:7474","neo4j","password")
		self.neo = Graph("http://192.168.1.4:7474/db/data")
		try:
			self.neo.schema.create_uniqueness_constraint("Function", "name")
		except:
			pass
		action = UiAction(
			id="neo4ida:upload",
			name="Upload",
			tooltip="Upload to neo4j",
			menuPath="Edit/neo4ida/",
			callback=self.upload,
		)
		if not action.registerAction():
			return 1
		action = UiAction(
			id="neo4ida:something",
			name="Something",
			tooltip="Something",
			menuPath="Edit/neo4ida/",
			callback=self.something,
		)
		if not action.registerAction():
			return 1
		return idaapi.PLUGIN_KEEP

	def term(self):
		return None

	def something(self,ctx):
		print "???"
		
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
				self.neo.create(caller_callee)

	def run(self):
		pass

def PLUGIN_ENTRY():
    return neo4ida_t()
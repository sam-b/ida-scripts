import json
import os
import time
import hashlib

import idc
import idautils
import idaapi

from idaapi import Form

from py2neo import authenticate, Graph, Node, Relationship

class ConnectionManagementForm(Form):
	def __init__(self,manager):
		self.manager = manager
		self.conf = manager.get_config()
		self.changed = False
		Form.__init__(self, 
			"""Neo4IDA - Manage Neo4j Connection
			{form_change}
			<#Host#~H~ost:{host}> <#Port#~P~ort:{port}>
			<#Username#~U~sername:{username}>
			<#Password#~P~assword:{password}>
			"""
			, {
				"form_change": Form.FormChangeCb(self.form_change),
				"host":Form.StringInput(swidth=20),
				"port":Form.StringInput(swidth=10),
				"username":Form.StringInput(swidth=40),
				"password":Form.StringInput(swidth=40)
			}
		)
		
		self.Compile()
		self.host.value = self.conf["host"]
		self.port.value = self.conf["port"]
		self.username.value = self.conf["username"]
		self.password.value = self.conf["password"]
		self.Execute()
	
	def form_change(self,fid):
		if fid == self.host.id:
			print "Hostname changed."
			tmp = self.GetControlValue(self.host)
			self.host.value = tmp
			self.changed = True
		if fid == self.port.id:
			print "Port changed"
			tmp = self.GetControlValue(self.port)
			self.port.value = tmp
			self.changed = True
		if fid == self.username.id:
			print "Username changed"
			tmp = self.GetControlValue(self.username)
			self.username.value = tmp
			self.changed = True
		if fid == self.password.id:
			print "Password changed"
			tmp = self.GetControlValue(self.password)
			self.password.value = tmp
			self.changed = True
		if fid == -2:
			print "OK button pressed"
			if self.changed:
				new_conf = {}
				new_conf['host'] = self.host.value
				new_conf['port'] = self.port.value
				new_conf['username'] = self.username.value
				new_conf['password'] = self.password.value
				self.manager.update_config(new_conf)
				self.conf = new_conf
				print "Config updated"
				self.manager.connect()
			self.Close(-1)

class CypherQueryForm(Form):
	def __init__(self,manager):
		self.manager = manager
		self.conf = manager.get_config()
		self.changed = False
		Form.__init__(self, 
			"""Neo4IDA - Execute Cypher Query
			{form_change}
			<#Query#~Q~uery:{query}>
			<#Execute Query#~E~xecute:{executeButton}>
			"""
			, {
				"form_change": Form.FormChangeCb(self.form_change),
				"query":Form.StringInput(swidth=80),
				"executeButton":Form.ButtonInput(self.button_press)
			}
		)
		
		self.Compile()
		self.query.value = "START n=node(*) return n;"
		self.Execute()
	
	def form_change(self,fid):
		print fid
		if fid == self.query.id:
			query = self.GetControlValue(self.query)
			self.query.value = query
		if fid == -2:
			self.Close(-1)
	
	def button_press(self,fid):
		print self.query.value
		for i in self.manager.neo.cypher.execute(self.query.value):
			print i
			
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
        if not idaapi.attach_action_to_toolbar("AnalysisToolBar", self.id):
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
		self.conf_file = os.path.expanduser("~") + os.path.sep + "neo4ida.json"
		config = self.get_config()
		if not config:
			config = self.create_default_config()
		self.connect()
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
			id="neo4ida:dropdb",
			name="Drop Database",
			tooltip="Delete all entries in database instance.",
			menuPath="Edit/neo4ida/",
			callback=self.drop_db,
		)
		if not action.registerAction():
			return 1
		action = UiAction(
			id="neo4ida:config",
			name="Configure",
			tooltip="Configure neo4j connection details.",
			menuPath="Edit/neo4ida/",
			callback=self.config_form,
		)
		if not action.registerAction():
			return 1
		action = UiAction(
			id="neo4ida:query",
			name="Cypher Query",
			tooltip="Execute a Cypher query.",
			menuPath="Edit/neo4ida/",
			callback=self.query_form,
		)
		if not action.registerAction():
			return 1
		action = UiAction(
			id="neo4ida:browser",
			name="Neo4j Browser",
			tooltip="Open Neo4j browser.",
			menuPath="Edit/neo4ida/",
			callback=self.open_browser,
		)
		if not action.registerAction():
			return 1
		action = UiAction(
			id="neo4ida:diff",
			name="Binary Diff",
			tooltip="Open binary diffing interface.",
			menuPath="Edit/neo4ida/",
			callback=self.binary_diff,
		)
		if not action.registerAction():
			return 1
		return idaapi.PLUGIN_KEEP

		
	def connect(self):
		conf = self.get_config()
		authenticate(conf['host'] + ":" + conf['port'],conf['username'],conf["password"])
		try:
			self.neo = Graph("http://" + conf['host'] + ":" + conf["port"] + "/db/data")
		except:
			print "Failed to connect!"
	
	def term(self):
		return None

	def binary_diff(self,ctf):
		print "Open binary diffing interface"

	def drop_db(self,ctx):
		self.neo.cypher.execute("START n=node(*) detach delete n;")
		print "All database nodes and relationships deleted."
	
	def open_browser(self,ctx):
		self.neo.open_browser()
	
	def config_form(self,ctx):
		ConnectionManagementForm(self)
	
	def query_form(self,ctf):
		CypherQueryForm(self)
	
	def upload(self,ctx):
		start = time.time()
		func_count = 0
		bb_count = 0
		call_count = 0
		target = idaapi.get_root_filename()
		hash = idc.GetInputMD5()
		tx = self.neo.cypher.begin()
		insert_binary = "MERGE (n:Binary {name:{N},hash:{H}}) RETURN n"
		insert_func = "MERGE (n:Function {name:{N},start:{S},flags:{F}}) RETURN n"
		create_relationship = "MATCH (u:Function {name:{N}}), (r:Function {name:{M}}) CREATE (u)-[:CALLS]->(r)"
		create_contains = "MATCH (u:BasicBlock {start:{S}}), (f:Function {name:{N}}) CREATE (f)-[:CONTAINS]->(u)"
		self.neo.cypher.execute(insert_binary, {"N":target, "H":hash})
		self.neo.cypher.execute("CREATE INDEX ON :Function(start)")
		for f in Functions():
			callee_name = GetFunctionName(f)
			flags = get_flags(f)
			tx.append(insert_func, {"N": callee_name, "S":f, "F":flags})
			#callee = Node("Function",target,start=f,name=callee_name,flags=flags)
			#type = GetType(f)
			#args = get_args(f)
			#if not type:
			#	print args
			#if args:
			#	callee.properties['args'] = args
			#self.neo.create(callee)
			func_count += 1
		tx.process()
		tx.commit()
		#tx = self.neo.cypher.begin()
		for f in Functions():
			callee = self.neo.find_one("Function","start",f)
			fc = idaapi.FlowChart(idaapi.get_func(f))
			for block in fc:
				bb = Node("BasicBlock",start=block.startEA,end=block.endEA)
				self.neo.create(bb)
				bb_count += 1
				link = Relationship(callee, "CONTAINS", bb)
				self.neo.create_unique(link)
			#tx.process()
		#tx.commit()
		tx = self.neo.cypher.begin()
		for f in Functions():
			callee = self.neo.find_one("Function","start",f)
			callee_name = callee.properties['name']
			for xref in CodeRefsTo(f,0):
				caller_name = GetFunctionName(xref)
				if caller_name != '':
					tx.append(create_relationship,{"N":caller_name,"M":callee_name})
					call_count += 1
					#caller = self.neo.find_one("Function","name",caller_name)
					#caller_callee = Relationship(caller, "CALLS", callee)
					#self.neo.create_unique(caller_callee)
		tx.process()
		tx.commit()
		print "Upload ran in: " + str(time.time() - start)
		print "Uploaded " + str(func_count) + " functions, " + str(call_count) +" function calls and " + str(bb_count) + " basic blocks."
	
	def run(self):
		pass
	
	def update_config(self,new_config):
		print "updating config to be " + json.dumps(new_config)
		os.remove(self.conf_file)
		with open(self.conf_file,"w+") as f:
			f.write(json.dumps(new_config))
	
	def create_default_config(self):
		default_conf = {
			"host": "localhost",
			"port": "7474",
			"username":"neo4j",
			"password":"neo4j"
		}
		with open(self.conf_file,"w+") as f:
			f.write(json.dumps(default_conf))
		return default_conf
	
	def get_config(self):
		try:
			with open(self.conf_file,"r") as f:
				return json.loads(f.read())
		except:
			return None

	def find_path(self,startFunc, endFunc):
		all_paths = ""
		print "Finding all paths from " + startFunc + " to " + endFunc
		self.neo.cypher.execute(all_paths,{})
	
def help():
	print "Upload: upload graph to neo instance."

def get_args(f):
  local_variables = [ ]
  arguments = [ ]
  current = local_variables

  frame = idc.GetFrame(f)
  arg_string = ""
  if frame == None:
    return None
        
  start = idc.GetFirstMember(frame)
  end = idc.GetLastMember(frame)
  count = 0
  max_count = 10000
  args_str = ""     
  while start <= end and count <= max_count:
    size = idc.GetMemberSize(frame, start)
    count = count + 1
    if size == None:
      start = start + 1
      continue

    name = idc.GetMemberName(frame, start)  
    start += size
            
    if name in [" r", " s"]:
      # Skip return address and base pointer
      current = arguments
      continue
    arg_string += " " + name
    current.append(name)
  if len(arguments) == 0:
    arguments.append("void")
  return arguments	

def get_flags(f):
	out = []
	flags = idc.GetFunctionFlags(f)
	if flags & FUNC_NORET: 
		out.append("FUNC_NORET")
	if flags & FUNC_FAR: 
		out.append("FUNC_FAR")
	if flags & FUNC_LIB: 
		out.append("FUNC_LIB")
	if flags & FUNC_STATIC: 
		out.append("FUNC_STATIC")
	if flags & FUNC_FRAME: 
		out.append("FUNC_FRAME")
	if flags & FUNC_USERFAR:  
		out.append("FUNC_USERFAR") 
	if flags & FUNC_HIDDEN:
		out.append("FUNC_HIDDEN")
	if flags & FUNC_THUNK:  
		out.append("FUNC_THUNK")
	if flags & FUNC_LIB:
		out.append("FUNC_BOTTOMBP")
	return out
	
def PLUGIN_ENTRY():
    return neo4ida_t()
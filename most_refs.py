import idc
import idautils
import idaapi
saved_funcs = []
#iterate overall functions in the binary
for func in idautils.Functions():
	func_obj = idaapi.get_func(func)
	flags = func_obj.flags
	if flags & FUNC_LIB or flags & FUNC_THUNK: #skip library functions and stubs
		continue
	refs = idautils.CodeRefsTo(func, 0)
	ref_count = len(list(refs)) #get size of a generator expression
	if ref_count > 1: #if its only called once don't bother storing it
		saved_funcs.append((hex(func), idc.GetFunctionName(func), ref_count,func_obj.size()))

sorted_by_ref_count = sorted(saved_funcs, key=lambda saved_funcs: saved_funcs[2],reverse=True)
print "Most ref'd functions - names are clickable :)"
print "|Address		|Name		|Ref Count	|Length	|"
width = 69 #Genuine coincidence...
print "|" + "-" * width +"|"
for i in range(10):
	print "|%s\t|%s\t|%d\t\t|%d\t|"% sorted_by_ref_count[i]
print "|" + "-" * width +"|"
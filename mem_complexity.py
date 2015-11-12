import idc
import idautils
import idaapi
import colorsys

def pseudocolor(val, minval, maxval):
	# convert val in range minval..maxval to the range 0..120 degrees which
	# correspond to the colors red..green in the HSV colorspace
	h = (float(val-minval) / (maxval-minval)) * 120
	# convert hsv color (h,1,1) to its rgb equivalent
	# note: the hsv_to_rgb() function expects h to be in the range 0..1 not 0..360
	r, g, b = colorsys.hsv_to_rgb(h/360, 1., 1.)
	return int("%02X%02X%02X" % (int(round(r*200)), int(round(b*200)), int(round(g*200))),16)

start_time = time.time()
#Taken from https://msdn.microsoft.com/en-us/library/bb288454.aspx + standard interesting-ness
interesting_funcs = ['_memset','_free','_strcpy', '_strcpyA', '_strcpyW', '_wcscpy', '_tcscpy', '_mbscpy', '_StrCpy', '_StrCpyA', '_StrCpyW', '_lstrcpy', '_lstrcpyA', '_lstrcpyW', '_tccpy', '_mbccpy', '_ftcscpy', '_strncpy', '_wcsncpy', '_tcsncpy', '_mbsncpy', '_mbsnbcpy', '_StrCpyN', '_StrCpyNA', '_StrCpyNW', '_StrNCpy', '_strcpynA', '_StrNCpyA', '_StrNCpyW', '_lstrcpyn', '_lstrcpynA', '_lstrcpynW,strcat', '_strcatA', '_strcatW', '_wcscat', '_tcscat', '_mbscat', '_StrCat', '_StrCatA', '_StrCatW', '_lstrcat', '_lstrcatA', '_lstrcatW', '_StrCatBuff', '_StrCatBuffA', '_StrCatBuffW', '_StrCatChainW', '_tccat', '_mbccat', '_ftcscat', '_strncat', '_wcsncat', '_tcsncat', '_mbsncat', '_mbsnbcat', '_StrCatN', '_StrCatNA', '_StrCatNW', '_StrNCat', '_StrNCatA', '_StrNCatW', '_lstrncat', '_lstrcatnA', '_lstrcatnW', '_lstrcatn,sprintfW', '_sprintfA', '_wsprintf', '_wsprintfW', '_wsprintfA', '_sprintf', '_swprintf', '_stprintf', '_wvsprintf', '_wvsprintfA', '_wvsprintfW','_vsprintf', '_vstprintf', '_vswprintf', '_wnsprintf', '_wnsprintfA', '_wnsprintfW','_snwprintf', '_snprintf', '_sntprintf _vsnprintf', '_vsnprintf', '_vsnwprintf', '_vsntprintf', '_wvnsprintf', '_wvnsprintfA', '_wvnsprintfW', '_snwprintf', '_snprintf', '_sntprintf', '_nsprintf', '_wvsprintf', '_wvsprintfA', '_wvsprintfW', '_vsprintf', '_vstprintf', '_vswprintf', '_vsnprintf', '_vsnwprintf', '_vsntprintf', '_wvnsprintf', '_wvnsprintfA', '_wvnsprintfW', '_strncpy', '_wcsncpy', '_tcsncpy', '_mbsncpy', '_mbsnbcpy', '_StrCpyN', '_StrCpyNA', '_StrCpyNW', '_StrNCpy', '_strcpynA', '_StrNCpyA', '_StrNCpyW', '_lstrcpyn', '_lstrcpynA', '_lstrcpynW', '_fstrncpy', '_strncat', '_wcsncat', '_tcsncat', '_mbsncat', '_mbsnbcat', '_StrCatN', '_StrCatNA', '_StrCatNW', '_StrNCat', '_StrNCatA', '_StrNCatW', '_lstrncat', '_lstrcatnA', '_lstrcatnW', '_lstrcatn', '_fstrncat', '_strtok', '_tcstok', '_wcstok', '_mbstok', '_makepath', '_tmakepath', '_makepath', '_wmakepath', '_splitpath', '_tsplitpath', '_wsplitpath', '_scanf', '_wscanf', '_tscanf', '_sscanf', '_swscanf', '_stscanf', '_snscanf', '_snwscanf', '_sntscanf', '_itoa', '_itow', '_i64toa', '_i64tow', '_ui64toa', '_ui64tot', '_ui64tow', '_ultoa', '_ultot', '_ultow', '_CharToOem', '_CharToOemA', '_CharToOemW', '_OemToChar', '_OemToCharA', '_OemToCharW', '_CharToOemBuffA', '_CharToOemBuffW', '_IsBadWritePtr', '_IsBadHugeWritePtr', '_IsBadReadPtr', '_IsBadHugeReadPtr', '_IsBadCodePtr', '_IsBadStringPtr', '_gets', '_getts', '_gettws', '_CharToOem', '_CharToOemA', '_CharToOemW', '_OemToChar', '_OemToCharA', '_OemToCharW', '_CharToOemBuffA', '_CharToOemBuffW', '_alloca', '_alloca', '_ strlen', '_wcslen', '_mbslen', '_mbstrlen', '_StrLen', '_lstrlen', '_RtlCopyMemory', '_CopyMemory', '_wmemcpy', '_ChangeWindowMessageFilter']
jmps_x86 = ['jo', 'jno', 'js', 'jns', 'je', 'jz', 'jne', 'jnz','jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz']

targets = []
for func in idautils.Functions():
	jmp_count = 0
	int_count = 0
	func_obj = idaapi.get_func(func)
	flags = func_obj.flags
	if flags & FUNC_LIB or flags & FUNC_THUNK: #skip library functions and stubs
		continue
	dism_addr = list(idautils.FuncItems(func))
	line_count = len(dism_addr)
	for line in dism_addr:
		m = idc.GetMnem(line)
		if m == 'call':
			opnd = idc.GetOpnd(line, 0)
			if opnd in interesting_funcs:
				int_count += 1
		elif m in jmps_x86:
			jmp_count += 1
	if jmp_count > 0 and int_count > 0:
		complex = ((jmp_count + int_count) / float(line_count)) * 100
		targets.append((func,idc.GetFunctionName(func), line_count, jmp_count,int_count,complex))

targets = sorted(targets, key=lambda targets: targets[5],reverse=True)

min = targets[0][5]
max = targets[len(targets) - 1][5]

print("--- Ran in: %s seconds ---" % (time.time() - start_time))
print "------------------------------------------------------------------------------"
print "| Addr   | Name     | Line Count | JMP Count | Interesting Calls | Jmp/Int % |"
print "------------------------------------------------------------------------------"
for i in targets:
	print "|%8x|%10s|%12s|%11s|%19s|%11.2f|" % i
	start_ea = idaapi.get_func(i[0]).startEA
	color = pseudocolor(i[5],min,max)
	idc.SetColor(start_ea, idc.CIC_FUNC, color)
print "------------------------------------------------------------------------------"
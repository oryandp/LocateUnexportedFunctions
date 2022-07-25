import idc
import idaapi

def get_call_instructions(func_name):
	func_addr = idc.get_name_ea_simple(func_name)
	
	call_instructions = []
	for startea, endea in Chunks(func_addr):
			for line_ea in Heads(startea, endea):
				insn = ida_ua.insn_t()
				ida_ua.decode_insn(insn, line_ea)
				
				if insn.get_canon_mnem() == 'call':
					call_instructions.append(insn)
	
	return call_instructions

def get_calls_count(func_name, dest_func):
	calls = get_call_instructions(func_name)
	for i, call in enumerate(calls, 1):		
		func_addr = get_operand_value(call.ea, 0)  
		if func_addr == get_name_ea_simple(dest_func):
			return (i, len(calls))

	# return -1 to indicate the function is not found
	return (-1, len(calls)) 

def main():
	win_version = 'Win10_1903_x64'

	# funcs_to_search struct: [(caller, calee)]
	funcs_to_search = [('LdrLoadDll', 'LdrpLoadDll'),
						('LdrpLoadDll', 'LdrpLoadDllInternal'),
						('LdrpLoadDllInternal', 'LdrpProcessWork'),
						('LdrpProcessWork', 'LdrpSnapModule'),
						('LdrpSnapModule', 'LdrpDoPostSnapWork'),
						('LdrpDoPostSnapWork', 'LdrpHandleTlsData')]
	
	for caller_func, callee_func in funcs_to_search:
		callee_num, total_calls = get_calls_count(caller_func, callee_func)
		print('Function %s was found in function %s after %d/%d calls' % \
			(callee_func, caller_func, callee_num, total_calls))

main()		


import idc
import idaapi
import csv

win_versions = ["Win10_1507_x64", "Win10_1511_x64", "Win10_1607_x64", "Win10_1803_x64", "Win10_1809_x64", \
				 "Win10_1909_x64", "Win10_1903_x64", "Win10_20h1_x64", "Win10_20h2_x64"]

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

	return (-1, len(calls)) # -1 to indicate the function is not found

def main():
	win_version = idc.ARGV[1]
	output_path = idc.ARGV[2]

	idaapi.auto_wait()

	# funcs_to_search struct: [(caller, callee)]
	funcs_to_search = [('LdrLoadDll', 'LdrpLoadDll'),
						('LdrpLoadDll', 'LdrpLoadDllInternal'),
						('LdrpLoadDllInternal', 'LdrpProcessWork'),
						('LdrpProcessWork', 'LdrpSnapModule'),
						('LdrpSnapModule', 'LdrpDoPostSnapWork'),
						('LdrpDoPostSnapWork', 'LdrpHandleTlsData')]
	
	header_list = ['Caller Function', 'Callee Function']
	header_list += win_versions

	with open(output_path, 'r') as f:
		reader = csv.DictReader(f)
		rows = [row for row in reader]

	new_rows = []
	for caller_func, callee_func in funcs_to_search:
		callee_num, total_calls = get_calls_count(caller_func, callee_func)
		row_to_update = {}
		for row in rows:
			if row['Caller Function'] == caller_func and row['Callee Function'] == callee_func:
				row[win_version] = "' %d/%d '" % (callee_num, total_calls)
				row_to_update = row

		if row_to_update == {}:
			row_to_update = {'Caller Function': caller_func, 'Callee Function': callee_func, win_version: "' %d/%d '" % (callee_num, total_calls)}
		new_rows.append(row_to_update)

	with open(output_path, 'w', newline='') as f:	
		writer = csv.DictWriter(f, fieldnames=header_list, quoting=csv.QUOTE_ALL)
		writer.writeheader()
		writer.writerows(new_rows)

	# Ensure the database is not saved on exit
	idaapi.set_database_flag(idaapi.DBFL_KILL)
	idc.qexit(0)

main()		


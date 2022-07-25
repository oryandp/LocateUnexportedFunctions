import os
import idc
import idautils
import csv
from ast import literal_eval

def get_segments():
	segments = idautils.Segments()
	first_segment = idaapi.getseg(segments.__next__())
	for s in segments:
		seg = idaapi.getseg(s)
	last_segment = seg 
	
	return first_segment, last_segment

def find_byte_sequence(byte_seq):
	first_segment, last_segment = get_segments()
	dll_start_ea = first_segment.start_ea
	dll_end_ea = last_segment.end_ea
	
	return ida_search.find_binary(dll_start_ea, dll_end_ea, byte_seq, 16, ida_search.SEARCH_DOWN)
	
def search_function_by_byte_seq_and_offset(function_name, byte_seq, offset):
	seq_addr = find_byte_sequence(byte_seq)
	return seq_addr - offset == idc.get_name_ea_simple(function_name)

def update_results_in_csv(win_version, function_name, byte_seq, offset, result, output_path):
	header_list = ['Os Version', 'Byte Sequence', 'Offset', 'Result']
	with open(output_path, 'a', newline='') as f:
		dw = csv.DictWriter(f, delimiter=',', fieldnames=header_list)
		dw.writerows([{'Os Version': win_version, 'Byte Sequence': byte_seq, 'Offset': offset, 'Result': result}])

def main():
	win_version = idc.ARGV[1]
	is_64 = literal_eval(idc.ARGV[2])
	function_name = idc.ARGV[3]
	byte_seq = idc.ARGV[4]
	offset = int(idc.ARGV[5])
	output_path = idc.ARGV[6]

	idaapi.auto_wait()
	
	result = 'Found' if search_function_by_byte_seq_and_offset(function_name, byte_seq, offset) else 'Not Found'
	update_results_in_csv(win_version, function_name, byte_seq, offset, result, output_path)

	# Ensure the database is not saved on exit
	idaapi.set_database_flag(idaapi.DBFL_KILL)
	idc.qexit(0)

main()

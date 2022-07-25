import os
import idc
import idautils
import csv

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
	
def get_func_by_byteseq_and_offset(function_name, byte_seq, offset):
	seq_addr = find_byte_sequence(byte_seq)
	return seq_addr - offset == idc.get_name_ea_simple(function_name)

def get_offset(function_name, byte_seq):
	seq_addr = find_byte_sequence(byte_seq)
	if seq_addr == 0xffffffffffffffff:
		print('Byte sequence was not found')
		return -1 
	return seq_addr - idc.get_name_ea_simple(function_name)

def main():
	function_name = 'LdrpHandleTlsData'
	byte_seq = "74 33 44 8D 43 09"
	offset = 0x46
	
	result = get_func_by_byteseq_and_offset(function_name, byte_seq, offset) 
	print('Found' if result else 'Not Found')
	if not result:
		new_offset = get_offset(function_name, byte_seq)
		if new_offset != -1:
			print('Try with offset 0x%x' % new_offset)

main()

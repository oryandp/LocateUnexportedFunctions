import os
import csv
import subprocess
from time import sleep


# Config params:
IDA_DIR = r'C:\Program Files\IDA Pro 7.6'
DLLS_BASE_DIR = r'.\Ntdlls' # Update full path here
SCRIPTS_DIR = r'.\Scripts'  # Update full path here

# Scripts to run:
search_func_by_byteseq = os.path.join(SCRIPTS_DIR, '2_1_calc_byte_seq_and_offset_multiple.py')
search_func_by_func_calls = os.path.join(SCRIPTS_DIR, '3_2_get_calls_count_multiple.py')

ntdll_files_x64_first_method = [
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1507_x64.dll'), "Win10_1507_x64", True, "44 8D 43 09 4C 8D 4C 24 38", 0x43),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1511.dll'), "Win10_1511_x64", True, "44 8D 43 09 4C 8D 4C 24 38", 0x43),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1607.dll'), "Win10_1607_x64", True, "44 8D 43 09 4C 8D 4C 24 38", 0x43),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1803_x64.dll'), "Win10_1803_x64", True, "74 33 44 8D 43 09", 0x44), 
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1809_x64.dll'), "Win10_1809_x64", True, "74 33 44 8D 43 09", 0x44),  
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1903.dll'), "Win10_1903_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1909_x64.dll'), "Win10_1909_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h1.dll'), "Win10_20h1_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h2_x64.dll'), "Win10_20h2_x64", True, "74 33 44 8D 43 09", 0x46)] 

ntdll_files_x64_second_method = [
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1507_x64.dll'), "Win10_1507_x64", True, "48 8B 4B 30 66 39 79 6E 75 0C E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1511.dll'), "Win10_1511_x64", True, "48 8B 4B 30 66 39 79 6E 75 0C E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1607.dll'), "Win10_1607_x64", True, "48 8B 4B 30 66 39 79 6E 75 0C E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1803_x64.dll'), "Win10_1803_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11), 
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1809_x64.dll'), "Win10_1809_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11),  
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1903.dll'), "Win10_1903_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1909_x64.dll'), "Win10_1909_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h1.dll'), "Win10_20h1_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h2_x64.dll'), "Win10_20h2_x64", True, "48 8B 4F 38 66 39 71 6E 75 0B E8", 11)] 

ntdll_files_x64_third_method = [
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1507_x64.dll'), "Win10_1507_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1511.dll'), "Win10_1511_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1607.dll'), "Win10_1607_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1803_x64.dll'), "Win10_1803_x64", True), 
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1809_x64.dll'), "Win10_1809_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1903.dll'), "Win10_1903_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1909_x64.dll'), "Win10_1909_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h1.dll'), "Win10_20h1_x64", True),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h2_x64.dll'), "Win10_20h2_x64", True)] 


def run_script_for_all_ntdlls(script_path, ntdll_files, function_name, dll_name='ntdll', with_deref=False):
	output_dir = os.path.join(SCRIPTS_DIR, 'Output')
	
	# Create output files with headers
	if script_path == search_func_by_byteseq:
		if with_deref:
			output_file = '%s_%s_by_byteseq_with_deref.csv' % (dll_name, function_name)	   
		else:
			output_file = '%s_%s_by_byteseq.csv' % (dll_name, function_name)
		
		header_list = ['Os Version', 'Byte Sequence', 'Offset', 'Result']
		output_path = os.path.join(output_dir, output_file)	
		with open(output_path, 'w') as f:
			dw = csv.DictWriter(f, delimiter=',', fieldnames=header_list)
			dw.writeheader()
			
		for ntdll_path, win_version, is_x64, byte_seq, offset in ntdll_files:
			print(win_version)
			ida_filename = 'ida64.exe' if is_x64 else 'ida.exe'
			ida_path = os.path.join(IDA_DIR, ida_filename)
		
			subprocess.call([ida_path, '-A', '-S"{}" "{}" "{}" "{}" "{}" "{}" "{}" "{}"'.format(script_path, win_version, is_x64, function_name, byte_seq, offset, output_path, with_deref), ntdll_path])
			
	elif script_path == search_func_by_func_calls:
		output_file = '%s_%s_by_calls_count.csv' % (dll_name, function_name)
		output_path = os.path.join(output_dir, output_file)	
		
		header_list = ['Caller Function', 'Calee Function']
		dll_versions = [win_version for _, win_version, _ in ntdll_files]
		header_list += dll_versions

		with open(output_path, 'w', newline='') as f:
			dw = csv.DictWriter(f, delimiter=',', fieldnames=header_list)
			dw.writeheader()

		for ntdll_path, win_version, is_x64 in ntdll_files:
			print(win_version)
			ida_filename = 'ida64.exe' if is_x64 else 'ida.exe'
			ida_path = os.path.join(IDA_DIR, ida_filename)

			subprocess.call([ida_path, '-A', '-S"{}" "{}" "{}"'.format(script_path, win_version, output_path), ntdll_path])
		
		
def main():
	# First method params:
	###ntdll_files = ntdll_files_x64_first_method
	###script_to_run = search_func_by_byteseq
	###with_deref = False
	
	# Second method params:
	###ntdll_files = ntdll_files_x64_second_method
	###script_to_run = search_func_by_byteseq
	###with_deref = True
	
	# Third method params:
	ntdll_files = ntdll_files_x64_third_method
	script_to_run = search_func_by_func_calls
	with_deref = False
	
	print('Running script on multiple dlls...')
	run_script_for_all_ntdlls(script_to_run, ntdll_files, 'LdrpHandleTlsData', with_deref=with_deref)
	print("Done!")
	
main()
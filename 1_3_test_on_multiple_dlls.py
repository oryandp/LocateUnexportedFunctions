import os
import csv
import subprocess

# Config params:
IDA_DIR = r'C:\Program Files\IDA Pro 7.6'
DLLS_BASE_DIR = r'.\Ntdlls' # Update full path here
SCRIPTS_DIR = r'.\Scripts'  # Update full path here

# Scripts to run:
search_func_by_byteseq = os.path.join(SCRIPTS_DIR, '1_2_calc_byte_seq_and_offset_multiple.py')

ntdll_files_x64 = [
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1507_x64.dll'), "Win10_1507_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1511.dll'), "Win10_1511_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1607.dll'), "Win10_1607_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1803_x64.dll'), "Win10_1803_x64", True, "74 33 44 8D 43 09", 0x46), 
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1809_x64.dll'), "Win10_1809_x64", True, "74 33 44 8D 43 09", 0x46),  
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1903.dll'), "Win10_1903_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_1909_x64.dll'), "Win10_1909_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h1.dll'), "Win10_20h1_x64", True, "74 33 44 8D 43 09", 0x46),
(os.path.join(DLLS_BASE_DIR, r'64\ntdll_20h2_x64.dll'), "Win10_20h2_x64", True, "74 33 44 8D 43 09", 0x46)] 


def run_script_for_all_ntdlls(script_path, ntdll_files, function_name, dll_name='ntdll'):
	output_dir = os.path.join(SCRIPTS_DIR, 'Output')
	
	# Create output files with headers
	header_list = ['Os Version', 'Byte Sequence', 'Offset', 'Result']
	output_file = '%s_%s_by_byteseq.csv' % (dll_name, function_name)
		
	output_path = os.path.join(output_dir, output_file)	
	with open(output_path, 'w', newline='') as f:
		dw = csv.DictWriter(f, delimiter=',', fieldnames=header_list)
		dw.writeheader()
			
	for ntdll_path, win_version, is_x64, byte_seq, offset in ntdll_files:
		print(win_version)
		ida_filename = 'ida64.exe' if is_x64 else 'ida.exe'
		ida_path = os.path.join(IDA_DIR, ida_filename)
		
		subprocess.call([ida_path, '-A', '-S"{}" "{}" "{}" "{}" "{}" "{}" "{}"'.format(script_path, win_version, is_x64, function_name, byte_seq, offset, output_path), ntdll_path])				
		
def main():
	ntdll_files = ntdll_files_x64
	script_to_run = search_func_by_byteseq
	
	print('Running script on multiple dlls...')
	run_script_for_all_ntdlls(script_to_run, ntdll_files, 'LdrpHandleTlsData')
	print("Done!")
	
main()

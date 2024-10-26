# Basics
```
Stings:
"Alice" + "Bob" 			# AliceBob
"Alice" + " Bob" 			# Alice Bob
"Alice" * 3				# AliceAliceAlice
"Alice" + "!" * 10			# Alice!!!!!!!!!!
f'Some string {variable}'		# adding variable in string
sites = some_string.split(',')		# split the variable (string) into a list based on commas (,)


```

# file
```
# file
f = open("file_name", "r")
print(f.read())

f = open("demofile1.txt", "a")			# Append to an existing file
f.write("The file will include more text..")
f.close()

f = open("demofile2.txt", "w")			# Creating and writing to a new file
f.write("demofile2 file created, with this content in!")
f.close()


# using with - as
with open(file_path, 'r') as file:
	message = file.read()			# needs print()


```

# sys
```
sys.builtin_module_names		# returns the our modules/libraries
sys.modules				# returns every modules that we can use
'time' in sys.modules			# to see if we have the time module and can use it
import new.py
'new' in sys.modules
from new import *			# this helps us to only print the variable name instead of typing new.variable 
reload ( new )				# reload the imported module after brining any change to it

sys.platform				# returns the OS kind


```


# OS
```
import os

1. 
command = 'touch os-test.txt'
os.system(command)			# run the command, but doesn't give us a value back (see os1.py)
					# we my get the result on the terminal screen but not value back for script

2.
host = input('Host / IP Address to ping: ')
command = (f'ping -c 1 {host}')
response = os.popen(command).read()	# with popen we get a response back from OS and can parse or do actions on it
					# we can use different method instead of .read to convert the object to different format

print(response)

3.
directory = os.path.dirname(os.path.abspath(__file__))	# set the dir path to be the current dir
os.path.abspath(__file__)				# means the path that the current python file is located at

file_path = os.path.join(directory, file_name)		# .join() is used to combine both directory and file name for OS (now in a single variable) 

# Write/overwrite a file 
with open(file_path, 'w') as file:
	file.write('The OS Mudule is COOL')

4.
# This is more appropriate to use python functions instead of OS commands (if we have an option):
os.mkdir('test-dir')
os.rename('test-dir', 'not-test-dir')
os.rmdir('not-test-dir')

# scan anything in the directory and print the result 
result = os.scandir()			

for x in result:
	print(x)

5. 
command = (f'ping -c 1 {address}')
response = os.popen(command).read()			# ping errors will return in screen
response = os.popen(f'{command} 2> /dev/null').read()	# removes the error values from output

```

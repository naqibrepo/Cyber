# Variables
```bash
-----------------------
# best particle is to use lower case for variables 
# environment variables are uppercase (env)

myname="Jay"
echo $myname

-----------------------
# always use double-quotes for variables instead of single-quote

echo "Hello, my name is $myname."
echo "I'm $myage years old."

-----------------------
# execute commands

---
# this will run the command, capture the output, and store into the files variable
files=$(ls)				# $(ls) is a subshell, subshell allows you to run command in the background

echo "Today is: $(date)"		# run the date command from inside an string

---
# This will also run the command
command=ls
command=/usr/bin/ls			# better version
$command
```

===============================================================================

# Basic Math
```bash
-----------------------
# type "expr" before the expression to specify this is math operation
expr 9 + 2
expr 9 - 2
expr 9 / 2
expr 9 % 2				# remainder
expr 9 \* 2				# user the escape character for multiplication

-----------------------
num1=9
num2=2
expr $num1 + $num2			# have to have space before and after operation sign

-----------------------
# arithmetic expansion

myvar=1

while [ $myvar -le 10 ]
do 
        echo $myvar
        myvar=$(( $myvar +1 ))		# Similar to Augmented Assignment Operator in python
        sleep 0.5
done

-----------------------
even_or_odd() {
    if (( $1 % 2 == 0 ))
    then echo "Even"
    else echo "Odd"
    fi
}
```

===============================================================================

# Conditions
```bash
-----------------------
# Example

mynum=300

if [ $mynum -eq 200 ]
then
	echo "The condition is ture."
else
	echo "The variable does not equal to 200."
fi

-----------------------
-eq					# equal
-ne					# not equal
-gt					# greater than
-lt					# lower than
-ge					# greater than and equal
-le					# less than and equal

-----------------------
# square brackets "[  ]" needed if you are running the test command. 
# When we use if statement with [], we're actually using the test command
# man test

if [ ! $mynum -eq 200 ]			# reverse match (not)
if [ -f ~/myfile ]			# true if file exist, false if not
if [ -d ~/myfile ]			# true if directory exist, false if not
if command -v top			# true if the command top exist, false if not
```

===============================================================================

# Exit Code
```bash
-----------------------
# 0 = successful, other numbers = failure

echo $?					# see the exit code of the last executed command 

-----------------------
# exit code in pipeline

cat file.txt | grep hello | wc -l
echo "${PIPESTATUS[@]}"

-----------------------
command=$(ls ~/myFiles)
echo "The exit code for the command is: $?"

-----------------------
# you can exit the script anytime with or without an exit code

exit 500				# exit the script with the exit code of 5000
```

===============================================================================

# While Loop
```bash
#!/bin/bash

myvar=1

while [ $myvar -le 10 ]
do 
        echo $myvar
        myvar=$(( $myvar +1 ))		# Similar to Augmented Assignment Operator in python
        sleep 0.5
done
```

===============================================================================

# For Loop
```bash
-----------------------
!/bin/bash

for current_number in 1 2 3 4 5 6 7 8 9 10
do 
        echo $current_number
        sleep 1
done

echo "This is outside of the for loop."


-----------------------
# Loop over list

for current_number in {1..10}

-----------------------
# Loop over files

for file in logfiles/*.log
do
        tar -czvf $file.tar.gz $file
done
```

===============================================================================

# Data Streams
```bash
-----------------------
# Standard Output & Standard Error

# Standard Output: Output that is printed to the screen that is not an error.
# Standard output is designated by 1
# Standard Error: Output that is printed to the screen that is an error.
# Standard error is designated by 2
# & include both Standard Output & Standard Error

find /etc -type f 1> /dev/null		# Redirect the standard output to /dev/null (errors will be printed)
find /etc -type f > /dev/null		# If the number is not specified, it considered 1 (standard output)
find /etc -type f 2> /dev/null		# Redirect the standard error to /dev/null (output will be printed)
find /etc -type f &> file.txt		# Redirect both to file.txt (nothing will be displayed)
<command> 1>output.txt 2>errors.txt	# send output and errors to different files


-----------------------
# Standard Input: Get user's input

echo "Please enter you name:"
read myname				# input/read the user's input and store it into variable "myname"
echo "your name is: $myname"

---
# read

-p prompt shows a prompt before reading.
-a array stores words into an array.
-r stops backslash from acting as an escape character.

---
read name
echo "Hello, $name"

---
read -p "Enter your name: " name

---
read -a words
echo "${words[0]}"

read -p "List the words: " -a words
echo "${words[*]}"

---
read -r line

---
# If you do not give any variable names, the input goes into REPLY.

read
echo "$REPLY"

```

===============================================================================

# Functions
```bash
# Define a function
add_numbers() {
    result=$((5 + 3))
    echo "The result is: $result"
}

# Call the function
add_numbers
```

===============================================================================

# Arguments
```bash

# Arguments are passed to the script during the runtime
# The are represented as variable inside the function
# The variable for each argument is represented with $<number of the passed argument>
# $1: first argument, $2: second argument ...
# $#: the total number of passwd argument

-----------------------
# Example

# call the script: ./myscript.sh Linux Book Study Gym
echo "You entered the argument: $1, $2, $3, and $4."

-----------------------
lines=$(ls -lh $1 | wc -l)

if [ $# -ne 1 ]					# if the total amount of passed arguments are not equal to 1
then
	echo "This script requires exactly one directory path passwd to it."
	echo "Please try again."
	exit 1
fi

echo "You have $(($lines-1)) objects in the $1 directory."
```

===============================================================================

# Case Statements
```bash
#!/bin/bash

echo "Enter a day:"
read day

case $day in						# do the action in front of the matching case ($day)
  "Monday") echo "Start of the work week";;
  "Friday") echo "End of the work week";;
  "Saturday" | "Sunday") echo "It's the weekend!";;
  *) echo "It's a regular weekday";;
esac
```

===============================================================================

# Script Storage & PATH
```bash
# place the script in /usr/local/bin

# if multiple users needs to access the same script, we can store it in a directory listed in PATH 
# give the script proper ownership and permission first
# if required to run by sudo then chown it to root

sudo cp myscript /usr/local/bin/			

-----------------------
which <command>				# prints the first path to the command

-----------------------
# PATH

# PATH is an environment variable in Linux that stores PATH to executables separated by colon (:)
# When typing a command, Linux checks the paths listed in the variable one by one and run the first executable that matches the name
# We can add our append or prepend out path the variable

export PATH=$PATH:/path/to/script                               # append to PATH
export PATH=/path/to/script:$PATH                               # prepend to PATH
```

===============================================================================

# Operators
```bash
-----------------------
&	This operator allows you to run commands in the background of your terminal.
&&	This operator allows you to combine multiple commands together in one line of your terminal.
>	take the output from a command (such as using cat to output a file) and direct it elsewhere. Overwrite.
>>	Appends the output rather than replacing (meaning nothing is overwritten).
<	redirect standard input to read from file
| 	redirect standard output to another command as standard input
||	or operator
```

===============================================================================

# Scheduling Jobs
```bash 
-----------------------
# at command

at 18:00 -f myscript.sh				# run the script at 6:00 PM today/tomorrow
at 18:00 052026 -f myscript.sh			# run it on 05/20/2026 at 6:00 PM
atq						# list the jobs in the que
atrm <id>					# remove the specific job

-----------------------
# cron

crontab -e					# create crontab for the logged in user
sudo crontab -u bob -e				# create crontab for bob
0 */12 * * * cp -R /home/cmnatic/Documents /var/backups/
|Min Hour Day Month Year [[command]]|
*/11	Every 11 hours
00 11	at 11 AM 
MIN	What minute to execute at
HOUR	What hour to execute at
DOM	What day of the month to execute at
MON	What month of the year to execute at
DOW	What day of the week to execute at [0 - 7], 0 and 7 are both for Sunday

example:
11 11 * * * /usr/bin/mkdir -p /home/jhammond/test			# create the test dir at 11:11 AM every day
```

===============================================================================

# Update Script
```bash    
#!/bin/bash

release_file=/etc/os-release

if grep -q "Arch" $release_file
then
        # The host is based on Arch, run the pacman update command
        sudo pacman -Syu
fi

if grep -q "Debian" $release_file || grep -q "Ubuntu" $release_file
then
        # Debian or Ubuntu,
        # Run the apt version of the command
        sudo apt udpate
        sudo apt dist-upgrade
fi
```



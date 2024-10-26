Logging


===============================================================================
# commands
```
log parsing

head -n 30
tail -n 20
sort				# alphabetic sort
sort -n				# numerical sort
sort -rn			# sort from large to small
uinq				# remove duplicates and list unique values
uniq -c				# count the number of unique values
wc -l				# count lines
grep "\"200 "			# list lines that contain "200 
grep -i				# case insensitive (uppercase, lowercase doesn't matter)
grep -E				# anything in a formula (use regexr.com to test), we can find formula for any value like IP and search for it
grep -A 10 -B 10 text		# -A: number of lines befor text, -B: number of lines after text
grep -C 10			# list 10 line after and before
grep -v				# Selects the non-matching lines of the provided

cat file.txt | grep -E "\/2[0-9][0-9] "		# list all lines that contain /2[any number][any number] (lines
						# that numbers from /200 to /299)
cat vsftpd.log | grep ftpuser | grep -i mkdir | head -n 1

awk '{print $6}'
awk '{print $1, $6}'
cut -d " " -f 1
cut -f 2,3
cat access.log | cut -d '"' -f3 | cut -d ' ' -f2 | sort | uniq -c | sort -rn

sed -nr 's/PPAPIService: Request: (.*)/\1/p' payments.log > requests.xml
sed -nr 's/PPAPIService: Response: <\?.*\?>(.*)/\1/p' payments.log > responses.xml
sed -nr 's/.*currencyID="USD">([0-9]+(\.[0-9]+)?).*/\1/p' requests.xml
sed -nr 's/.*StateOrProvince>([A-Za-z]+).*/\1/p' payments.log
```



===============================================================================
# sed

```
sed [options] commands [file-to-edit]
sed '' BSD				# cat BSD
cat BSD | sed ''

# sed operates on data line by line. It reads a line, operates on it, and outputs the resulting text before repeating the process on the next line.
sed 'p' BSD				# print each line twice on the screen
sed -n 'p' BSD				# avoids the automatic printing

sed -n '1p' BSD				# print the first line
sed -n '1,5p' BSD			# print line 1 to 5 (line range)
sed -n '1,+4p' BSD			# start at line 1 and then operate on the next 4 lines as well
sed -n '1~2p' BSD			# prints every other line (print line 1,3,5,7...), we can specify ~3 or ~4
sed '1,5d' BSD				# delete line 1 to 5 from the output and print other lines
sed '1~2d' BSD > everyother.txt

sed -i '1~2d' everyother.txt		# This will alter the source file, not only outputs on the screen
sed -i.bak '1~2d' everyother.txt	# creates a backup file with the .bak extension, and then edits the
					# original file in-place.
# Substituting Text
s/old_word/new_word/			# "s" is the substitute command and in this case slash / is the delimiter
					# but we can use different delimiter like _,-,+ or others for it
echo "http://www.example.com/index.html" | sed 's_com/index_org/home_'	# replaces com/index with org/home
sed 's/on/forward/' song.txt		# the "s" command operates on any first match (on, song, son) in a line
sed 's/on/forward/g' song.txt		# replace the all "on" in a line with "forward" not only the first one
sed 's/on/forward/2' song.txt		# replace only the second "on" in each line with "forward"
sed -n 's/on/forward/2p' song.txt	# print the substituted lines
sed 's/SINGING/saying/i' song.txt	# ignore case

# Replacing and Referencing Matched Text
sed 's/^.*at/REPLACED/' song.txt	# replace everything (from beginning of the line to "at") with REPLACED
sed 's/^.*at/(&)/' song.txt		# see what we are replacing in ()


# for the first match, replace any word that have the expression characters with escaped references:
sed 's/\([a-zA-Z0-9][a-zA-Z0-9]*\) \([a-zA-Z0-9][a-zA-Z0-9]*\)/\2 \1/' song.txt
# we create a match and then referce it by \1, \2, \3 etc.
# () : we create the match inside ()
# [a-zA-Z0-9] : one character
# [a-zA-Z0-9]* : any and multiple character
# \([a-zA-Z0-9][a-zA-Z0-9]*\) \([a-zA-Z0-9][a-zA-Z0-9]*\) : 
[one or any character that match with expression]space[same]
# \2 \1 : [escaped reference 2]space[escaped reference 1]

# for the first match, replace [any word]space[any word] with escaped references:
sed 's/\([^ ][^ ]*\) \([^ ][^ ]*\)/\2 \1/' song.txt
# [^ ] : any character that is not a space
# I think the [^ ] is not required here and only below can do the same:
sed 's/\([^ ]*\) \([^ ]*\)/\2 \1/' song.txt



sed 's/\(..\)/0x\1, /g' candata.txt			# put 0x in the first of each two each two characters
							# and put a comma and a space at the end of them
sed 's/\(.*\), /\1/' can2.txt				# remove the last comma and space of each line
sed 's/.*/[&]/' input_file				# put each line in a []


```

currencyID="USD"> 932.56

===============================================================================
# Splunk
```


# in search head --> source_file.format > host > index > field
source="VPN-logs-1663593355154.json" host="VPN_connection" index="vpn_logs" sourcetype="_json"  Source_ip="107.3.206.58"

data summary			# there is more info here

Field Sidebar:
Selected Fields			# default fields which appear in each event
Alpha-numeric fields 'α'
Numeric fields '#'

Search Processing Language (SPL)	# queries
|					# chaining commands
| fields + HostName - EventID		# show HostName and don't show EventID in the result
| search Powershell 			# search for the word Powershell
| table EventID User Image Hostname	# create a table with selective fields as columns
| dedup EventID				# remove the duplicates to show the unique values
index=windowslogs | table EventID User Image Hostname | dedup EventID
| rename User as Employees		# rename the field in the search result
index=windowslogs | fields + host + User + SourceIp | rename User as Employees
| reverse				# reverse event based on the latest time to current time
| head					# returns the first 10 events if no number is specified
| tail					# returns the last 10 events if no number is specified
| sort <field_name> 			# order the fields in ascending or descending order
| top limit=7 Hostname			# display the top 7 Hostnames that used more
| top Hostname				# top 10
| rare limit=7 Image			# opposite of top
| highlight User, host, EventID, Image	# highlight fields

stats:
Average					# stats avg(field_name)
Max					# stats max(field_name)	
Min					# stats min(field_name)
Sum					# stats sum(field_name)
Count 					# stats count(function) AS new_NAME

| chart count by User
| timechart count by Image


Linux:
server:
./splunk start --accept-license		# accepting the splunk license agreement and start it, set admin and pass
splunk start
splunk stop
splunk restart
splunk status
splunk add oneshot			# add a single event to the Splunk index
splunk search {word}
splunk help


forwarder:
Heavy Forwarders			# we can change and analyze logs before it forward them
Universal Forwarders			# simply forwards the logs

./splunk add forward-server 10.10.90.9:9997		# add the forwarder server, which listens to port 9997
./splunk add monitor /var/log/syslog -index Linux_host	# tell Splunk Forwarder to monitor the /var/log/syslog file, specify index
/opt/splunkforwarder/etc/apps/search/local/inputs.conf	# contains configurations for inputs, which define the data sources that the 
							# forwarder should monitor and forward to the Splunk instance
logger "test text"					# creating test log in syslog
logger -p auth.info "Test text"				# creating test log in auth.log


Windows:




```



===============================================================================
directories


/var/log/utmp - an access log that contains information regarding users that are currently logged into the system
/var/log/wtmp - an access log that contains information for all users that have logged in and out of the system


/etc/sudoers
/etc/group
/etc/passwd
/etc/gshadow
/etc/login.defs
/etc/pam.d or /etc/pam.conf

/etc/issue		# contains a message or system identification to be printed before the login prompt.
/etc/profile		# controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived
/proc/version		# specifies the version of the Linux kernel
/etc/passwd		# has all registered user that has access to a system
/etc/shadow		# contains information about the system's users' passwords
/root/.bash_history	# contains the history commands for root user
/var/log/dmessage	# contains global system messages, including the messages that are logged during system startup
/var/mail/root		# all emails for root user
/root/.ssh/id_rsa	# Private SSH keys for a root or any known valid user on the server
/var/log/apache2/access.log	# the accessed requests for Apache  webserver
C:\boot.ini		# contains the boot options for computers with BIOS firmware
c:\windows\win.ini	# 
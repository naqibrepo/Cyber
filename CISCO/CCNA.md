# CCNA


===============================================================================
# Basic Commands
```
enable                                       # enter privileged EXEC mode
configure terminal                           # enter global configuration mode
enable password <password>                   # configures a password to protect privileged EXEC mode
service password-encryption                  # encrypts the enable password (and other passwords)
enable secret <password>                     # configures a more secure, always-encrypted enable password
do <privileged-exec-level-command>           # executes a privileged-exec level command from global configuration mode
no <command>                                 # removes the command
show running-config                          # displays the current, active configuration file
show startup-config                          # displays the saved configuration file which will be loaded if the device is restarted
write                                        # saves the configuration
write memory                                 # saves the configuration
copy running-config startup-config           # saves the configuration
show running-config interface <name>		# view the running config for the specified interfaces

default interface <name>			# reset the interface to its default settings

arp -a 						# show arp table on Windows
```

===============================================================================
# Switch
```
show mac address-table				# show mac table
clear mac address-table dynamic			# clear all dynamic mac addresses on the table
clear mac address-table dynamic address 0c2f.b011.9d00
clear mac address-table dynamic interface Gi0/0

show ip interface brief				# (list): interface(name), ip, method, status, protocol(layer2 down or up)
show interfaces status				# port, name(desc), status, vlan, duplex(auto,a-full), speed(a-100,auto), type(10/100baseTX)
show interfaces <name>				# detailed info and errors
show interfaces <name> <option exp. [switchport]>	# show the interface option's info
conf t
int <name>
interface range f0/5 -12			# configure a range of interfaces at the same time
interface range f0/5 -6, f0/9 -12		# multi range
speed <100,auto>
duplex <auto,full,half>
desc <>

```
===============================================================================
# VLANs
```
------------------------------------------------------------------
show vlan brief					# list VLANs with brief info
interface range g1/0-3				# configure the range of interfaces
switchport mode access				# enable access mode of the ports (an access port belongs to single VLAN a connects to end host)
switchport access vlan 10			# assign the port/ports to VLAN 10 (it automatically creates VLAN 10 if doesn't exist)

---
vlan 10						# create new VLAN or enter to vlan 10 configs
name <VLAN new name>				# change the VLAN's name

---
# we can shutdown a vlan

------------------------------------------------------------------
# trunk port (can be used to carry traffics from multiple VLANs over a single interface)

conf t
int <name>
switchport trunk encapsulation <dot1q, isl, negotiate|auto|>		# set the trunk protocol (on old devices)
# For negotiate, if both switches have ISL, then they pick ISL instead of dot1q, use DTP for negotiation, DTP frames are sent in VLAN1 using ISL or native VLAN using 802.1Q (default native is VLAN1)
switchport mode trunk							# set the port/interface as a trunk port

switchport trunk allowed vlan <(VLAN ID), add, all, except, none, remove>	# set allowed VLANs when the port is trunking
switchport trunk native vlan 1001						# change the native VLAN to unsued vlan for security purposes

---
show interfaces trunk				# show trunk info

------------------------------------------------------------------
# ROAS (Router on a Stick): Route between multiple VLANs using a single interface (like trunk on switch and connects to trunk, sub-interfaces on router)

conf t
int <name>
interface g0/0.10				# setting ROAS protocol on port g0/0 for vlan 10 (creates sub-interfaces)
encapsluation dot1q <vlan id like 10>
ip address <ip> <sub net>

------------------------------------------------------------------
# Native VLAN

# Switch
switchport trunk native vlan 10						# for interface

# Router
1.
interface g0/0.10
encapsluation dot1q <vlan id like 10> native				# set native to vlan 10
ip address <ip> <vlan #>

2.
# Configure the IP address for the native VLAN on the router's physical interface (dot1q is not necessary)

------------------------------------------------------------------
# layer 3 (Multilayer) Switch

SVI (Switch Virtual Interfaces): V ints that you can assign IPs to in a multiyear switch. They are Default Getaways for vlans

---
default interface <name>			# reset the interface to its default settings 
ip routing					# enable layer 3 routing

---
int <name>
no switchport					# set port as routed port (layer 3), physical int acting as layer 3 port, normally connected to router
ip address <ip> <mask>

---
ip route 0.0.0.0 0.0.0.0 <ip of the next hope>		# configure the default route (to be the router ip)

---
show interfaces status				# see the status of the interfaces (port, name, status, vlan (id, trunk, routed), duplex, speed, type)

---
# Inter-VLAN Routing via SVI

conf t
interface vlan10
ip address <ip> <mask>
no shutdown					# SVIs are shutdown by default
interface vlan20
ip address <ip> <mask>
no shutdown
interface vlan30
ip address <ip> <mask>
no shutdown
```

===============================================================================
# DTP & VTP
```
------------------------------------------------------------------
DTP (Dynamic Trunking Protocol): dynamically determine interface status/mode (access or trunk)

switchport mode dynamic [auto/desirable]	# enable auto/desirable DTP on a port	
# desirable: actively try to form a trunk (other port = trunk, desirable, auto). default on old switches.
# auto: passive, not actively try to form a trunk, it will form a trunk if the connected port actively trying to form a trunk (other port = trunk, desirable). default on new switches.

switchport nonegotiate				# disable DTP:
switchport mode access				# disable DTP:

show interfaces <name> switchport		# show the interface switchport info

# switches can also use DTP to negotiate encapsulation type (802.1Q/ISL)
# For negotiate mode on encapsulation [default trunk mode is negotiate also (DTP), so encapsulation is negotiate too], if both switches have ISL, then they pick ISL instead of dot1q, use DTP for negotiation, DTP frames are sent in VLAN1 using ISL or native VLAN using 802.1Q (default native is VLAN1)

------------------------------------------------------------------
VTP (VLAN Trunking Protocol): Allows VTP servers and clients to synchronize their VLAN database
Versions: 1, 2, 3 (1,2 no extended VLANS, 1006 - 4094; 2 has token ring)
Modes:
- server (default): can modify VLANs, store VLANs database in non-volatile RAM (NVRAM), increase the "revision #", advertize latest revission on trunk, clients synchronize to it, also act as VTP client to sync to another server's changes; 
- client: cannot modify VLANs, don't store in NVRAM (V3 does), sync to server in their domain, advertise their VLAN database and forward VTP advertisements over trunk
- transparent: desn't participate in domain (not sync its database), store its own in NVRAM, can modify VLANs, won't advertise it own but will forward VTP ads that are in the same domain 

# if recives a VTP ad in the same domain with higher rev #, it will update it's VLAN database to match
# make rev # to 0: change domain name, set transparent mode

conf t
vtp domain <name>			# rename the vtp domain; if has no domain name and resive and ad with domain name, it will automatically join
vtp mode client/transparent		# configure the vtp mode
sh vtp status
```

===============================================================================
# STP
```
Port States: Blocking, Listening, Learning, Forwarding, Disabled
Port Roles: Root, Designated, Non-Designated

show spanning-tree			# stp protocol (ieee=stp, rstp=rapid pvst+), root info, bridge info, interfaces (port id)
show spanning-tree vlan 1
show spanning-tree detail
show spanning-tree summery		# summery of vlan's interfaces on stp
show spanning-tree interface <name> details					# STP details of the interface
spanning-tree mode <mst(multiple spanning tree), pvst, rapic-pvst)		# configure STP mode

---
# Manually Configure STP

# we can configure a different root bridge for different VLANs (load-balancing), on each VLAN different int will be disabled

spanning-tree vlan <VLAN #> root primary
# make the bridge to be the root/primary bridge on this VLAN
# If another switch has lower priority, this command will set the STP to 4096 less than the other switch's priority
# The actual command that runs is "spanning-tree vlan <VLAN #> priority <lowest priority # between switches>"

spanning-tree vlan <VLAN #> priority <priority #>
# set the bridge priority (in increments of 4096)

spanning-tree vlan <VLAN #> root secondary
# set secondary root bridge for that VLAN

---
STP port settings

spanning-tree vlan <VLAN #> cost <# like 200>
# change the path cost (root cost)

spanning-tree vlan <VLAN #> port-priority <priory number of the interface between 0-224 in the increments of 32>
# priority is the first half of the port id |default 128|


------------------------------------------------------------------
STP Options 

---
# portfast

# blew commands automatically adds the "edge" word (for edge portfast VS network portfast) 
int: spanning-tree portfast [edge]		# enable port fast for the int
int: spanning-tree portfast disable		# disable posrtfast on the int
conf: spanning-tree portfast [edge] default	# enable it on all access ports (not trunk ports)
int: spanning-tree portfast [edge] trunk	# enable port fast for the trunk port (for trunk connect to VMs Server, and ROAS)

---
# BPDU Guard 
int: spanning-tree bpduguard enable/disable
conf: spanning-tree portfast [edge] bpduguard default		# enable it on all portfast-enabled interfaces

# if BPDU Guard enable port receives BPDU, it will go to error-disable state and to turn it back on --> "shutdown", then "no shutdown"


## errdisable recovery: will automaticly re-enable port after certain period of time (300 sec), it is dissabled by default for bpduguard

show errdisable recovery					# show causes that put port in errdisable stat and their recovery status
errdisable recovery interval <seconds>				# change the time interval
errdisable recovery cause bpduguard 				# enable recovery for bpduguard errdisable ports

---
# BPDU Filter
# Doesn't disable port if recive BPDU, don't let the port to send BPDU

int: spanning-tree bpdufilter enable/disable
# don't send bpdu
# ignore any BPDUs it recieves
# (disable STP on port)

conf: spanning-tree portfast [edge] bpdufilter default
# all portfast enabled ports		
# if receives a BPDU, PortFast and BPDU Filter are disabled, and oprate as normal STP port

---
# Root Guard
# Prevents a port from becoming a Root Port by diabling it if superior BPDUs are received, thereby enforcing the current Root Bridge.

int: spanning-tree guard root

---
# Loop Guard
# blocking port after the port not receiving BPDU and Max Age is 0 (unidirectional link)
# should be enabled on root and non-designated ports

int: spanning-tree guard loop
int: spanning-tree guard none				# disable
conf: spanning-tree loopguard default			# enable on all port

---
# recommendations
1. enable portfast and PBDU Guard however you prefer (per-port or by default)
2. only enable BPDU Filter by default (global config mode) 			# it will ignore received bpdu if enabled per-port
3. loop guard and root guard can't be enabled on the same port (root guard prevents a designated port to become root, loop guard prevents a root or non-designated port to become designated. If one enabled on the port, another will be disabled.
4.

```

===============================================================================
# Rapid PVST+ (RSTP)
```
1. Port States: Discarding, Learning, Forwarding

2. Port Roles: 
Root, 
Designated, 
alternate (backup to the root port), 
backup: back up to designated port on same SW, receive superior BPDU from another interface on the same switch

3. Link States: Edge, Point-to-Point, Shared

UplinkFast: Imadiate move of of alternate port from blocking to forwarding state (imadiate moving is UplinkFast and also exist in clasic STP)
BackboneFast: Rapidly expire the Max Edge timer on Alternate/Non-designated port when it changing state to forwarding 

# edge: (move directly to forwarding state)
int: spanning-tree portfast

# Point-to-Point: (full duplex, SW-SW)
int: spanning-tree link-type point-to-point

# Shared: (half-duplex, SW-Hub)
int: spanning-tree link-type shared
```

===============================================================================
# Router
```
show ip interface brief				# (list): interface(name), ip, method, status, protocol(layer2 down or up)
show interfaces <name>				# detailed info and erros
show interfaces description			# (list): interface, status, protocol, description

conf t
default interface <name>			# reset the interface to its default settings
interface <int name>				# enter the interface config
interface range f0/5 -12			# configure a range of interfaces at the same time
interface range f0/5 -6, f0/9 -12		# multi range
ip address <ip address>	<subnet mask>		# assighn ip address
no shutdown 					# turn it on
description <DESCRIPTION>			# add description/comment 

---
(conf)# interface loopback <interface number>	# create a loopback interface (it's virtual)
(conf-if)# ip address 1.1.1.1 255.255.255.255	# configure loopback IP address

```

===============================================================================
# Static Routing
```
show ip route					# show the routing table
ip route <|network| ip> <net mask> <next-hop>	# create static route
ip route <|network| ip> <net mask> <exit interface>		# create a route that use ARP Proxy (direct connect)
ip route <|network| ip> <net mask> <exit interface> <next-hop>	# create static route

ip route 192.168.1.0 255.255.255.0 192.168.13.1			# next hop to 192.168.1.0/24 network is 192.168.13.1
ip route 192.168.4.0 255.255.255.0 192.168.34.4			# next hop to 192.168.4.0/24 network is 192.168.34.4
ip route 0.0.0.0 0.0.0.0 203.0.250.2				# default route (gateway of the last resort), |candidate default|

ip route <net address> <mask> <next-hop> <AD>			# change the Administrative Distance or Distance metric of a static route
```

===============================================================================
# RIP
```
(conf)# router rip						# go to configuring rip
(conf-router)# version 2					# enable rip v2
(conf-router)# no auto-summary					# if on, the router automatically converts the address to classful on advertisements 
(conf-router)# network 10.0.0.0					# enable it on interfaces that matches 10.0.0.0/8 (are in 10.*.*.*/*). (it is classful automatically but won't advertise it as classful to other routers, instead it advertise the routing table with their original mask)
(conf-router)# passive-interface g2/0				# stop sending RIP advertisements out of g2/0 (when it is not connected to neighbor)
(conf-router)# default-information originate			# share that I have a default gateway address
()# show ip protocols						# show routing protocols info
(conf-router)# maximum-paths					# maximum path for load balancing
(conf-router)# distance <#>					# set AD
```

===============================================================================
# EIGRP
```
(conf)# router eigrp 1						# go to EIGRP configs for Autonomous System (AS) 1 (AS should be same on all routers)
(conf-router)# no auto-summary					# if on, the router automatically converts the address to classful on advertisements
(conf-router)# passive-interface g2/0				# stop sending advertisements out of g2/0 (when it is not connected to neighbor)
(conf-router)# network 10.0.0.0					# enable it on interfaces that matches 10.0.0.0/8
(conf-router)# network 172.16.1.0 0.0.0.15			# we can use network with wildcard (subnet reverse)
(conf-router)# network 0.0.0.0 255.255.255.255			# enable EIGRP on all interfaces (not recommended on real network)
(conf-router)# distance <#>					# set AD
(conf-router)# eigrp router-id 1.1.1.1				# set the router's unique id which identifies it within the AS
(conf-router)# variance 2					# enable unequal load balancing (unique EIGRP option), this would load balance with any feasible successor route if their FD is lower or equal to "successor's feasible distance x 2" (UCLB)
()# show ip protocols						# show routing protocols info
()# show ip eigrp neighbors					# info about EIGRP and its configured interfaces
()# show ip eigrp topology					# also show routes the router received

wildcard = 255 - <subnet mask oct.>
0 in wildcard mask means the bits must match between the interface's IP address and the EIGRP network command.
Match:
interface IP: 10101100.*
network cmd:  10101000.*
wildcard: 00000111.*
```

===============================================================================
# OSPF
```
(conf)# router ospf <Process ID>				# routers with different process IDs can become OSPF neighbors (only locally significant)
(conf-router)# network <IP> <wildcard> area <area #>		# requires the area
(conf-router)# passive-interface g2/0				# stop sending OSPF 'hello' message out of g2/0 (when it is not connected OSPF to neighbor), but the router will still send LSAs to inform neighbors about the subnet configured on the interface
(conf-router)# passive-interface default			# turn all interfaces to passive mode by default
(conf-router)# default-information originate			# share that I have the default gateway address
(conf-router)# router-id 1.1.1.1				# set the router's unique id manually (need reload or clear)
(conf-router)# clear ip ospf process				# clear/reset the ospf (not recommended on active network unless necessary)
(conf-router)# maximum-paths <#>				# maximum path for load balancing 
(conf-router)# distance <#>					# set the AD to make it preferred over other routing protocols 
(conf-router)# shutdown	(no shutdown)				# shutdown and turn on the OSPF process

-----------------------
# OSPF calculate the cost/metric by: <reference bandwidth(100 Mb default)>/<interface bandwidth>
(conf-router)# auto-cost reference-bandwidth <Mb>		# change the reference bandwidth
(conf-if)# ip ospf cost <#>					# manually change the cost of an interface
(conf-if)# bandwidth <Kb>					# change the bandwidth of the interface to modify the cost (not recommended)

(conf-if-range)# ip ospf 1 area 0				# can enable it on range of interfaces directly
 
-----------------------
(conf-if)# ip ospf priority <#>					# change the OSPF interface priority (if 0, then can't be DR/BDR)
(conf-if)# ip ospf network <type>				# set the OSPF network type (p2p, broadcast, non-broadcast, p2m)
(conf-if)# ip ospf hello-interval <#>				# set the hello timer interval (default 10s)
(conf-if)# ip ospf dead-interval <#>				# set the dead timer interval (default 40s)
(conf-if)# no ip ospf <hello-interval, dead-interval, router-id>
(conf-if)# ip mtu <#> (no ip mtu)				# configure the MTU

#set OSPF password and enable authentication 
(conf-if)# ip ospf authentication-key <password>		# set the password (still need to enable authentication)
(conf-if)# ip ospf authentication 				# enable OSPF authentication

# HDCL encapsulation:
(conf-if)# clock rate <#>					# set clock rate on DCE on serial point to point interface (speed for ethernet)
(conf-if)# encapsulation <ppp/hdlc>				# set encapsulation type on serial connections (must much on both ends)
()# sh controllers s2/0						# show the DCE/DTE info on serial point to point

---
()# sh ip pro
()# sh ip ospf database						# show LSDB 
()# sh run | section ospf					# see running configs related to OSPF
()# sh ip ospf int <name>					# info about the ospf interface and its cost
()# sh ip ospf neighbor
()# sh ip ospf int brief
()# sh controllers s2/0						# show the DCE/DTE info on serial point to point
```
===============================================================================
# FHRP
```
# HSRP:

(conf-if)# standby version 2					# use HSRP version 2
(conf-if)# standby <group number (1)> ip <ip>			# set the VIP of the gateway on the group/vlan/subnet
(conf-if)# standby <group number (1)> priority <#>		# set a higher priority to make it Active router

# non-preemptive is default that don't allows the going back to previous state automatically once the state changed (keeps the new states)
(conf-if)# standby <group number (1)> preempt			# disables the default non-preempt, it allows the router to take the role of active router even if another router already has the role.

()# sh standby							# show HSRP details
```

===============================================================================
# Ether Channel (Port Channel, LAG/Link Aggregation)
```
show etherchannel load-balance					# show the load balancing method of ether channel
conf: port-channel load-balance <method>			# configure the load-balancing method for ether channel

int(range): channel-group 1 mode <auto, desirable, active, passive,  on>
# Create a channel-group (port channel) interface and join the physical interfaces to that
# PAgP: auto, desirable (auto+auto= no Ether-Channel)
# LACP: active, passive (passive+passive= no Ether-Channel)
# Static: on (only on+on)

int(range): channel-protocol <lacp, pagp>			# set the protocol for ether-channel

---
# configure the LAG (port channel)

# Layer 2 Ether-Channel
int(range): channel-group 1 mode <auto, desirable, active, passive,  on>
int/conf: interface port-channel 1
[switchport trunk encapsulation dot1q]
switchport mode trunk

# Layer 3 Ether-Channel
int range g0/0-3
no switchport
channel-group 2 mode active

int po2
ip address <ip> <sub>
---

show etherchannel summary					# displays a summary of EtherChannels on the switch
show etherchannel port-channel					# Displays information about the virtual port-channel interfaces on the switch
```

===============================================================================
# IPv6
```
()# sh ipv6 interface brief

(conf)# ipv6 unicast-routing					# allows router to perform IPv6 routing
(conf-if)# ipv6 address 2001:db8:0:0::1/64			# set ipv6 address on the interface


```
===============================================================================
# reset the switch
```
# Power off switch, hold MODE button, power on, release when LED blinks (ROMMON mode)
flash_init                                  # initialize flash
dir flash:                                  # check files in flash

del flash:config.text                       # delete startup config
del flash:private-config.text               # delete SSH keys / certs
del flash:vlan.dat                          # delete VLAN database
del flash:config.text.backup                # optional: delete config backup
del flash:private-config.text.backup        # optional: delete private-config backup
[delete /recursive /force flash:c2960x-universalk9-mz.152-4.E1   	# optional: delete old IOS folder]

boot [flash:c2960x-universalk9-mz.152-7.E4.bin]   			# boot into newest IOS

enable                                      		# enter privileged mode
configure terminal                          		# enter config mode
boot system flash:c2960x-universalk9-mz.152-7.E4.bin  	# set default IOS
end                                         		# exit config mode
write memory                                		# save boot variable
reload                                      		# reboot and verify clean boot
```
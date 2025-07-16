PFSense

===============================================================================
# Basics
```
- enable ssh
- add user
- disable ipv6 (system > networking, interfaces > WAN, DHCP V6 server, router advertisement on LAN, interfaces > LAN, disable ipv6 firewall rule that allows all)
- customize the dashboard (optional)
```
===============================================================================
# Firewall Considerations
```
Rules and Rulesets
Stateful Filtering
Block (silently drop, good for wan) or Reject (reject with a reply, good for LAN)
Ingress (out to in) and Egress (in to out)

- Firewall rules, filter the traffic that comes to interface (in) form its network. For example, the LAN interface, filter for traffic originated from lan, and DMZ interface filter for the traffic that originated from DMZ network. (rule on outbound traffic)

- floating rules:
Apply to multiple interfaces
Applies before interface rules
Can apply to in, out, or both directions. Interface rules only use in (from firewall perspective, or |input|)
Quick option: Allows you to stop further rule processing if one rule matches 
Advanced matching: Can filter based on packet state, direction, and interface all at once.


1. Create aliases (for group of things)
2. Add firewall rules

ICMP Allowed types: "3-destination unreachable", "8-ICMP Echo Request (ping)", "11-Time Exceeded", "12-Parameter Problem"

google quick: UDP 443
SPNs: TCP 5223

3. Use Separators
4. Backup before any major change
```
===============================================================================
# Packages
```
------------------------------------------------------------------
pfBlockerNG

Country_Block & IP_Blocklist
XMLRPC Sync
Dashboard Widget
Choice of what and how to block


------------------------------------------------------------------
Snort

- download the package
- select the rules
- update
- interfaces


------------------------------------------------------------------
Suricata

- IDS/IPS newer than snort
- Multi-threading
- IP Reputation
- Automatic Protocol Detection

very similar to snort

```
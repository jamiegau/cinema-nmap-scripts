local nmap = require "nmap"
local stdnse = require "stdnse"
local snmp = require "snmp"

description = [[
Detects socket fingerprint of NEC DCI cinema projector and flags if found.
Will attempt to pull out software and firmware version of system

Sockets required for scan, 21,22,80,7142,43728

Tool uses SNMP, OID for query data.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p21,22,80,1173,7142,43728 --script=cinema-nec-projector --script-args 'getcerts=true' <target>
-- @output
-- PORT    STATE SERVICE
-- to be create

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 80 and port  21, 22, 1173, 7142, 43728 are the right state, we try and query the target
portrule = function(host, port)
	if port.number ~= 80 then
		return false
	end

	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 and all these following ports are open, we can assume its a Dolby player
	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local dci = { number = 1173, protocol = "tcp" }
	local dci_open = nmap.get_port_state(host, dci)
	local necS1 = { number = 7142, protocol = "tcp" }
	local necS1_open = nmap.get_port_state(host, necS1)
	local necS2 = { number = 43728, protocol = "tcp" }
	local necS2_open = nmap.get_port_state(host, necS2)

	local res = false
	if ftp_open.state ~= 'open' and
		ssh_open.state ~= 'open' and
		dci_open.state ~= 'open' and
		(necS1_open.state == 'open' or necS2_open.state == 'open') then
		res = true
	end
	return res
end

-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil or s == false then
		return ''
	end
	s = tostring(s)
	return s:match("^%s*(.-)%s*$")
end

local function hexencode(str)
	return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

function get_snmp_IOD_value(host, port, iod)
	local res = ''

	local snmpHelper = snmp.Helper:new(host, port)
	snmpHelper:connect()

	local status, retvar = snmpHelper:get({ reqId = 28428 }, iod)
	if status == false then
		res = 'na'
	else
		res = all_trim(retvar[1][1])
	end

	return res
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	local getcerts = stdnse.get_script_args('getcerts')
	if getcerts == 'y' or getcerts == 'yes' or getcerts == 'true' then
		getcerts = true
	else
		getcerts = false
	end

	--
	--
	local snmp_port = { number = 161, protocol = "udp" }
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, version
	output.classification = 'dci-projector'
	output.vendor = 'NEC'
	--
	-- productName/vModelName / .1.3.6.1.4.1.119.2.3.123.1.13.0
	output.productName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.13.0')
	--
	-- serialNumber/vSerialNoPJ .1.3.6.1.4.1.119.2.3.123.1.12.1.0
	output.serialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.1.0')
	--
	-- vVerBIOS - .1.3.6.1.4.1.119.2.3.123.1.2.1.0
	local vVerBIOS = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.2.1.0')
	-- vVerFirm - .1.3.6.1.4.1.119.2.3.123.1.2.2.0
	local vVerFirm = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.2.2.0')
	-- vVerData - .1.3.6.1.4.1.119.2.3.123.1.2.3.0
	local vVerData = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.2.3.0')
	output.version = vVerBIOS .. ', ' .. vVerFirm .. ', ' .. vVerData
	output.vVerBIOS = vVerBIOS
	output.vVerFirm = vVerFirm
	output.vVerData = vVerData

	-- vSystemName .1.3.6.1.4.1.119.2.3.123.1.1.0
	output.vSystemName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.1.0')
	-- vHostName .1.3.6.1.4.1.119.2.3.123.1.16.1.7.0
	output.vHostName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.16.1.7.0')

	-- vSlotB .1.3.6.1.4.1.119.2.3.123.1.11.1.0
	output.vSlotB = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.11.1.0')
	-- vSlotA .1.3.6.1.4.1.119.2.3.123.1.11.2.0
	output.vSlotA = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.11.2.0')

	-- enigmaVersion .1.3.6.1.4.1.12612.220.11.1.2.18.0
	output.enigmaVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.18.0')

	-- vSerialNoEnigma .1.3.6.1.4.1.119.2.3.123.1.12.4.0
	output.vSerialNoEnigma = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.4.0')

	-- vVerPJ .1.3.6.1.4.1.119.2.3.123.1.12.5.0
	output.vVerPJ = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.5.0')

	-- vVerICP .1.3.6.1.4.1.119.2.3.123.1.12.7.0
	output.vVerICP = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.7.0')

	-- vVerICPLoginList .1.3.6.1.4.1.119.2.3.123.1.12.8.0
	output.vVerICPLoginList = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.8.0')

	-- vVerSIB .1.3.6.1.4.1.119.2.3.123.1.12.9.0
	output.vVerSIB = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.9.0')

	-- vVerEnigma .1.3.6.1.4.1.119.2.3.123.1.12.10.0
	output.vVerEnigma = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.119.2.3.123.1.12.10.0')

	return output
end

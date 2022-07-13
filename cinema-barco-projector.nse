local nmap = require "nmap"
local stdnse = require "stdnse"
local snmp = require "snmp"

description = [[
Detects socket fingerprint of Barco DCI cinema projector and flags if found.
Will attempt to pull out software and firmware version of system

Sockets required for scan, 21,22,80,1173,43680,43728
Port 43680 - S1
Port 43728 - S2

NOTE: not tested against Series4 projectors, very different API/socket implementation.

Tool uses SNMP, OID for query data.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p21,22,80,1173,43680,43728 --script=cinema-barco-projector --script-args 'getcerts=true' <target>
-- @output
-- PORT    STATE SERVICE
-- to be create

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe", "intrusive" }

-- if port 80 and port  21, 22, 1173, 43680, 43728 are the right state, we try and query the target
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
	local barcoS1 = { number = 43680, protocol = "tcp" }
	local barcoS1_open = nmap.get_port_state(host, barcoS1)
	local barcoS2 = { number = 43680, protocol = "tcp" }
	local barcoS2_open = nmap.get_port_state(host, barcoS2)


	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state == 'open' and
		dci_open.state == 'open' and
		(barcoS1_open.state == 'open' or barcoS2_open.state == 'open') then
		res = true
	end
	return res
end

-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil then
		return ''
	end
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

	local snmp_port = { number = 161, protocol = "udp" }
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, version
	output.classification = 'dci-projector'
	output.vendor = 'Barco'
	--
	-- productName / .1.3.6.1.2.1.1.1.0
	output.productName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.1.0')
	--
	-- serialNumber .1.3.6.1.4.1.12612.220.11.2.2.1.0
	output.serialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.1.0')
	--
	-- tiPackageVersion - .1.3.6.1.4.1.12612.220.11.1.2.12.0
	local tiPackageVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.12.0')
	-- tiSerialNumber - .1.3.6.1.4.1.12612.220.11.1.2.16.0
	local tiSerialNumber = hexencode(get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.16.0'))
	output.version = tiPackageVersion
	output.tiPackageVersion = tiPackageVersion
	output.tiSerialNumber = tiSerialNumber

	-- enigmaVersion .1.3.6.1.4.1.12612.220.11.1.2.18.0
	output.enigmaVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.18.0')

	-- enigmaSerialNumber .1.3.6.1.4.1.12612.220.11.1.2.19.0
	output.enigmaSerialNumber = hexencode(get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.19.0'))

	-- lampSerialNumber .1.3.6.1.4.1.12612.220.11.2.2.4.1.0
	output.lampSerialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.4.1.0')

	-- lampArticleNumber .1.3.6.1.4.1.12612.220.11.2.2.4.2.0
	output.lampArticleNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.4.2.0')

	-- location .1.3.6.1.2.1.1.6.0
	output.location = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.6.0')

	if getcerts then
		-- Proj Cert .1.3.6.1.4.1.12612.220.11.1.2.17.1.3.1
		local projectorCert = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.17.1.3.1')
		projectorCert = projectorCert:gsub("\x0D", "")
		output.projectorCert = projectorCert


		-- Link Decryptor Cert .1.3.6.1.4.1.12612.220.11.1.2.17.1.3.2
		local linkDecryptorCert = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.17.1.3.2')
		linkDecryptorCert = linkDecryptorCert:gsub("\x0D", "")
		output.linkDecryptorCert = linkDecryptorCert
	end

	return output
end

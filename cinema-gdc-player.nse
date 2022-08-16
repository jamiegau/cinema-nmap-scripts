local nmap = require "nmap"
local stdnse = require "stdnse"
local snmp = require "snmp"

description = [[
Detects socket fingerprint of GDC DCI cinema players and flags if found.
Will attempt to pull out software and firmware version of system

Sockets required for scan, 21,22,80,49153

Tool uses SNMP, OID for query data.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p21,22,80,49153 --script=cinema-gdc-player <target>
-- @output
-- PORT      STATE SERVICE
-- 21/tcp    open  ftp
-- 22/tcp    open  ssh
-- 80/tcp    open  http
-- | cinema-gdc-player:
-- |   classification: dci-player
-- |   vendor: GDC
-- |   productName: SA2100
-- |   serialNumber: A00871
-- |   version: OS-SA2K-2.0.74, 8.01-build300
-- |   osVersion: OS-SA2K-2.0.74
-- |   manufacturer: GDC Technology Ltd
-- |   motherboardVendor: Supermicro
-- |   motherboardProduct: C2SBC-Q 0123456789
-- |   biosVendor: Phoenix Technologies LTD
-- |   biosVersion: 1.1c
-- |   location: ChaintownCinema
-- |   auditoriumNo: 1
-- |   description: GDC D-cinema server
-- |   contactDetails: movie@chinatowncinema.com.au
-- |_  systemName: SA-2100
-- 49153/tcp open  unknown

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 80 and port  21, 22 and 49153 are open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 80 then
		return false
	end

	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 and all these following ports are open, we can assume its a Dolby player
	local cp1 = { number = 21, protocol = "tcp" }
	local cp1_open = nmap.get_port_state(host, cp1)
	local cp2 = { number = 22, protocol = "tcp" }
	local cp2_open = nmap.get_port_state(host, cp2)
	local cp3 = { number = 49153, protocol = "tcp" }
	local cp3_open = nmap.get_port_state(host, cp3)

	local res = false
	if cp1_open.state == 'open' and
		cp2_open.state == 'open' and
		cp3_open.state == 'open' then
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

--

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
	local snmp_port = { number = 161, protocol = "udp" }
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'dci-player'
	output.vendor = 'GDC'
	--
	-- GDC-DC-MIB::model.0 / .1.3.6.1.4.1.28713.1.1.1.0
	output.productName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.1.0')
	--
	-- serialNumber .1.3.6.1.4.1.28713.1.1.2.0
	output.serialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.2.0')
	--
	-- osVersion - .1.3.6.1.4.1.28713.1.1.3.0
	-- softwareVersion - .1.3.6.1.4.1.28713.1.1.4.0
	local osVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.3.0')
	local softwareVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.4.0')
	output.version = osVersion .. ', ' .. softwareVersion
	output.osVersion = osVersion

	-- manufacturer .1.3.6.1.4.1.28713.1.1.7.0
	output.manufacturer = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.7.0')

	-- motherboardVendor .1.3.6.1.4.1.28713.1.2.4.0
	output.motherboardVendor = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.2.4.0')

	-- motherboardProduct .1.3.6.1.4.1.28713.1.2.5.0
	output.motherboardProduct = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.2.5.0')

	-- biosVendor .1.3.6.1.4.1.28713.1.2.6.0
	output.biosVendor = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.2.6.0')

	-- biosVersion .1.3.6.1.4.1.28713.1.2.7.0
	output.biosVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.2.7.0')

	-- location .1.3.6.1.2.1.1.6.0
	output.location = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.6.0')

	-- auditoriumNo .1.3.6.1.4.1.28713.1.1.9.0
	output.auditoriumNo = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.28713.1.1.9.0')

	-- description .1.3.6.1.2.1.1.1.0
	output.description = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.1.0')

	-- contactDetails .1.3.6.1.2.1.1.4.0
	output.contactDetails = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.4.0')

	-- systemName .1.3.6.1.2.1.1.5.0
	output.systemName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.5.0')

	return output
end

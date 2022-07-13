local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects socket fingerprint of Dolby or Doremi DCI cinema players and flags if found.
Will attempt to pull out software and firmware version of system

Sockets required for scan, 21,22,80,5000,10000

Tool uses SNMP, OID for query data
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -p21,22,80,5000,10000 --script=cinema-dolby-player --script-args 'username=manager,password=password,getcerts=true' <target>
-- @output
-- PORT    STATE SERVICE
-- to be create

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe", "intrusive" }

-- if port 80 and port  21, 22, 5000 and 10000 are open, we try and query the system Doby Player
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
	local cp3 = { number = 5000, protocol = "tcp" }
	local cp3_open = nmap.get_port_state(host, cp3)
	local cp4 = { number = 10000, protocol = "tcp" }
	local cp4_open = nmap.get_port_state(host, cp4)

	local res = false
	if cp1_open.state == 'open' and
		cp2_open.state == 'open' and
		cp3_open.state == 'open' and
		cp4_open.state == 'open' then
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

local function soap_login_query(host, port, username, password)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SessionManagement'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://www.doremilabs.com/dc/dcp/ws/v1_0"><SOAP-ENV:Header/><ns0:Body><ns1:Login><username>'
		.. username .. '</username><password>' .. password .. '</password></ns1:Login></ns0:Body></SOAP-ENV:Envelope>'
	-- print(req)

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'Failed to Login, please supply username and password in arguments'
	end
	local sessionId = string.match(result['body'], "<sessionId>(.-)</sessionId>")
	return true, sessionId
end

--
local function soap_Hostname_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SystemInformation'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://www.doremilabs.com/dc/dcp/ws/v1_0" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><ns1:Body><ns0:GetHostname><sessionId>'
		.. sessionId .. '</sessionId></ns0:GetHostname></ns1:Body></SOAP-ENV:Envelope>'

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetHostname Failed'
	end

	local HostnameTable = {}
	HostnameTable['hostname'] = all_trim(string.match(result['body'], '<hostname>(.-)</hostname>'))
	HostnameTable['screenName'] = all_trim(string.match(result['body'], '<screenName>(.-)</screenName>'))
	return true, HostnameTable
end

--
local function soap_GetProductInformation_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SystemInformation'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://www.doremilabs.com/dc/dcp/ws/v1_0"><SOAP-ENV:Header/><ns0:Body><ns1:GetProductInformation><sessionId>'
		.. sessionId .. '</sessionId></ns1:GetProductInformation></ns0:Body></SOAP-ENV:Envelope>'

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetProductInformation Failed'
	end

	local ProdInfoTable = {}
	ProdInfoTable['productName'] = all_trim(string.match(result['body'], '<sys:productName>(.-)</sys:productName>'))
	ProdInfoTable['serialNumber'] = all_trim(string.match(result['body'], '<sys:serialNumber>(.-)</sys:serialNumber>'))
	ProdInfoTable['mainSoftwareVersion'] = all_trim(string.match(result['body'],
		'<sys:mainSoftwareVersion>(.-)</sys:mainSoftwareVersion>'))
	ProdInfoTable['mainFirmwareVersion'] = all_trim(string.match(result['body'],
		'<sys:mainFirmwareVersion>(.-)</sys:mainFirmwareVersion>'))
	return true, ProdInfoTable
end

--
local function soap_GetSoftwareInventoryList_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SystemInformation'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://www.doremilabs.com/dc/dcp/ws/v1_0" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><ns1:Body><ns0:GetSoftwareInventoryList><sessionId>'
		.. sessionId .. '</sessionId></ns0:GetSoftwareInventoryList></ns1:Body></SOAP-ENV:Envelope>'

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetSoftwareInventoryList Failed'
	end

	local SwInfoTable = {}
	local counter = 0
	for match_txt in (result['body']):gmatch '<sys:softwarePart>(.-)</sys:softwarePart>' do
		SwInfoTable[counter] = {}
		SwInfoTable[counter]['title'] = all_trim(string.match(match_txt, '<sys:title>(.-)</sys:title>'))
		SwInfoTable[counter]['type'] = all_trim(string.match(match_txt, '<sys:type>(.-)</sys:type>'))
		SwInfoTable[counter]['vendor'] = all_trim(string.match(match_txt, '<sys:vendor>(.-)</sys:vendor>'))
		SwInfoTable[counter]['version'] = all_trim(string.match(match_txt, '<sys:version>(.-)</sys:version>'))
		counter = counter + 1
	end

	return true, SwInfoTable
end

--
local function soap_GetHardwareInventoryList_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SystemInformation'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://www.doremilabs.com/dc/dcp/ws/v1_0"><SOAP-ENV:Header/><ns0:Body><ns1:GetHardwareInventoryList><sessionId>'
		.. sessionId .. '</sessionId></ns1:GetHardwareInventoryList></ns0:Body></SOAP-ENV:Envelope>'

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetHardtwareInventoryList Failed'
	end

	local HwInfoTable = {}
	local counter = 0
	for match_txt in (result['body']):gmatch '<sys:hardwarePart>(.-)</sys:hardwarePart>' do
		HwInfoTable[counter] = {}
		HwInfoTable[counter]['title'] = all_trim(string.match(match_txt, '<sys:title>(.-)</sys:title>'))
		HwInfoTable[counter]['type'] = all_trim(string.match(match_txt, '<sys:type>(.-)</sys:type>'))
		HwInfoTable[counter]['vendor'] = all_trim(string.match(match_txt, '<sys:vendor>(.-)</sys:vendor>'))
		HwInfoTable[counter]['version'] = all_trim(string.match(match_txt, '<sys:version>(.-)</sys:version>'))
		HwInfoTable[counter]['model'] = all_trim(string.match(match_txt, '<sys:model>(.-)</sys:model>'))
		HwInfoTable[counter]['serial'] = all_trim(string.match(match_txt, '<sys:serial>(.-)</sys:serial>'))
		HwInfoTable[counter]['status'] = all_trim(string.match(match_txt, '<sys:status>(.-)</sys:status>'))
		counter = counter + 1
	end

	return true, HwInfoTable
end

--
local function soap_GetCertificateList_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. '/dc/dcp/ws/v1/SystemInformation'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://www.doremilabs.com/dc/dcp/ws/v1_0"><SOAP-ENV:Header/><ns0:Body><ns1:GetCertificateList><sessionId>'
		.. sessionId .. '</sessionId></ns1:GetCertificateList></ns0:Body></SOAP-ENV:Envelope>'

	local result = http.post(host.ip, 80, path, nil, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetCertificateList Failed'
	end

	local CertInfoTable = {}
	local counter = 0
	for match_txt in (result['body']):gmatch '<sys:certificate>(.-)</sys:certificate>' do
		CertInfoTable[counter] = {}
		CertInfoTable[counter]['title'] = all_trim(string.match(match_txt, '<sys:title>(.-)</sys:title>'))
		CertInfoTable[counter]['cert'] = all_trim(string.match(match_txt, '<sys:cert>(.-)</sys:cert>'))
		-- Dropped adding the chain data as there appears to be a bug in that the full
		-- chain TEXT is nto returned byt the SOAP command.  Plus it is rearly used
		-- CertInfoTable[counter]['chain'] = all_trim(string.match(match_txt, '<sys:chain>(.-)</sys:chain>'))
		counter = counter + 1
	end

	return true, CertInfoTable
end

--

function TableConcat(t1, t2)
	for i = 1, #t2 do
		t1[#t1 + 1] = t2[i]
	end
	return t1
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	-- get command line username and password
	-- arguments, username, password, getcerts
	local username = stdnse.get_script_args('username')
	if username == nil then
		username = 'manager'
	end
	local password = stdnse.get_script_args('password')
	if password == nil then
		password = 'password'
	end
	local getcerts = stdnse.get_script_args('getcerts')
	if getcerts == 'y' or getcerts == 'yes' or getcerts == 'true' then
		getcerts = true
	else
		getcerts = false
	end
	--
	--
	local login_res, sessionId = soap_login_query(host, port, username, password)
	if not login_res then
		return sessionId
	end
	--
	-- Get Hostname
	local Hostname_res, HostnameTable = soap_Hostname_query(host, port, sessionId)
	if not Hostname_res then
		return HostnameTable
	end
	--
	-- Get basic information about device
	local ProdInfo_res, ProdInfoTable = soap_GetProductInformation_query(host, port, sessionId)
	if not ProdInfo_res then
		return ProdInfoTable
	end
	--
	-- Get GetSoftwareInventoryList
	local SwInfo_res, SwInfoTable = soap_GetSoftwareInventoryList_query(host, port, sessionId)
	if not SwInfo_res then
		return SwInfoTable
	end
	--
	-- Get GetSoftwareInventoryList
	local HwInfo_res, HwInfoTable = soap_GetHardwareInventoryList_query(host, port, sessionId)
	if not HwInfo_res then
		return HwInfoTable
	end
	--
	-- Get GetCertificateList
	local CertInfo_res
	local CertInfoTable
	if getcerts == true then
		CertInfo_res, CertInfoTable = soap_GetCertificateList_query(host, port, sessionId)
		if not CertInfo_res then
			return CertInfoTable
		end
	end

	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'dci-player'
	output.vendor = 'Dolby'
	output.productName = ProdInfoTable['productName']
	output.serialNumber = ProdInfoTable['serialNumber']
	output.version = ProdInfoTable['mainSoftwareVersion'] .. ', ' .. ProdInfoTable['mainFirmwareVersion']

	output.hostname = HostnameTable['hostname']
	output.screenName = HostnameTable['screenName']

	output.mainSoftwareVersion = ProdInfoTable['mainSoftwareVersion']
	output.mainFirmwareVersion = ProdInfoTable['mainFirmwareVersion']

	output.SoftwareInfo = SwInfoTable

	output.HardwareInfo = HwInfoTable

	if getcerts == true then
		output.CertInfo = CertInfoTable
	end

	return output
end

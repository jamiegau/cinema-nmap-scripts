local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"
local slaxml = require "slaxml"

description = [[
Detects socket fingerprint of Dolby or Doremi DCI cinema players and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- sudo nmap -sS -n -p 21,22,80,5000,8080,49155 --script cinema-qube-player --script-args 'getcerts=false' <target>
-- @output
-- PORT      STATE    SERVICE
-- 21/tcp    open     ftp
-- 22/tcp    filtered ssh
-- 80/tcp    open     http
-- 5000/tcp  open     upnp
-- 8080/tcp  open     http-proxy
-- | cinema-qube-player:
-- |   classification: dci-player
-- |   vendor: Qube
-- |   productName: XP-D
-- |   serialNumber: QXPD-01089-09-14
-- |   version: 3.0.1.23
-- |_  hardwareVersion: 1.5.0.0
-- 49155/tcp open     unknown

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- Check for the right port fingerprint of a Qube XP-D
portrule = function(host, port)
	if port.number ~= 8080 then
		return false
	end

	stdnse.debug("port is " .. port.state .. ", protocol is " .. port.protocol)
	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 and all these following ports are open, we can assume its a Dolby player
	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local p5000 = { number = 5000, protocol = "tcp" }
	local p5000_open = nmap.get_port_state(host, p5000)
	local p80 = { number = 80, protocol = "tcp" }
	local p80_open = nmap.get_port_state(host, p80)
	local p49155 = { number = 49155, protocol = "tcp" }
	local p49155_open = nmap.get_port_state(host, p49155)

	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state ~= 'open' and
		p5000_open.state == 'open' and
		p80_open.state == 'open' and
		p49155_open.state == 'open' then
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
local function soap_GetPlayerInfo_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. ':8080/services/Status'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://services.qubecinema.com/XP/Status/2012-07-01/" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><ns1:Body><ns0:GetPlayerInfo/></ns1:Body></SOAP-ENV:Envelope>'

	-- specifying headers
	local opt = {
		header = {
			["Content-Length"] = string.len(req),
			["Content-Type"] = 'text/xml; charset=utf-8',
			["SOAPAction"] = 'http://services.qubecinema.com/XP/Status/2012-07-01/IStatusService/GetPlayerInfo'
		}
	}

	local result = http.post(host.ip, 8080, path, opt, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetPlayerInfo Failed'
	end

	local GetPlayerInfoTable = {}
	GetPlayerInfoTable['productMake'] = all_trim(string.match(result['body'], '<a:Make>(.-)</a:Make>'))
	GetPlayerInfoTable['productName'] = all_trim(string.match(result['body'], '<a:Model>(.-)</a:Model>'))
	GetPlayerInfoTable['serialNumber'] = all_trim(string.match(result['body'], '<a:SerialNumber>(.-)</a:SerialNumber>'))
	GetPlayerInfoTable['softwareVersion'] = all_trim(
		string.match(result['body'], '<a:SoftwareVersion>(.-)</a:SoftwareVersion>')
	)
	GetPlayerInfoTable['hardwareVersion'] = all_trim(string.match(result['body'], '<a:Version>(.-)</a:Version>'))

	-- stdnse.pretty_printer(GetPlayerInfoTable)
	return true, GetPlayerInfoTable
end

--
local function soap_GetDeviceCertificate_query(host, port, sessionId)
	local path = 'http://' .. host.ip .. ':8080/services/Status'
	local req
	req = '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns0="http://services.qubecinema.com/XP/Status/2012-07-01/" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><ns1:Body><ns0:GetDeviceCertificate/></ns1:Body></SOAP-ENV:Envelope>'

	-- specifying headers
	local opt = {
		header = {
			["Content-Length"] = string.len(req),
			["Content-Type"] = 'text/xml; charset=utf-8',
			["SOAPAction"] = 'http://services.qubecinema.com/XP/Status/2012-07-01/IStatusService/GetDeviceCertificate'
		}
	}
	local result = http.post(host.ip, 8080, path, opt, nil, req)
	-- stdnse.pretty_printer(result)
	-- print('BODY: ' .. result['body'])
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'GetProductInformation Failed'
	end

	Cert = all_trim(string.match(result['body'], '<GetDeviceCertificateResult>(.-)</GetDeviceCertificateResult>'))

	return true, Cert
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
	local getcerts = stdnse.get_script_args('getcerts')
	if getcerts == 'y' or getcerts == 'yes' or getcerts == 'true' then
		getcerts = true
	else
		getcerts = false
	end
	--
	--
	--
	-- GetPlayerInfo
	local GetPlayerInfo_res, GetPlayerInfoTable = soap_GetPlayerInfo_query(host, port)
	if not GetPlayerInfo_res then
		return GetPlayerInfoTable
	end
	--
	-- Get GetDeviceCertificate
	local CertInfo_res
	local CertInfoTable
	if getcerts == true then
		CertInfo_res, CertInfoTable = soap_GetDeviceCertificate_query(host, port)
		if not CertInfo_res then
			return CertInfoTable
		end
	end

	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'dci-player'
	output.vendor = 'Qube'
	if GetPlayerInfoTable['productMake'] ~= "Qube" then
		output.vendor = 'Qube' .. '/' .. GetPlayerInfoTable['productMake']
	end

	output.productName = GetPlayerInfoTable['productName']
	output.serialNumber = GetPlayerInfoTable['serialNumber']
	output.version = GetPlayerInfoTable['softwareVersion']
	output.hardwareVersion = GetPlayerInfoTable['hardwareVersion']

	if getcerts == true then
		output.CertInfo = CertInfoTable
	end

	return output
end

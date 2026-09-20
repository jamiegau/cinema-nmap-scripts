local nmap = require "nmap"
local stdnse = require "stdnse"
local snmp = require "snmp"
local http = require "http"
local json = require "json"
local url = require "url"

description = [[
Identifies Barco DCI cinema projectors and reads model, serial and firmware.

Legacy S1/S2 ports: 21,22,80,1173,43680,43728. Series 4: 80 and/or 443.
Port 43680 - S1
Port 43728 - S2

Series 4 SP2K/SP4K: read-only REST identity queries on HTTP/HTTPS. HTTP may
upgrade to HTTPS on the same host. No login attempts or control commands are
sent by default. Optional credentials: cinema-barco-projector.username/password.

Legacy projectors use SNMP GET queries; Series 4 uses HTTP GET only.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p80,443 --script=cinema-barco-projector <target>
-- nmap -sS -p21,22,80,1173,43680,43728 --script=cinema-barco-projector --script-args 'getcerts=true' <target>
-- @args cinema-barco-projector.username Optional Series 4 REST username.
-- @args cinema-barco-projector.password Optional Series 4 REST password.
-- @output
-- PORT      STATE SERVICE
-- 21/tcp    open  ftp
-- 22/tcp    open  ssh
-- 80/tcp    open  http
-- | cinema-barco-projector:
-- |   classification: dci-projector
-- |   vendor: Barco
-- |   productName: DP2K-20C
-- |   serialNumber: 1190136617
-- |   version: 4.5.454
-- |   tiPackageVersion: 4.5.454
-- |   tiSerialNumber: 01d96e261a000085
-- |   enigmaVersion: P1.8(24)
-- |   enigmaSerialNumber: 860e1b4a0c06359d
-- |   lampSerialNumber: E914Wq158
-- |   lampArticleNumber: R9855937 OSRAM(R) XBO 4000W/DHP OFR
-- |   location: ChinetownC1
-- |   projectorCert: -----BEGIN CERTIFICATE-----
-- | MIIEzTCCA7WgAwIBAgIDAYVwMA0GCSqGSIb3DQEBCwUAMIGZMSkwJwYDVQQLEyBD
-- | QS02LkRMUC1DaW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNp
-- | bmVtYS5UZXhhc0luc3RydW1lbnRzMR8wHQYDVQQDExYuVGV4YXNJbnN0cnVtZW50
-- | cy5DQS42MSUwIwYDVQQuExxyNjNkNFdGdmhkc1dLMjBweTRaamV0a0lBZEk9MB4X
-- | DTE4MDIyNDE1MDM0NFoXDTQxMDIyNjAwMDAwMFowgaQxJDAiBgNVBAsTG0RMUC1D
-- | aW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNpbmVtYS5UZXhh
-- | c0luc3RydW1lbnRzMS8wLQYDVQQDEyZQUi5ETFAtQ2luZW1hLlNlcmllczIuMDFE
-- | OTZFMjYxQTAwMDA4NTElMCMGA1UELhMcOW40QW0xa1pzYnZxV2VDOHlWRXp3Tk0z
-- | b1pBPTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwcjQx7YFeNR9Hb
-- | +MISPpPCJnG16CpiBAe4Sa+zBA/OXqyR50SSdVZkG736ZR7l1zXSLc+17i+wPW1k
-- | 98pj6bDzGiu8Y91oJAWfMCUXZXloWCRMoyWT/5J7VFBVxZ5etxKIA+KTA/hqgW8e
-- | THAPG6DqeSUIGgxMRP3wl2A24U/QZjsft3D8v6QB36ngErJwkg+IGmUgglE0z+D4
-- | V6HKHTlz0TqitjXBM5dUlY7F4DKt1PIn+XMzJ4/EI3mFMr7N8tUS0NLLx6syvGqN
-- | flQh8eJelheqy3aFPRvDDpQ5JHtc7P0k90uswrWMQDdh2Zsr3HCIS2PLgL8rdGk+
-- | 973cBNcCAwEAAaOCAQ8wggELMIHOBgNVHSMEgcYwgcOAFK+t3eFhb4XbFittKcuG
-- | Y3rZCAHSoYGnpIGkMIGhMSQwIgYDVQQKExtETFAtQ2luZW1hLlRleGFzSW5zdHJ1
-- | bWVudHMxLDAqBgNVBAsTI1Jvb3QtQ0EuRExQLUNpbmVtYS5UZXhhc0luc3RydW1l
-- | bnRzMSQwIgYDVQQDExsuVGV4YXNJbnN0cnVtZW50cy5Sb290LUNBLjAxJTAjBgNV
-- | BC4THGZmQW1JdVdSenVuTVgrKzJuQmNnTDFpeXdHST2CAQcwHQYDVR0OBBYEFPZ+
-- | AJtZGbG76lngvMlRM8DTN6GQMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgSwMA0G
-- | CSqGSIb3DQEBCwUAA4IBAQCogIHREIdVpdQq5ULV+YBDc4XqEezm59pfol96NfjH
-- | MmPai9Hwg4x1QpneumkWdrJMxwRM8ok6FfIGcjrHyi+ZG6adeB3wZClgvDPso3ls
-- | ny+/r0xQ+ZpBTJe2MwmdkwCCsrmWONpAp//sXdcxZylYQGxtVNDvj6Y7PJ/HkLpH
-- | Pzk+QMm++AAOkMzl6qXSLkQWPPnKGPyEeLKSs7SBSY0P9EDSJZRefbe8MrL6ncTC
-- | Xg5RXDTlYWqGK19rulnbSuwbMKWk+0gEOFypOt122X1kmAMVrxagmbx6X1DJOBVH
-- | mD2KHaPFUoj9FTzNcJxdpBtIP+V+Y70kK+7D8nwi/RLe
-- | -----END CERTIFICATE----7
-- | -----END CERTIFICATE---
-- |   linkDecryptorCert: -----BEGIN CERTIFICATE-----
-- | MIIEzTCCA7WgAwIBAgIDAIt/MA0GCSqGSIb3DQEBCwUAMIGZMSkwJwYDVQQLEyBD
-- | QS02LkRMUC1DaW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNp
-- | bmVtYS5UZXhhc0luc3RydW1lbnRzMR8wHQYDVQQDExYuVGV4YXNJbnN0cnVtZW50
-- | cy5DQS42MSUwIwYDVQQuExxyNjNkNFdGdmhkc1dLMjBweTRaamV0a0lBZEk9MB4X
-- | DTEzMDkwNjAxMDIwOVoXDTQxMDIyNjAwMDAwMFowgaQxJDAiBgNVBAsTG0RMUC1D
-- | aW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNpbmVtYS5UZXhh
-- | c0luc3RydW1lbnRzMS8wLQYDVQQDEyZMRC5ETFAtQ2luZW1hLlNlcmllczIuODYw
-- | RTFCNEEwQzA2MzU5RDElMCMGA1UELhMcT1lFUEJXL3NYQkZQMVpLYlAyWHNLdFBx
-- | TkJvPTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANaAstK2m9YwsFLk
-- | Ii3uqX6eN8eULnVFuzAxmzkeO+2cN6WbSAzmM4Wu0mCzdJssHxnxUCbYhkJ71efb
-- | 8a4Hvj6SsmHSKet+v3xVuxYYqeMkvVJa1SWyAYxL27ZMcO1Qr6BMqCigfDLJYXFo
-- | 6AxQRI9E2FfHl8I0ejW1X0Rgy5GIbio4wGOvekfciK/WRf7M+4zQvriBCZhZKpAm
-- | 9nIt8wAdWX1OORuyGFfZTFfN/UeYoGFczLuMU/BbsH3JeSWKblPIyFQo2HChBp9J
-- | efoZwwomRcTDd9ucUKnFwqAfpc0GgUPF1y9lG16OTRYQWCuLmXjeqfTT7ejI3d7K
-- | wY2CWNMCAwEAAaOCAQ8wggELMIHOBgNVHSMEgcYwgcOAFK+t3eFhb4XbFittKcuG
-- | Y3rZCAHSoYGnpIGkMIGhMSQwIgYDVQQKExtETFAtQ2luZW1hLlRleGFzSW5zdHJ1
-- | bWVudHMxLDAqBgNVBAsTI1Jvb3QtQ0EuRExQLUNpbmVtYS5UZXhhc0luc3RydW1l
-- | bnRzMSQwIgYDVQQDExsuVGV4YXNJbnN0cnVtZW50cy5Sb290LUNBLjAxJTAjBgNV
-- | BC4THGZmQW1JdVdSenVuTVgrKzJuQmNnTDFpeXdHST2CAQcwHQYDVR0OBBYEFDmB
-- | DwVv7FwRT9WSmz9l7CrT6jQaMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgSwMA0G
-- | CSqGSIb3DQEBCwUAA4IBAQClp2XLcC9WS0BegmPkPewS8ADQBVFtXpc6RSTVWzlC
-- | 7I2njwVYg8m7lKGvSJN7vO3CABi5qhK5VB0dGy5YjxLDjdEcpRy5EFyq9jUXJFJ5
-- | Fxew5C9cskgGa6xyjiGnaeYALbMkapFLw7rcGp7f+P6myFIVb/iw4ApdovV35aqn
-- | u2edWrY22EUXN4fc99EoTNP+hBlSZiXIdt0MVEnQ44kYX/rLpfPJ/H4u7RGOTUJM
-- | fvi2Ce9mook9Sjah98DJ7Z4cPYr0ZnlqNWTDsSM9McuIqUhYUpGwHHk05FDs4RRq
-- | dEvTzLD3QBuc+uCD4/Mebc3Q8nt3gIvEgI85pvyq+Rm7
-- |_-----END CERTIFICATE---
-- 1173/tcp  open  d-cinema-rrp
-- 43680/tcp open  unknown
-- 43728/tcp open  unknown

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "discovery" }

local function port_open(host, number)
	local state = nmap.get_port_state(host, { number = number, protocol = "tcp" })
	return state ~= nil and state.state == "open"
end

local function legacy_fingerprint(host)
	return port_open(host, 21) and port_open(host, 22) and port_open(host, 1173)
		and (port_open(host, 43680) or port_open(host, 43728))
end

-- REST identification is safe on web ports; legacy SNMP is separately gated.
portrule = function(host, port)
	if port.number ~= 80 and port.number ~= 443 then
		return false
	end

	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- Run once when both ports were scanned. Positive REST identity, not the
	-- presence of a web server or a TI control port, determines the vendor.
	return port.number == 80 or not port_open(host, 80)
end

-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if type(s) ~= "string" and type(s) ~= "number" then
		return ''
	end
	return tostring(s):match("^%s*(.-)%s*$")
end

local function series4_identity(host, port)
	local rest_port = port
	local options = { timeout = 3000, max_body_size = 4096, redirect_ok = false }
	local username = stdnse.get_script_args('cinema-barco-projector.username')
	local password = stdnse.get_script_args('cinema-barco-projector.password')
	if username and password then
		options.auth = { username = username, password = password }
	end
	local function read_property(name)
		local path = '/rest/system/' .. name
		options.scheme = rest_port.number == 443 and 'https' or 'http'
		local response = http.get(host, rest_port, path, options)
		if response and rest_port.number == 80 and
			(response.status == 301 or response.status == 302 or response.status == 307 or response.status == 308) then
			local location = response.header and response.header.location
			local redirect = location and url.parse(location)
			-- Never follow off-host redirects or send supplied credentials elsewhere.
			if redirect and redirect.scheme == 'https' and redirect.host == host.ip
				and (redirect.port == nil or tonumber(redirect.port) == 443)
				and redirect.path == path and not redirect.userinfo and not redirect.query then
				rest_port = { number = 443, protocol = 'tcp', service = 'https' }
				options.scheme = 'https'
				response = http.get(host, rest_port, path, options)
			end
		end
		if not response or response.status ~= 200 or response.truncated
			or type(response.body) ~= 'string' then return nil end
		local ok, data = json.parse(response.body)
		if not ok or type(data) ~= 'table' or type(data.result) ~= 'string' then return nil end
		local value = all_trim(data.result)
		if value == '' then return nil end
		return value
	end
	local model = read_property('modelname')
	if not model or not model:match('^SP[24]K%-%d+[%w%-]*$') then return nil end
	local output = stdnse.output_table()
	output.classification = 'dci-projector'
	output.vendor = 'Barco'
	output.productName = model
	output.serialNumber = read_property('serialnumber')
	-- Catcher maps the common NSE "version" field to softwareVersion.
	output.version = read_property('firmwareversion')
	output.familyName = read_property('familyname')
	return output
end

local function hexencode(str)
	return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

function get_snmp_IOD_value(host, port, iod)
	local res = ''

	local snmpHelper = snmp.Helper:new(host, port, nil, { timeout = 2000 })
	local connected = snmpHelper:connect()
	local status, retvar
	if connected then status, retvar = snmpHelper:get({ reqId = 28428 }, iod) end
	if snmpHelper.socket then snmpHelper.socket:close() end
	if not status or type(retvar) ~= 'table' or type(retvar[1]) ~= 'table' then
		res = 'na'
	else
		res = all_trim(retvar[1][1])
	end

	return res
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	local identity = series4_identity(host, port)
	if identity then return identity end
	if not legacy_fingerprint(host) then return nil end
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

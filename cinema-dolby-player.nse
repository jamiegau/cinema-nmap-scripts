local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"
local slaxml = require "slaxml"

description = [[
Identifies Dolby/Doremi cinema players through read-only SystemInformation SOAP.
Reports Software, Firmware and Security Manager separately and in a labelled
version summary. SM is taken only from a named software-inventory entry, never
from a hardware revision or by assuming it matches the main software version.
Missing or conflicting SM information is explicitly reported as Not reported.
]]
author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "discovery" }

-- @usage
-- nmap -p21,22,80,5000,10000 --script=cinema-dolby-player TARGET
-- @args cinema-dolby-player.username SOAP login (default manager; legacy username accepted).
-- @args cinema-dolby-player.password SOAP password (legacy password accepted).
-- @args cinema-dolby-player.getcerts Include certificates (default false; legacy getcerts accepted).
-- @args cinema-dolby-player.soap-port Explicit SOAP port, bypassing the multi-port fingerprint.
-- @output
-- | cinema-dolby-player:
-- |   classification: dci-player
-- |   vendor: Dolby
-- |   productName: IMS2000
-- |   mainSoftwareVersion: 2.8.52
-- |   mainFirmwareVersion: 4.6.12
-- |   securityManagerVersion: 6.2.1
-- |_  version: Software: 2.8.52; Firmware: 4.6.12; SM: 6.2.1

local SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
local API = "http://www.doremilabs.com/dc/dcp/ws/v1_0"
local LIMIT = 262144

local function argument(name)
  return stdnse.get_script_args("cinema-dolby-player." .. name)
end

local function soap_port()
  local value = argument("soap-port")
  if value == nil then return 80 end
  if type(value) ~= "string" and type(value) ~= "number" then return nil end
  local number = tonumber(value)
  if number and number >= 1 and number <= 65535 and number % 1 == 0 then return number end
end

portrule = function(host, port)
  local number = soap_port()
  if not number or port.number ~= number or port.protocol ~= "tcp" or port.state ~= "open" then return false end
  if argument("soap-port") ~= nil then return true end
  for _, required in ipairs({21, 22, 5000, 10000}) do
    local state = nmap.get_port_state(host, {number=required, protocol="tcp"})
    if not state or state.state ~= "open" then return false end
  end
  return true
end

-- Parse expanded XML names instead of depending on the player's arbitrary
-- 'sys:' prefix. Reject incomplete documents, excessive depth and DTDs.
local function parse_xml(xml)
  if xml:find("<!DOCTYPE", 1, true) or xml:find("<!ENTITY", 1, true) then return nil end
  local root, stack, count = nil, {}, 0
  local parser = slaxml.parser:new({
    startElement = function(name, ns)
      count = count + 1
      assert(count <= 8192 and #stack < 24)
      local node = {name=name, ns=ns, children={}, text=""}
      if #stack == 0 then assert(root == nil); root = node
      else table.insert(stack[#stack].children, node) end
      stack[#stack + 1] = node
    end,
    closeElement = function(name, ns)
      local node = stack[#stack]
      assert(node and node.name == name and node.ns == ns)
      stack[#stack] = nil
    end,
    text = function(value)
      if #stack > 0 then stack[#stack].text = stack[#stack].text .. value
      else assert(value:match("^%s*$")) end
    end,
  })
  local ok = pcall(parser.parseSAX, parser, xml)
  if ok and #stack == 0 then return root end
end

local function child(node, name)
  local found
  for _, item in ipairs(node and node.children or {}) do
    if item.name == name then
      if found then return nil end
      found = item
    end
  end
  return found
end

local function scalar(node, limit)
  if not node or #node.children ~= 0 then return nil end
  local text = node.text:match("^%s*(.-)%s*$")
  if text == "" or #text > (limit or 100) or text:find("%c") then return nil end
  if text:lower() == "unknown" or text:lower() == "n/a" or text == "-" then return nil end
  return text
end

local function escape(text)
  return (tostring(text):gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
    :gsub('"', "&quot;"):gsub("'", "&apos;"))
end

local function query(host, number, service, operation, fields)
  local request = '<s:Envelope xmlns:s="' .. SOAP .. '" xmlns:d="' .. API .. '"><s:Body><d:' .. operation .. '>'
  for _, field in ipairs(fields) do
    request = request .. '<' .. field[1] .. '>' .. escape(field[2]) .. '</' .. field[1] .. '>'
  end
  request = request .. '</d:' .. operation .. '></s:Body></s:Envelope>'
  local ok, result = pcall(http.post, host, {number=number, protocol="tcp"},
    '/dc/dcp/ws/v1/' .. service, {
      timeout=5000, max_body_size=LIMIT, redirect_ok=false,
      header={['Content-Type']='text/xml; charset="utf-8"', SOAPAction='""'},
    }, nil, request)
  if not ok or not result or result.status ~= 200 or result.truncated
    or type(result.body) ~= "string" or #result.body > LIMIT then return nil end
  local root = parse_xml(result.body)
  if not root or root.name ~= "Envelope" or root.ns ~= SOAP then return nil end
  local body = child(root, "Body")
  if not body or body.ns ~= SOAP or #body.children ~= 1 then return nil end
  local response = child(body, operation .. "Response")
  if response and response.ns == API then return response end
end

local function inventory(response, list_name, entry_name, fields)
  local rows = {}
  local list = child(response, list_name)
  for _, entry in ipairs(list and list.children or {}) do
    if entry.name == entry_name then
      local row = {}
      for _, field in ipairs(fields) do row[field] = scalar(child(entry, field)) end
      rows[#rows + 1] = row -- Lua arrays start at one; don't lose the first part.
    end
  end
  return rows
end

local function sm_version(rows)
  local selected
  -- Doremi MIB/SNMP Description 000494 v1.2 names inventory #6
  -- 'MD software' and explicitly identifies its version as 'SM Version'.
  local labels = {mdsoftware=true, sm=true, securitymanager=true, securitymanagersm=true,
    smversion=true, smfirmware=true, smsoftware=true,
    securitymanagerversion=true, securitymanagerfirmware=true, securitymanagersoftware=true}
  for _, row in ipairs(rows) do
    local label = (row.title or ""):lower():gsub("[^%w]", "")
    label = label:gsub("^dolby", ""):gsub("^doremi", "")
    if labels[label] then
      -- Missing/conflicting entries cannot silently select another SM version.
      if not row.version or (selected and selected ~= row.version) then return nil end
      selected = row.version
    end
  end
  return selected
end

action = function(host, port)
  local number = soap_port()
  if not number then return nil end
  local username = argument("username") or stdnse.get_script_args('username') or 'manager'
  local password = argument("password") or stdnse.get_script_args('password') or 'password'
  local login = query(host, number, 'SessionManagement', 'Login', {{'username', username}, {'password', password}})
  local session = scalar(child(login, 'sessionId'), 512)
  if not session then return nil end
  local session_fields = {{'sessionId', session}}
  local function info(operation) return query(host, number, 'SystemInformation', operation, session_fields) end

  local ok, output = pcall(function()
    local product = child(info('GetProductInformation'), 'productInformation')
    local model = scalar(child(product, 'productName'))
    if not model then return nil end
    local software = inventory(info('GetSoftwareInventoryList'), 'softwarePartList', 'softwarePart', {'title','type','vendor','version'})
    local result = stdnse.output_table()
    result.classification = 'dci-player'
    result.vendor = 'Dolby'
    result.productName = model
    result.serialNumber = scalar(child(product, 'serialNumber'))
    result.mainSoftwareVersion = scalar(child(product, 'mainSoftwareVersion')) or 'Not reported'
    result.mainFirmwareVersion = scalar(child(product, 'mainFirmwareVersion')) or 'Not reported'
    result.securityManagerVersion = sm_version(software) or 'Not reported'
    result.version = 'Software: ' .. result.mainSoftwareVersion .. '; Firmware: ' .. result.mainFirmwareVersion .. '; SM: ' .. result.securityManagerVersion
    result.bundleVersion = scalar(child(product, 'bundleVersion'))
    result.SoftwareInfo = software
    result.HardwareInfo = inventory(info('GetHardwareInventoryList'), 'hardwarePartList', 'hardwarePart', {'title','type','vendor','version','model','serial','status'})
    local hostname = info('GetHostname')
    result.hostname = scalar(child(hostname, 'hostname'))
    result.screenName = scalar(child(hostname, 'screenName'))
    local getcerts = argument('getcerts') or stdnse.get_script_args('getcerts')
    if getcerts == true or getcerts == 'y' or getcerts == 'yes' or getcerts == 'true' then
      local certificates = child(info('GetCertificateList'), 'certificateList')
      result.CertInfo = {}
      for _, entry in ipairs(certificates and certificates.children or {}) do
        if entry.name == 'certificate' then
          local cert = child(entry, 'cert')
          result.CertInfo[#result.CertInfo + 1] = {title=scalar(child(entry, 'title')), cert=cert and cert.text}
        end
      end
    end
    return result
  end)
  -- End our own SOAP session even when an optional query fails.
  query(host, number, 'SessionManagement', 'Logout', session_fields)
  if ok then return output end
  stdnse.debug1('Dolby player information unavailable; session closed')
end

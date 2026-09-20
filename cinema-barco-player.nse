local nmap = require 'nmap'
local stdnse = require 'stdnse'
local slaxml = require 'slaxml'

description = [[
Identifies Barco ICMP/Alchemy players via the SMS SOAP 1.2 API on HTTPS 43758.
Uses one TLS connection, one Login, GetProductInformation and Logout. No
playback, ingest or configuration commands are issued. Uses the documented
monitoring account by default; no credential guessing or reconnect retries.
Documentation-based implementation; live ICMP hardware validation is pending.
]]
author = 'James Gardiner'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'cinema', 'safe', 'discovery'}

-- @usage
-- nmap -p43758 --script=cinema-barco-player TARGET
-- @args cinema-barco-player.username SMS username (default Monitor).
-- @args cinema-barco-player.password SMS password (default Monitor1234).
-- @args cinema-barco-player.soap-port HTTPS port override (default 43758).
-- @output
-- | cinema-barco-player:
-- |   classification: dci-player
-- |   vendor: Barco
-- |   productName: ICMP
-- |   serialNumber: TEST-123
-- |_  version: Software: 1.2.3

local SOAP = 'http://www.w3.org/2003/05/soap-envelope'
local API = 'http://www.barco.com/sms/sms_1'
local BODY_LIMIT, HEADER_LIMIT, TIMEOUT = 65536, 16384, 10000

local function argument(name)
  return stdnse.get_script_args('cinema-barco-player.' .. name)
end

local function soap_port()
  local value = argument('soap-port')
  if value == nil then return 43758 end
  if type(value) ~= 'string' and type(value) ~= 'number' then return nil end
  local number = tonumber(value)
  if number and number >= 1 and number <= 65535 and number % 1 == 0 then return number end
end

portrule = function(host, port)
  return port.protocol == 'tcp' and port.state == 'open' and port.number == soap_port()
end

local function parse_xml(xml)
  if xml:find('<!DOCTYPE', 1, true) or xml:find('<!ENTITY', 1, true) then return nil end
  local root, stack, count = nil, {}, 0
  local parser = slaxml.parser:new({
    startElement = function(name, ns)
      count = count + 1
      assert(count <= 2048 and #stack < 20)
      local node = {name=name, ns=ns, children={}, text=''}
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
      else assert(value:match('^%s*$')) end
    end,
  })
  local ok = pcall(parser.parseSAX, parser, xml)
  if ok and #stack == 0 then return root end
end

local function child(node, name, ns)
  local found
  for _, item in ipairs(node and node.children or {}) do
    if item.name == name and item.ns == ns then
      if found then return nil end
      found = item
    end
  end
  return found
end

local function scalar(node, limit)
  if not node or #node.children ~= 0 then return nil end
  local text = node.text:match('^%s*(.-)%s*$')
  if text == '' or #text > (limit or 100) or text:find('%c') then return nil end
  if text:lower() == 'unknown' or text:lower() == 'n/a' then return nil end
  return text
end

local function escape(text)
  return (text:gsub('&', '&amp;'):gsub('<', '&lt;'):gsub('>', '&gt;')
    :gsub('"', '&quot;'):gsub("'", '&apos;'))
end

-- Barco binds login to the TLS connection, not a token. http.post opens a
-- fresh connection per call, so use one socket with bounded HTTP framing.
-- No redirects, compression, pipelining, HTTP fallback or reconnects.
local function transport(socket, host, port)
  local buffer = ''
  local deadline
  local function receive()
    local remaining = deadline - nmap.clock_ms()
    assert(remaining > 0, 'response deadline')
    socket:set_timeout(remaining)
    local ok, data = socket:receive()
    assert(ok and #data > 0, 'response incomplete')
    buffer = buffer .. data
    assert(#buffer <= BODY_LIMIT + HEADER_LIMIT, 'response too large')
  end
  local function take(size)
    assert(size <= BODY_LIMIT, 'body too large')
    while #buffer < size do receive() end
    local data = buffer:sub(1, size)
    buffer = buffer:sub(size + 1)
    return data
  end
  local function line()
    while not buffer:find('\r\n', 1, true) do
      assert(#buffer < HEADER_LIMIT, 'header too large')
      receive()
    end
    local finish = buffer:find('\r\n', 1, true)
    assert(finish < HEADER_LIMIT, 'header too large')
    return take(finish + 1):sub(1, -3)
  end
  return function(operation, fields)
    local xml = '<s:Envelope xmlns:s="' .. SOAP .. '"><s:Body><' .. operation .. ' xmlns="' .. API .. '">'
    for _, field in ipairs(fields or {}) do
      xml = xml .. '<' .. field[1] .. '>' .. escape(field[2]) .. '</' .. field[1] .. '>'
    end
    xml = xml .. '</' .. operation .. '></s:Body></s:Envelope>'
    deadline = nmap.clock_ms() + TIMEOUT
    socket:set_timeout(TIMEOUT)
    local hostname = host.ip:find(':', 1, true) and ('[' .. host.ip .. ']') or host.ip
    assert(socket:send('POST / HTTP/1.1\r\nHost: ' .. hostname .. ':' .. port ..
      '\r\nContent-Type: application/soap+xml; charset=utf-8; action="' .. API .. '/' .. operation ..
      '"\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\nContent-Length: ' .. #xml .. '\r\n\r\n' .. xml))
    local status = line():match('^HTTP/1%.[01] (%d%d%d) ')
    assert(status == '200', 'HTTP command rejected')
    local headers, total = {}, 0
    while true do
      local item = line()
      total = total + #item + 2
      assert(total <= HEADER_LIMIT, 'headers too large')
      if item == '' then break end
      local key, value = item:match('^([%w-]+):%s*(.-)%s*$')
      assert(key, 'invalid header')
      key = key:lower()
      if key == 'content-length' or key == 'transfer-encoding' or key == 'content-encoding' then
        assert(headers[key] == nil, 'duplicate framing header')
      end
      headers[key] = value
    end
    assert(not headers['content-encoding'] or headers['content-encoding']:lower() == 'identity', 'encoded body')
    local body
    if headers['transfer-encoding'] then
      assert(headers['transfer-encoding']:lower() == 'chunked' and not headers['content-length'], 'invalid framing')
      local chunks, length = {}, 0
      while true do
        local chunkline = line()
        local hex = chunkline:match('^([%da-fA-F]+)$') or chunkline:match('^([%da-fA-F]+);')
        local size = hex and tonumber(hex, 16)
        assert(size and size <= BODY_LIMIT - length, 'invalid chunk size')
        if size == 0 then
          local trailers = 0
          while true do
            local trailer = line()
            trailers = trailers + #trailer + 2
            assert(trailers <= HEADER_LIMIT, 'trailers too large')
            if trailer == '' then break end
          end
          break
        end
        length = length + size
        chunks[#chunks + 1] = take(size)
        assert(take(2) == '\r\n', 'invalid chunk end')
      end
      body = table.concat(chunks)
    else
      local size = headers['content-length']
      assert(size and size:match('^%d+$'), 'missing body length')
      body = take(tonumber(size))
    end
    local root = parse_xml(body)
    assert(root and root.name == 'Envelope' and root.ns == SOAP, 'invalid SOAP envelope')
    local soapbody = child(root, 'Body', SOAP)
    assert(soapbody and #soapbody.children == 1, 'invalid SOAP body')
    local response = child(soapbody, operation .. 'Response', API)
    assert(response, 'unexpected SOAP response')
    local code = scalar(child(response, operation .. 'Result', API))
    if not code or not code:match('^%d+$') or tonumber(code) ~= 0 then return nil end
    return response
  end
end

action = function(host, port)
  local username = argument('username') or 'Monitor'
  local password = argument('password') or 'Monitor1234'
  if type(username) ~= 'string' or type(password) ~= 'string' or #username > 256 or #password > 256 then return nil end
  local socket = nmap.new_socket()
  local output
  local ok = pcall(function()
    socket:set_timeout(TIMEOUT)
    assert(socket:connect(host, port.number, 'ssl'))
    local query = transport(socket, host, port.number)
    if not query('Login', {{'userName', username}, {'password', password}, {'sessionInfo', 'Nmap read-only discovery'}}) then return end
    local info_ok, response = pcall(query, 'GetProductInformation')
    -- Only attempt logout on a well-framed connection. Closing our TLS socket
    -- releases the connection-bound session after a transport/protocol failure.
    if info_ok then pcall(query, 'Logout') end
    if not info_ok or not response then return end
    local info = child(response, 'productInfo', API)
    local name = scalar(child(info, 'ProductName', API))
    local model = scalar(child(info, 'Model', API))
    local function is_icmp(value)
      local normalized = (value or ''):lower():gsub('[^%w]', ''):gsub('^barco', '')
      return normalized == 'icmp' or normalized == 'icmpx' or normalized == 'alchemy' or normalized == 'icmpalchemy'
    end
    if not is_icmp(name) and not is_icmp(model) then return end
    output = stdnse.output_table()
    output.classification, output.vendor = 'dci-player', 'Barco'
    output.productName = is_icmp(name) and name or model
    output.model = model
    output.serialNumber = scalar(child(info, 'SerialNumber', API))
    output.hostname = scalar(child(info, 'Hostname', API))
    output.mainSoftwareVersion = scalar(child(info, 'Version', API))
    output.version = output.mainSoftwareVersion and ('Software: ' .. output.mainSoftwareVersion) or 'Software: Not reported'
    -- These identify the attached projector, never the player itself.
    output.projectorModel = scalar(child(info, 'ProjectorModel', API))
    output.projectorHostname = scalar(child(info, 'ProjectorHostname', API))
  end)
  socket:close()
  if not ok then stdnse.debug1('Barco player discovery unavailable; connection closed') end
  return output
end

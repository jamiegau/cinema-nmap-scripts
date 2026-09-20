local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Identifies Edge Senior IO using one read-only get.ip query on TCP 1125.
Requires the complete Version / IP Adr / Subnet / Router / command.ack reply
observed on a Senior running 1.1.3. Reports version but does not invent a serial.

WARNING: Senior units have been reported to lock up during Nmap scans. A
read-only query is not a guarantee of safety. Prefer direct mode with -sn -Pn
and --disable-arp-ping, selecting ONLY this script and ONE known Senior IP.
This skips port scanning and sends one command over one connection, without
application retries. Do not run alongside other scans or during a live show.
]]

-- @usage
-- nmap -n -sn -Pn --disable-arp-ping --script ./cinema-edge-senior-io.nse --script-args cinema-edge-senior-io.direct=true SENIOR_IP
-- @args cinema-edge-senior-io.direct Explicit host-script mode; disables the port rule.
-- @args cinema-edge-senior-io.port Explicit alternative TCP port (default 1125).
-- @output
-- | cinema-edge-senior-io:
-- |   classification: automation-io
-- |   vendor: Edge
-- |   productName: Senior-IO
-- |_  version: 1.1.3

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
-- Deliberately not categorised as 'safe': fragile firmware can still lock up.
categories = { "cinema", "discovery" }

local function target_port()
  local value = stdnse.get_script_args("cinema-edge-senior-io.port")
  if value == nil then return 1125 end
  local number = tonumber(value)
  if number and number >= 1 and number <= 65535 and number % 1 == 0 then
    return number
  end
end

local function direct_mode()
  local value = stdnse.get_script_args("cinema-edge-senior-io.direct")
  return value == true or value == "true" or value == "1"
end

hostrule = function()
  return direct_mode() and target_port() ~= nil
end

portrule = function(_, port)
  return not direct_mode() and port.number == target_port()
    and port.protocol == "tcp" and port.state == "open"
end

local function ipv4(value)
  if not value then return false end
  local a, b, c, d = value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  for _, part in ipairs({a, b, c, d}) do
    if #part > 3 or tonumber(part) > 255 then return false end
  end
  return true
end

local function parse_reply(reply)
  local lines = {}
  for line in reply:gmatch("[^\r\n]+") do
    line = line:match("^%s*(.-)%s*$")
    if line ~= "" then lines[#lines + 1] = line end
  end
  if #lines ~= 5 or lines[5] ~= "command.ack" then return nil end
  local version = lines[1]:match("^Version%s+(%d+%.%d+%.%d+)$")
  if not version or not ipv4(lines[2]:match("^IP Adr%s+(.+)$"))
    or not ipv4(lines[3]:match("^Subnet%s+(.+)$"))
    or not ipv4(lines[4]:match("^Router%s+(.+)$")) then return nil end
  local output = stdnse.output_table()
  output.classification = "automation-io"
  output.vendor = "Edge"
  output.productName = "Senior-IO"
  output.version = version
  return output
end

action = function(host)
  local port = target_port()
  if not port then return nil end
  -- De-duplicate even failed attempts within this Nmap invocation. This is NOT
  -- a cross-process lock or a substitute for infrequent use.
  host.registry = host.registry or {}
  local key = "cinema-edge-senior-io.queried"
  if host.registry[key] then return nil end
  host.registry[key] = true

  local socket = nmap.new_socket()
  local ok, result = pcall(function()
    socket:set_timeout(3000)
    if not socket:connect(host, port, "tcp") then return nil end
    -- Give the small controller a moment after connection establishment.
    stdnse.sleep(0.25)
    if not socket:send("get.ip\n") then return nil end
    local deadline = nmap.clock_ms() + 3000
    local reply = ""
    for _ = 1, 128 do
      local remaining = deadline - nmap.clock_ms()
      if remaining <= 0 then return nil end
      socket:set_timeout(remaining)
      -- Replies are short and can be fragmented; never wait for 1024 bytes.
      local status, chunk = socket:receive_bytes(1)
      if not status or type(chunk) ~= "string" or #chunk == 0 then return nil end
      if #reply + #chunk > 4096 then return nil end
      reply = reply .. chunk
      if reply:match("[\r\n]command%.ack%s*$") then
        return parse_reply(reply)
      end
    end
  end)
  socket:close()
  if ok then return result end
  stdnse.debug1("Senior read-only query failed; no retry will be made")
  return nil
end

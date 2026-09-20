local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"
local slaxml = require "slaxml"

description = [[
Identifies Dolby CP950 and CP950A cinema sound processors using read-only
SystemManagement SOAP queries. Exact model evidence is required; the shared
CP850/CP950 ASCII protocol is not a model discriminator. Reads device info,
chassis serial and main software version when available. No control-port
connection, login, fader/mute/macro changes or reboot commands are performed.
Documentation-based implementation; not yet tested on CP950/CP950A hardware.
]]
author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "discovery" }

-- @usage
-- sudo nmap -n -sS -p9090,61408 --script ./cinema-dolby-cp950.nse TARGET
-- @args cinema-dolby-cp950.soap-port Explicit SOAP port override (default 9090).

local SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
local BASE = "http://www.dolby.com/cp/ws/smi/"
local PATH = "/cp/ws/smi/v1/services/SystemManagement"
local function soap_port()
    local number = tonumber(stdnse.get_script_args("cinema-dolby-cp950.soap-port") or 9090)
    if number and number >= 1 and number <= 65535 and number % 1 == 0 then return number end
end

portrule = function(host, port)
    local number = soap_port()
    if not number or port.protocol ~= "tcp" or port.state ~= "open" then return false end
    if port.number == number then return true end
    if port.number ~= 61408 then return false end
    local soap = nmap.get_port_state(host, {number=number, protocol="tcp"})
    -- Older Catcher scan lists include 61408 but not 9090. That is enough to
    -- select a candidate; only a positive SOAP identity produces any output.
    -- If SOAP was explicitly scanned closed, do not make another attempt.
    return soap == nil
end

-- SAX callbacks enforce balanced tags/depth; the library's permissive DOM
-- helper alone can accept incomplete documents. No DTD/entity expansion.
local function parse_xml(xml)
    if xml:find("<!DOCTYPE", 1, true) or xml:find("<!ENTITY", 1, true) then return nil end
    local root, stack, count = nil, {}, 0
    local parser = slaxml.parser:new({
        startElement = function(name, ns)
            count = count + 1
            assert(count <= 512 and #stack < 16)
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

local function child(node, name, ns)
    local found
    for _, item in ipairs(node and node.children or {}) do
        if item.name == name and (not ns or item.ns == ns) then
            if found then return nil end -- Ambiguous duplicate, not a scalar.
            found = item
        end
    end
    return found
end

local function clean(value)
    if type(value) ~= "string" then return nil end
    value = value:match("^%s*(.-)%s*$")
    if value == "" or #value > 100 or value:find("%c") or
       value:lower() == "unknown" or value:lower() == "n/a" then return nil end
    return value
end

local function scalar(node)
    if node and #node.children == 0 then return clean(node.text) end
end

local function query(host, number, operation, version)
    local ns = BASE .. version
    local request = '<?xml version="1.0"?><s:Envelope xmlns:s="' .. SOAP ..
        '" xmlns:d="' .. ns .. '"><s:Body><d:' .. operation ..
        'Request/></s:Body></s:Envelope>'
    local result = http.post(host, {number=number,protocol="tcp"}, PATH, {
        timeout=2500, max_body_size=32768, redirect_ok=false,
        header={ ["Content-Type"]='text/xml; charset="utf-8"',
            SOAPAction='"' .. BASE .. 'v1/' .. operation .. '"' },
    }, nil, request)
    if not result or result.status ~= 200 or result.truncated or
       type(result.body) ~= "string" or #result.body > 32768 then return nil end
    local root = parse_xml(result.body)
    if not root or root.name ~= "Envelope" or root.ns ~= SOAP then return nil end
    local body = child(root, "Body", SOAP)
    if not body or #body.children ~= 1 then return nil end
    return child(body, operation .. "Response", ns)
end

local function pairs_from(node)
    local values = {}
    for _, item in ipairs(node and node.children or {}) do
        if item.name == "keyValuePair" then
            local key, value = scalar(child(item, "key")), scalar(child(item, "value"))
            if key and value then
                key = key:lower():gsub("[^%w]", "")
                if values[key] ~= nil and values[key] ~= value then
                    values[key] = false -- conflicting duplicates stay unusable
                else values[key] = value end
            end
        end
    end
    return values
end

local function select_value(values, keys)
    local selected
    for _, key in ipairs(keys) do
        if values[key] == false then return nil end
        if values[key] then
            if selected and selected ~= values[key] then return nil end
            selected = values[key]
        end
    end
    return selected
end

action = function(host, port)
    local number = soap_port()
    if not number then return nil end
    local info = pairs_from(query(host, number, "getDeviceInfo", "v1_0"))
    local model = select_value(info, {"model", "modelname", "productname", "devicemodel"})
    if model then model = model:upper():gsub("^DOLBY CINEMA PROCESSOR%s+", ""):gsub("^DOLBY%s+", "") end
    if model ~= "CP950" and model ~= "CP950A" and model ~= "CP850" then return nil end
    host.registry = host.registry or {}
    host.registry.cinema_dolby_cp_model = model
    if model == "CP850" then return nil end -- Existing CP850 script handles it.
    local output = stdnse.output_table()
    output.classification = "sound-processor"
    output.vendor = "Dolby"
    output.productName = model
    output.serialNumber = select_value(info, {"chassisserialnumber", "chassissn"})
    output.version = select_value(info, {"mainsoftwareversion", "softwareversion", "systemsoftwareversion"})
    if not output.serialNumber then
        output.serialNumber = scalar(child(query(host, number, "getSerialNumber", "v1_1"), "serialNumber"))
    end
    if not output.version then
        local versions = pairs_from(query(host, number, "getSystemVersions", "v1_1"))
        output.version = select_value(versions, {"mainsoftwareversion", "softwareversion", "systemsoftwareversion"})
    end
    return output
end

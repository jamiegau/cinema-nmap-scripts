local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Identifies Christie cinema projectors using read-only serial-over-Ethernet
queries on TCP 5000. Supports documented PNG types for CP2000, Solaria,
CineLife and CineLife+. Model and chassis serial are reported only when
unambiguously labelled in the response. See README for documentation sources
and limitations: this implementation has not been tested on Christie hardware.
No login, power, playback, configuration or other write commands are sent.
]]
author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "discovery" }

-- @usage
-- sudo nmap -n -sS -p5000 --script ./cinema-christie-projector.nse PROJECTOR_IP
-- @args cinema-christie-projector.port Optional explicit serial TCP port (default 5000).

portrule = function(_, port)
    local number = tonumber(stdnse.get_script_args("cinema-christie-projector.port") or 5000)
    return number ~= nil and number >= 1 and number <= 65535 and number % 1 == 0 and
        port.protocol == "tcp" and port.state == "open" and port.number == number
end

local families = {
    [41] = "CP2000-ZX", [42] = "CP2000-M", [46] = "Solaria / Series 2",
    [60] = "CineLife / Series 3", [71] = "CineLife+ / Series 4"
}

-- Christie messages are parenthesis-delimited, not necessarily newline-
-- delimited. Preserve partial frames across TCP reads and parentheses inside
-- quoted strings. A new unquoted '(' discards an incomplete previous frame.
local function pop_frame(reader)
    local start, quoted, escaped
    for i = 1, #reader.buffer do
        local c = reader.buffer:sub(i, i)
        if start then
            if escaped then escaped = false
            elseif c == "\\" then escaped = true
            elseif c == '"' then quoted = not quoted
            elseif not quoted and c == "(" then start = i
            elseif not quoted and c == ")" then
                local frame = reader.buffer:sub(start + 1, i - 1)
                reader.buffer = reader.buffer:sub(i + 1)
                return frame
            end
        elseif c == "(" then start = i; quoted = false; escaped = false end
    end
end

local function query(socket, command, group)
    if not socket:send("(" .. command .. "?)\r\n") then return {}, false end
    local reader, frames, total = { buffer = "" }, {}, 0
    local deadline = nmap.clock_ms() + 2500
    local prefix = command .. "!"
    for _ = 1, 128 do
        local frame = pop_frame(reader)
        while frame do
            if frame:sub(1, #prefix) == prefix then
                local body = frame:sub(#prefix + 1)
                if body:match('^%s*"%-+END%-+"%s*$') then return frames, true end
                frames[#frames + 1] = body
                if not group then return frames, true end
            elseif frame:match("^%s*ERR[%s!]") then
                -- Permission denied / unsupported command: do not try a login.
                return frames, false
            end
            frame = pop_frame(reader)
        end
        local remaining = deadline - nmap.clock_ms()
        if remaining <= 0 then return frames, false end
        socket:set_timeout(remaining)
        local ok, data = socket:receive_bytes(1)
        if not ok or type(data) ~= "string" or data == "" then return frames, false end
        total = total + #data
        if total > 16384 then return frames, false end
        reader.buffer = reader.buffer .. data
    end
    return frames, false
end

local function clean(value)
    value = value:match("^%s*(.-)%s*$")
    local lower = value:lower()
    if value == "" or #value > 100 or value:find("[%c\\]") or
       lower == "unknown" or lower == "n/a" or lower == "na" or
       lower == "not specified" or lower == "invalid data" or
       lower == "communication fault" then return nil end
    return value
end

local function apply_status(output, frames, legacy)
    for _, body in ipairs(frames) do
        local _, severity, value, label = body:match('^%s*(%d+)%s+(%d+)%s+"([^"\\]*)"%s+"([^"\\]*)"%s*$')
        -- The legacy and CineLife severity enumerations are different.
        if value and ((legacy and tonumber(severity) == 0) or
                      (not legacy and tonumber(severity) == 1)) then
            value = clean(value)
            label = label:lower():gsub("[^%w]", "")
            if value then
                if label == "projectormodel" or label == "projectormodelname" or
                   label == "model" or label == "modelname" then
                    -- Do not accept a lamp/board name or an arbitrary status value.
                    if value:match("^CP%d%d%d%d[%w%-]*$") or
                       value == "Solaria One" or value == "Solaria One+" then
                        output.productName = value
                    end
                elseif label == "projectorserialnumber" or label == "projectorsn" then
                    output.serialNumber = value
                end
            end
        end
    end
end

action = function(host, port)
    local socket = nmap.new_socket()
    local ok, result = pcall(function()
        socket:set_timeout(2500)
        if not socket:connect(host, port) then return nil end
        local replies = query(socket, "PNG", false)
        if not replies[1] then return nil end
        local device, major, minor, patch = replies[1]:match("^%s*(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s*$")
        if not device then
            device, major, minor = replies[1]:match("^%s*(%d+)%s+(%d+)%s+(%d+)%s*$")
        end
        device = tonumber(device)
        if not families[device] then return nil end
        -- Modern documentation requires all three version components.
        if (device == 60 or device == 71) and not patch then return nil end
        local output = stdnse.output_table()
        output.classification = "dci-projector"
        output.vendor = "Christie"
        output.family = families[device]
        output.version = tonumber(major) .. "." .. tonumber(minor)
        if patch then output.version = output.version .. "." .. tonumber(patch) end
        if device == 41 or device == 42 then
            output.productName = families[device]
            return output -- Basic identification only; do not assume Series 2 SST support.
        end
        -- Query groups instead of guessing status item indices. Firmware can
        -- add or reorder items. Never use an IMB/ICP/light-engine serial as the
        -- projector's chassis serial. PNG supplies the main CPU version.
        local groups = device == 46 and { "SST+CONF", "SST+SERI" } or
            { "SST+SERI", "SST+SYST" }
        for _, command in ipairs(groups) do
            local frames, complete = query(socket, command, true)
            apply_status(output, frames, device == 46)
            -- Some firmware does not emit a group terminator. Keep complete
            -- rows received before timeout and permit the next distinct group.
            if (not complete and #frames == 0) or
               (output.productName and output.serialNumber) then break end
        end
        return output
    end)
    socket:close()
    if ok then return result end
    stdnse.debug1("Christie discovery stopped after a socket/protocol error")
    return nil
end

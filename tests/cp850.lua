-- Offline contract tests for Juan Marin's CP850 contribution. No real sockets.
local root = assert(arg[1], "repository directory required")
local state
local commands = {
    "sys.macro_preset ?\r\n", "sys.macro_name ?\r\n",
    "sys.fader ?\r\n", "sys.mute ?\r\n"
}
local function reset()
    state = {
        ports = { [80] = { state = "open" }, [111] = { state = "closed" } },
        replies = { "sys.macro_preset 3\r\n", "sys.macro_name Non-Sync\r\n",
                    "sys.fader 37\r\n", "sys.mute 0\r\n" },
        sockets = 0, connects = 0, closes = 0, sends = {}, pauses = {}, reads = 0
    }
end
package.preload.nmap = function()
    return {
        get_port_state = function(_, port) return state.ports[port.number] end,
        new_try = function(catch)
            return function(ok, result)
                if not ok then catch(); error(result) end
                return result
            end
        end,
        new_socket = function()
            state.sockets = state.sockets + 1
            return {
                set_timeout = function(_, timeout) assert(timeout == 4000) end,
                connect = function(_, _, port)
                    assert(port == 61408)
                    state.connects = state.connects + 1
                    return not state.connect_error, "connect error"
                end,
                send = function(_, cmd)
                    table.insert(state.sends, cmd)
                    assert(cmd == commands[#state.sends], "only ordered read-only queries")
                    return state.send_error ~= #state.sends, "send error"
                end,
                receive_bytes = function()
                    state.reads = state.reads + 1
                    if state.receive_error == state.reads then return false, "TIMEOUT" end
                    return true, state.replies[state.reads]
                end,
                close = function() state.closes = state.closes + 1 end
            }
        end
    }
end
package.preload.stdnse = function()
    return {
        debug = function() end,
        output_table = function() return {} end,
        sleep = function(seconds)
            assert(seconds >= 0.5, "preserve the contributor's pacing")
            table.insert(state.pauses, seconds)
        end
    }
end
package.preload.nsedebug = function() return { tostr = tostring } end
local env = setmetatable({}, { __index = _G })
assert(loadfile(root .. "/cinema-dolby-cp850.nse", "t", env))()
local host = { ip = "127.0.0.1" }
local port = { number = 61408, state = "open", protocol = "tcp" }
local cases = 0
local function test(name, fn)
    reset(); fn(); cases = cases + 1; print("PASS: " .. name)
end

test("CP850 fingerprint matches", function() assert(env.portrule(host, port)) end)
test("CP750 fingerprint rejected", function()
    state.ports[80].state = "closed"; state.ports[111].state = "open"
    assert(not env.portrule(host, port))
end)
test("open RPC port rejected", function()
    state.ports[111].state = "open"; assert(not env.portrule(host, port))
end)
test("missing web fingerprint rejected", function()
    state.ports[80] = nil; assert(not env.portrule(host, port))
end)
test("wrong protocol, port and closed port rejected", function()
    for _, p in ipairs({{number=80,state="open",protocol="tcp"},
        {number=61408,state="open",protocol="udp"},
        {number=61408,state="closed",protocol="tcp"}}) do
        assert(not env.portrule(host, p))
    end
end)
test("contributor's live response and single paced connection", function()
    local out = env.action(host, port)
    assert(out.classification == "sound-processor" and out.vendor == "Dolby")
    assert(out.productName == "CP850" and out.macroPreset == "3")
    assert(out.macroName == "Non-Sync" and out.faderLevel == "3.7")
    assert(out.muteStatus == "Unmuted")
    assert(state.sockets == 1 and state.connects == 1 and state.closes == 1)
    assert(#state.sends == 4 and #state.pauses == 5)
end)
test("multiword macro and muted response", function()
    state.replies[2] = "sys.macro_name 5.1 + Dolby Atmos\r\n"
    state.replies[4] = "sys.mute 1\r\n"
    local out = env.action(host, port)
    assert(out.macroName == "5.1 + Dolby Atmos" and out.muteStatus == "Muted")
end)
test("unrecognised protocol rejected", function()
    state.replies[1] = "ERROR\r\n"; assert(env.action(host, port) == nil)
end)
test("missing optional values omitted", function()
    state.replies[2] = ""; state.replies[3] = "ERROR"; state.replies[4] = "ERROR"
    local out = env.action(host, port)
    assert(out.macroPreset == "3" and out.macroName == nil)
    assert(out.faderLevel == nil and out.muteStatus == nil)
end)
for i = 1, 4 do
    test("receive timeout " .. i .. " closes without reconnecting", function()
        state.receive_error = i
        assert(env.action(host, port) == nil)
        assert(state.connects == 1 and state.closes == 1 and #state.sends == i)
    end)
end
test("connect failure closes socket", function()
    state.connect_error = true
    assert(not pcall(env.action, host, port))
    assert(state.closes == 1 and #state.sends == 0)
end)
test("send failure closes without retrying", function()
    state.send_error = 2
    assert(not pcall(env.action, host, port))
    assert(state.connects == 1 and state.closes == 1 and #state.sends == 2)
end)
print(string.format("%d CP850 offline tests passed", cases))

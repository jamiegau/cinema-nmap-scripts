-- Offline regression checks for older JSD-60 web identity pages.
local root = assert(arg[1])
local pages, ports, socket_calls, requests
local host = {ip='192.0.2.15'}
local port = {number=80, protocol='tcp', state='open'}
package.preload.nmap = function() return {
    get_port_state=function(_, p) return ports[p.number] end,
    new_try=function() return function(ok, value) assert(ok, value); return value end end,
    new_socket=function()
        socket_calls = socket_calls + 1
        return {
            set_timeout=function() end,
            connect=function() return true end,
            send=function(self, value) self.command=value; return true end,
            receive_lines=function(self)
                if not self.command then return false, 'TIMEOUT' end
                if self.command:find('serial_number', 1, true) then return true, '3458\r\n' end
                if self.command:find('.ver', 1, true) then return true, 'E\t141205\t141218\t141014\r\n' end
                return true, 'Fixture\r\n'
            end,
            close=function() end,
        }
    end,
} end
package.preload.stdnse = function() return {output_table=function() return {} end, debug=function() end} end
package.preload.nsedebug = function() return {tostr=tostring} end
package.preload.http = function() return {
    get=function(_, _, path)
        requests[#requests+1]=path
        return pages[path] or {status=404, body='404 File not found'}
    end,
} end
local env=setmetatable({}, {__index=_G})
assert(loadfile(root..'/cinema-qsc-usl-devices.nse', 't', env))()
local function legacy(model)
    return '<html><title>USL, Inc. JSD-60</title><table>\n'..
        '<tr><td>Model Number</td><td>USL '..model..'</td></tr>\n'..
        '<tr><td>Serial Number</td><td>1234</td></tr>\n'..
        '<tr><td>PIC Version</td><td>130529</td></tr>\n'..
        '<tr><td>DSP Version</td><td>121208</td></tr>\n'..
        '<tr><td>Front Panel Version</td><td>121206</td></tr>\n'..
        '<tr><td>Host Name</td><td>SCREEN-ONE</td></tr>\n'..
        '<tr><td>Theater Name</td><td>Example Cinema</td></tr></table></html>'
end
local count=0
local function test(name, fn)
    pages={}; ports={[10001]={state='open'}}; socket_calls=0; requests={}
    fn(); count=count+1; print('PASS: '..name)
end
test('root-only JSD-60D identity survives missing ConfigFlash endpoints', function()
    pages['/']={status=200, body=legacy('JSD-60D')}
    local result=env.action(host, port)
    assert(result.classification=='sound-processor' and result.vendor=='QSC-USL')
    assert(result.productName=='JSD-60D' and result.serialNumber=='1234')
    assert(result.version=='PIC: 130529; DSP: 121208; Front panel: 121206')
    assert(result.hostname=='SCREEN-ONE' and result.theaterName=='Example Cinema')
    assert(socket_calls==0 and #requests==3)
end)
test('supported JSD-60 model suffixes remain distinguishable', function()
    for _, suffix in ipairs({'', 'L', 'D', 'LS', 'DS', 'LX', 'DX', 'LN', 'DN'}) do
        pages['/']={status=200, body=legacy('JSD-60'..suffix)}
        assert(env.action(host, port).productName=='JSD-60'..suffix)
    end
    assert(socket_calls==0)
end)
test('HTML attributes, whitespace and capitalization do not obscure the table', function()
    local body=legacy('JSD-60D'):gsub('<tr>', '<TR class="row">'):gsub('</tr>', '</TR>')
        :gsub('<td>', '<TD class="cell">  '):gsub('</td>', '  </TD>')
    pages['/']={status=200, body=body}
    assert(env.action(host, port).serialNumber=='1234')
end)
test('missing firmware fields preserve confirmed model and serial', function()
    local body=legacy('JSD-60D'):gsub('<tr><td>PIC Version.-</tr>', '')
        :gsub('<tr><td>DSP Version.-</tr>', ''):gsub('<tr><td>Front Panel Version.-</tr>', '')
    pages['/']={status=200, body=body}
    local result=env.action(host, port)
    assert(result.productName=='JSD-60D' and result.serialNumber=='1234' and result.version==nil)
end)
test('unrelated HTTP pages and unsupported models are not labelled QSC-USL', function()
    for _, body in ipairs({'<title>Printer</title>', legacy('JSD-60UNKNOWN'), legacy('Other model')}) do
        pages['/']={status=200, body=body}
        assert(not env.action(host, port))
    end
    assert(socket_calls==0)
end)
test('HTTP failures do not become unknown device identities', function()
    pages['/ConfigFlash.html']={status=503}
    pages['/debug/ConfigFlash.html']={status=401, body='Sign in'}
    pages['/']={status=200, body=legacy('JSD-60D')}
    assert(env.action(host, port).productName=='JSD-60D')
    pages['/']={status=503}
    assert(not env.action(host, port))
end)
test('modern ConfigFlash JSD-60 detection still queries its original identity', function()
    local handle=assert(io.open(root..'/example_device_data/QSC-USL/JSD-60 Config Flash.html'))
    pages['/ConfigFlash.html']={status=200, body=handle:read('*a')}; handle:close()
    local result=env.action(host, port)
    assert(result.classification=='sound-processor' and result.productName=='JSD-60')
    assert(result.serialNumber=='3458' and result.version=='E,141205,141218,141014')
    assert(#requests==1 and socket_calls>0)
end)
test('legacy JSD-100 fallback remains available', function()
    pages['/']={status=200, body='<title>USL JSD-100</title>\n'..
        '<tr><td>Model Number</td><td>JSD-100v110101</td></tr>\n'..
        '<tr><td>Host Name</td><td>SCREEN-ONE</td></tr>'}
    local result=env.action(host, port)
    assert(result.classification=='sound-processor' and result.productName=='JSD-100')
    assert(result.version=='110101' and socket_calls==0)
end)
test('focused port scans tolerate unscanned FTP and SSH ports', function()
    assert(env.portrule(host, port))
    ports[10001]={state='closed'}; assert(not env.portrule(host, port))
    ports[10001]=nil; assert(not env.portrule(host, port))
    ports[10001]={state='open'}; ports[22]={state='open'}
    assert(not env.portrule(host, port))
end)
print(('%d QSC-USL offline tests passed'):format(count))

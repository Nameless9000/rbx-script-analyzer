if not syn then print("Exploit not supported") return end
local HttpService = game:GetService("HttpService")

getgenv().analyzerSettings = getgenv().analyzerSettings or {
    Http = true,
    HttpDump = true, -- dumps the full args list
    Websocket = true,
    Remotes = true,
    Namecalls = true,
    Indexes = true,
    GTSpy = true,
    LogData = true,
--    GGSpy = false,
    SynSpy = true,
    DisableHttpReq = false,
    DisableWebhookReq = false
}

local analyzers = getgenv().analyzerSettings


local fileName

function LogData(...)
    if not analyzers.LogData then return end
    
    if not isfolder("ScriptAnalyzer") then
        makefolder("ScriptAnalyzer")
    end
    
    local startTick = math.floor(tick())
    if not fileName then
        fileName = "ScriptAnalyzer/"..startTick.."-Log.txt"
        writefile(fileName,"## Game: "..game.PlaceId.." | Server: "..game.JobId.." | Time: "..startTick.." ##\n\n")
    end
    
    local ar={...}
    appendfile(fileName, table.concat(ar).."\n")
end

local write = function(...)
    local ar={...}
    printconsole(table.concat(ar),255,255,255)
    LogData(table.concat(ar))
end
local writei = function(...)
    local ar={...}
    printconsole("[*] "..table.concat(ar),0,0,255)
    LogData("[*] "..table.concat(ar))
end
local writew = function(...)
    local ar={...}
    printconsole("[*] "..table.concat(ar).."\n",255, 255, 0)
    LogData("[*] "..table.concat(ar).."\n")
end
local writee = function(...)
    local ar={...}
    printconsole(table.concat(ar),255,0,0)
    LogData(table.concat(ar))
end

writee([[

______             _               _______              _                        
/ _____)           (_)       _     (_______)            | |                       
( (____   ____  ____ _ ____ _| |_    _______ ____  _____| |_   _  ___ _____  ____ 
\____ \ / ___)/ ___) |  _ (_   _)  |  ___  |  _ \(____ | | | | |/___) ___ |/ ___)
_____) | (___| |   | | |_| || |_   | |   | | | | / ___ | | |_| |___ | ____| |    
(______/ \____)_|   |_|  __/  \__) |_|   |_|_| |_\_____|\_)__  (___/|_____)_|    
                    |_|                              (____/                  
                        
                    
Originally made by CDXX/CEO of Africa#0591

Heavily moddified by Nameless#9000

]])


local request = syn.request or request or http.request

-------------------------------------------------------
-- Gang shit below

local gm = getrawmetatable(game)

local oldnamecall = gm.__namecall
local oldindex = gm.__index

-- Game

setreadonly(gm, false)

gm.__index = newcclosure(function(self, k)
    if checkcaller() and analyzers.Indexes then
        writew("Index Spy - "..tostring(k))
        write(tostring(k).." was indexed by "..tostring(self).."\n\n")
    end
    return oldindex(self, k)
end)
gm.__namecall = newcclosure(function(self, ...)
    local m = getnamecallmethod()
    if checkcaller() and analyzers.Namecalls then
        writew("Namecall Spy - "..tostring(m))
        write("Args: "..tostring((...)).."\n\n")
    end
    return oldnamecall(self, ...)
end)

local oldget, oldgetasync
oldget, oldgetasync = hookfunction(game.HttpGet, function(self, url, ...)
    if not analyzers.Http then print("no http") return oldget(self, url, ...) end
    writew("Http Spy - HttpGet")
    write("A http request was sent to "..tostring(url).."\n\n")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldget(self, url, ...)
end), hookfunction(game.HttpGetAsync, function(self, url, ...)
    if not analyzers.Http then return oldgetasync(self, url, ...) end
    writew("Http Spy - HttpGetAsync")
    write("A http request was sent to "..tostring(url).."\n\n")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldgetasync(self, url, ...)
end)

setreadonly(gm, true)

--  Syn

setreadonly(syn, false)

setmetatable(syn, {
    __newindex = function(t, i, v)
        if analyzers.SynSpy then
            writew("Syn Spy - "..tostring(i))
            write("A variable was declared in syn table with the name "..tostring(i).." set to "..tostring(v).."\n\n")
        end
    end
})

setreadonly(syn.websocket,false)

local oldwebsocket = syn.websocket.connect

syn.websocket.connect = function(t)
    local connection = oldwebsocket(t)
    
    if analyzers.Websocket then
        writew("Websocket Spy - Connection")
        write("A connection request was sent to "..tostring(t).."\n\n")
        
        connection.OnMessage:Connect(function(body)
            writew("Websocket Spy - Received")
            write("A connection request was sent to "..tostring(t).."\n")
            write("Sending the following information: "..body.."\n\n")
        end)
        
        connection.OnClose:Connect(function(body)
            writew("Websocket Spy - Closed")
            write("Connection closed on "..tostring(t).."\n\n")
        end)
        
        setreadonly(connection,false)
        
        local oldsend = connection.Send
        connection.Send = function(self, message)
            writew("Websocket Spy - Sent")
            write("A connection request was sent to "..tostring(t).."\n")
            write("Sending the following information: "..message.."\n\n")
            return oldsend(self, message)
        end
        
    end
    
    return connection
end


local oldrequest = syn.request
syn.request = function(t)
    if analyzers.Http then
        writew("Syn Req Spy - "..tostring(t.Method))
        if t.Body then
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n")
            write("Sending the following information: "..t.Body.."\n\n")
        else
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n\n")
        end
        if HttpDump then
            write("Args Dump:\n"..HttpService:JSONEncode(t).."\n\n")
        end
    end
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request") return end
    if analyzers.DisableWebhookReq and (string.find(t.Url, "https://discord.com/api/webhooks/") or string.find(t.Url, "https://discordapp.com/api/webhooks/")) then writee("Blocked HTTP Request to discord webhook.\n\n") return; end
    return oldrequest(t)
end

-- G Spy

setmetatable(_G, {
    __index = function(t, k)
        if analyzers.GTSpy then writew("GT Spy - Invalid Index") write("Attempt to index "..k.." with a nil value inside _G\n\n") end return;
    end,
    __newindex = function(t, i, v) 
        if analyzers.GTSpy then writew("GT Spy - New Index") write("New index was declared with the name of "..tostring(i).." and value of "..tostring(v).."\n\n") end rawset(t, i, v)
    end
})

setmetatable(getrenv()._G,{
    __index = function(t, k)
        if analyzers.GTSpy then writew("GT Spy - Invalid Index") write("Attempt to index "..k.." with a nil value inside _G\n\n") end return;
    end,
    __newindex = function(t,i,v)
        if analyzers.GTSpy then writew("GT Spy - New Index") write("New index was declared with the name of "..tostring(i).." and value of "..tostring(v).."\n\n") end rawset(t, i, v)
    end
})

-- Remote Spy
-- Decided to use hookfunction instead of the namecall metatable above

local oldinvoke, oldfire
oldinvoke, oldfire = hookfunction(Instance.new("RemoteFunction").InvokeServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was invoked with args: "..tostring((...)).."\n\n") end
    return oldinvoke(self, ...)
end), hookfunction(Instance.new("RemoteEvent").FireServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was fired with args: "..tostring((...)).."\n\n") end
    return oldfire(self, ...)
end)


writei("Script Analyzer started.\n")

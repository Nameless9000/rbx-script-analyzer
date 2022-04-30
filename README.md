# rbx-script-analyzer
Analyze roblox exploiting scripts and reverse engineer them. Usefull if you are trying to analyze malicious obfuscated scripts.

Instructions:

1 (optional) Edit the analyzer settings first
```lua
getgenv().analyzerSettings = {
    Http = true,
    Websocket = true,
    Remotes = true,
    Namecalls = true,
    Indexes = true,
    GTSpy = true,
    SynSpy = true,
    DisableHttpReq = false,
    DisableWebhookReq = false
}
```

2. Execute Script-Analyzer.lua in a roblox game (synapse only)

3. Execute scripts you want to analyze

4. Press insert (internal ui needs to be enabled)

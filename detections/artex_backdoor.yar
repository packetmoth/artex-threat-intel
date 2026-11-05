rule ARTEX_Backdoor_Build
{
    meta:
        description   = "Trojanized ARTEX build: verifyCaptcha pre-auth root RCE backdoor"
        reference     = "Badbyte / The Hacker News, 2026-11-05"
        date          = "2026-11-05"
        images        = "tomicdd/artex, congdonglinux/artex"
        layer_sha256  = "cb85a7206290dc1813e3203e044741054b26c7a7c557c7d9d6d91af20aeb232b"
        binary_sha256 = "d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573"
        note          = "Scan the extracted ARTEX server binary or image layers. Clean builds have no verifyCaptcha and no shell on the login path."
    strings:
        $fn      = "verifyCaptcha" ascii wide
        $login   = "authLogin" ascii wide
        $buildid = "3aC1db3gGU08O4UHbAt4J" ascii wide
        $sh1     = "/bin/sh" ascii wide
        $sh2     = "sh -c" ascii wide
    condition:
        ($fn and $login and ($sh1 or $sh2)) or $buildid
}

rule ARTEX_Compose_Pulls_Backdoored_Image
{
    meta:
        description = "docker-compose for ARTEX pulls a known backdoored prebuilt image instead of building from source"
        reference   = "Badbyte / The Hacker News, 2026-11-05"
        date        = "2026-11-05"
    strings:
        $i1 = "tomicdd/artex" ascii nocase
        $i2 = "congdonglinux/artex" ascii nocase
        $svc = "artex" ascii nocase
    condition:
        $svc and ($i1 or $i2)
}

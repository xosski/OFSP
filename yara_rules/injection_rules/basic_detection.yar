
    rule injection_basic_detection {
        meta:
            description = "Basic detection rule for injection"
            author = "YaraRuleManager"
            created = "2026-05-04"
        
        strings:
            $str1 = "CreateRemoteThread" nocase
            $str2 = "WriteProcessMemory" nocase
            $hex1 = { 68 ?? ?? ?? ?? }
        
        condition:
            any of them
    }
    
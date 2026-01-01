
    rule shellcode_basic_detection {
        meta:
            description = "Basic detection rule for shellcode"
            author = "YaraRuleManager"
            created = "2025-12-31"
        
        strings:
            $str1 = "shellcode" nocase
            $str2 = "payload" nocase
            $hex1 = { 55 8B EC }
        
        condition:
            any of them
    }
    
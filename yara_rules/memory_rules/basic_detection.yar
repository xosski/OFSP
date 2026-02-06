
    rule memory_basic_detection {
        meta:
            description = "Basic detection rule for memory"
            author = "YaraRuleManager"
            created = "2026-02-06"
        
        strings:
            $str1 = "VirtualAlloc" nocase
            $str2 = "MemoryBasicInformation" nocase
            $hex1 = { 90 90 90 90 90 }
        
        condition:
            any of them
    }
    
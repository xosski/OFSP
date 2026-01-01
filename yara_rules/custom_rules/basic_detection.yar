
    rule custom_basic_detection {
        meta:
            description = "Basic detection rule for custom"
            author = "YaraRuleManager"
            created = "2025-12-31"
        
        strings:
            $str1 = "suspicious" nocase
            $str2 = "detection" nocase
            $hex1 = { 00 01 02 03 04 }
        
        condition:
            any of them
    }
    
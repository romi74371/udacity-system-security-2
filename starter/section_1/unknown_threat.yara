rule darkl0rd_detector {
        meta:
                Author = "@hauptvogel"
                Description = "This rule detects suspicious darkl0rd.com domain"
        strings:
                $domain = "darkl0rd.com" nocase
                $port = "7758"
        condition:
                all of them
}

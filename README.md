# Memory-Forensics
The very first action taken on a suspect machine should be to acquire the active memory before modifying the system by running any malware tools.
Memory Aquisition Tools:
Dumpit, Winpmem, FTK imager

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
 
 
 -----------
 Red Flags to look out for:
 svchost.exe should always have parent process of services.exe and -k switch should always be present
 process does not have mapped file on disk associated with it, only exist in memory.  (could be  a process injeciton)
 
 

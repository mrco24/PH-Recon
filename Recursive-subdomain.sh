#!/bin/bash/
#link:https://sidxparab.gitbook.io/subdomain-enumeration-guide/passive-enumeration/recursive-enumeration
for sub in $( ( cat subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
    subfinder -d example.com-all -silent | anew -q passive_recursive.txt
    assetfinder --subs-only example.com | anew -q passive_recursive.txt
    amass enum -passive -d example.com | anew -q passive_recursive.txt
    findomain --quiet -t example | anew -q passive_recursive.txt
done

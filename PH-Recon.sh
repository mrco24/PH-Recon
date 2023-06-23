#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/PH-Recon/$domain/subdomain /root/PH-Recon/$domain/subdomain/good /root/PH-Recon/$domain/subdomain/good/Gen_sub /root/PH-Recon/$domain/Subomain-Takeover /root/PH-Recon/$domain/Subomain-Screenshots /root/PH-Recon/$domain/Special_subdomain /root/PH-Recon/$domain/Special_subdomain/scan /root/PH-Recon/$domain/scan  /root/PH-Recon/$domain/scan/my-jaeles /root/PH-Recon/$domain/scan/jaeles /root/PH-Recon/$domain/scan/jaeles/my-url /root/PH-Recon/$domain/scan/jaeles/url /root/PH-Recon/$domain/dri  /root/PH-Recon/$domain/scan/nuclei/Php-My-Admin /root/PH-Recon/$domain/scan/nuclei /root/PH-Recon/$domain/scan/new-nuclei /root/PH-Recon/$domain/url /root/PH-Recon/$domain/Secret-api /root/PH-Recon/$domain/gf /root/PH-Recon/$domain/xss /root/PH-Recon/$domain/sql /root/PH-Recon/$domain/js_url /root/PH-Recon/$domain/git_dork /root/PH-Recon/$domain/SQL

subfinder -d $domain -all -o /root/PH-Recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/PH-Recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/PH-Recon/$domain/subdomain/findomain.txt
#sudomy -d $domain -o /root/PH-Recon/$domain/subdomain/sudomy.txt
amass enum -active -d $domain -o /root/PH-Recon/$domain/subdomain/amass_sub.txt
amass enum -passive -d $domain -o /root/PH-Recon/$domain/subdomain/amass_sub_passive.txt
export CHAOS_KEY=8153077428be89cccb4f3f7e20f45a166c0f5565d9cb118b7c529a5d9ee5bd00
chaos -d $domain -o /root/PH-Recon/$domain/subdomain/chaos_sub.txt
/root/OK-VPS/tools/Lilly/./lilly.sh -d $domain -a hLRieliNwbe2vJf8TEXo3keLG2pZcdIP | tee -a /root/PH-Recon/$domain/subdomain/lilly_shodan.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/PH-Recon/$domain/subdomain/web.archive.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/PH-Recon/$domain/subdomain/crtsub.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/PH-Recon/$domain/subdomain/riddlersub.txt
curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee /root/PH-Recon/$domain/subdomain/bufferoversub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/PH-Recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/PH-Recon/$domain/subdomain/altnamesub.txt
shuffledns -d $domain -w $wordlist -r /root/wordlist/resolvers.txt -o /root/PH-Recon/$domain/subdomain/shuffledns.txt
cat /root/PH-Recon/$domain/subdomain/*.txt > /root/PH-Recon/$domain/subdomain/allsub.txt
cat /root/PH-Recon/$domain/subdomain/allsub.txt | uniq -u | grep $domain | tee -a /root/PH-Recon/$domain/subdomain/all_srot_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do

httpx -l /root/PH-Recon/$domain/subdomain/all_srot_sub.txt -threads 150 -o /root/PH-Recon/$domain/subdomain/good/passive_resolving_live_sub.txt

done
}
resolving_domains

#brut(){
#for domain in $(cat $host);
#do
#cp brut.sh /root/PH-Recon/$domain/subdomain/good
#cd /root/PH-Recon/$domain/subdomain/good
#./brut.sh passive_resolving_live_sub.txt
#done
#}
#brut

Recursive(){
for domain in $(cat /root/PH-Recon/$host);
do
cp /root/PH-Recon/web_archive_urls.sh /root/PH-Recon/$domain/url/
cp /root/PH-Recon/Recursive.sh /root/PH-Recon/$domain/subdomain/good/
cd /root/PH-Recon/$domain/subdomain/good
./Recursive.sh passive_resolving_live_sub.txt
done
}
Recursive

PH-Recon(){
for domain in $(cat /root/PH-Recon/$host);
do
cd /root/PH-Recon && ./PH-Recon.sh /root/PH-Recon/$host
done
}
PH-Recon

#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/Mrco24-Recon/$domain/subdomain /root/Mrco24-Recon/$domain/subdomain/good /root/Mrco24-Recon/$domain/subdomain/good/Gen_sub /root/Mrco24-Recon/$domain/Subomain-Takeover /root/Mrco24-Recon/$domain/Subomain-Screenshots /root/Mrco24-Recon/$domain/Special_subdomain /root/Mrco24-Recon/$domain/Special_subdomain/scan /root/Mrco24-Recon/$domain/scan  /root/Mrco24-Recon/$domain/scan/my-jaeles /root/Mrco24-Recon/$domain/scan/jaeles /root/Mrco24-Recon/$domain/scan/jaeles/my-url /root/Mrco24-Recon/$domain/scan/jaeles/url /root/Mrco24-Recon/$domain/dri  /root/Mrco24-Recon/$domain/scan/nuclei/Php-My-Admin /root/Mrco24-Recon/$domain/scan/nuclei /root/Mrco24-Recon/$domain/scan/new-nuclei /root/Mrco24-Recon/$domain/url /root/Mrco24-Recon/$domain/Secret-api /root/Mrco24-Recon/$domain/gf /root/Mrco24-Recon/$domain/xss /root/Mrco24-Recon/$domain/sql /root/Mrco24-Recon/$domain/js_url /root/Mrco24-Recon/$domain/git_dork /root/Mrco24-Recon/$domain/SQL

subfinder -d $domain -all -o /root/Mrco24-Recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/Mrco24-Recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/Mrco24-Recon/$domain/subdomain/findomain.txt
#sudomy -d $domain -o /root/Mrco24-Recon/$domain/subdomain/sudomy.txt
amass enum -active -d $domain -o /root/Mrco24-Recon/$domain/subdomain/amass_sub.txt
amass enum -passive -d $domain -o /root/Mrco24-Recon/$domain/subdomain/amass_sub_passive.txt
export CHAOS_KEY=8153077428be89cccb4f3f7e20f45a166c0f5565d9cb118b7c529a5d9ee5bd00
chaos -d $domain -o /root/Mrco24-Recon/$domain/subdomain/chaos_sub.txt
/root/OK-VPS/tools/Lilly/./lilly.sh -d $domain -a hLRieliNwbe2vJf8TEXo3keLG2pZcdIP | tee -a /root/Mrco24-Recon/$domain/subdomain/lilly_shodan.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/Mrco24-Recon/$domain/subdomain/web.archive.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/Mrco24-Recon/$domain/subdomain/crtsub.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/Mrco24-Recon/$domain/subdomain/riddlersub.txt
curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee /root/Mrco24-Recon/$domain/subdomain/bufferoversub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/Mrco24-Recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/Mrco24-Recon/$domain/subdomain/altnamesub.txt
shuffledns -d $domain -w $wordlist -r /root/wordlist/resolvers.txt -o /root/Mrco24-Recon/$domain/subdomain/shuffledns.txt
cat /root/Mrco24-Recon/$domain/subdomain/*.txt > /root/Mrco24-Recon/$domain/subdomain/allsub.txt
cat /root/Mrco24-Recon/$domain/subdomain/allsub.txt | uniq -u | grep $domain | tee -a /root/Mrco24-Recon/$domain/subdomain/all_srot_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do

httpx -l /root/Mrco24-Recon/$domain/subdomain/all_srot_sub.txt -threads 150 -o /root/Mrco24-Recon/$domain/subdomain/good/passive_resolving_live_sub.txt

done
}
resolving_domains

#brut(){
#for domain in $(cat $host);
#do
#cp brut.sh /root/Mrco24-Recon/$domain/subdomain/good
#cd /root/Mrco24-Recon/$domain/subdomain/good
#./brut.sh passive_resolving_live_sub.txt
#done
#}
#brut

Recursive(){
for domain in $(cat /root/Mrco24-Recon/$host);
do
cp /root/Mrco24-Recon/web_archive_urls.sh /root/Mrco24-Recon/$domain/url/
cp /root/Mrco24-Recon/Recursive.sh /root/Mrco24-Recon/$domain/subdomain/good/
cd /root/Mrco24-Recon/$domain/subdomain/good
./Recursive.sh passive_resolving_live_sub.txt
done
}
Recursive

Mrco24-Recon(){
for domain in $(cat /root/Mrco24-Recon/$host);
do
cd /root/Mrco24-Recon && ./Mrco24-Recon.sh /root/Mrco24-Recon/$host
done
}
Mrco24-Recon

#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/PH-PH-Recon/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/PH-Recon/$domain/subdomain /root/PH-Recon/$domain/subdomain/good  /root/PH-Recon/$domain/Subomain-Takeover /root/PH-Recon/$domain/Subomain-Screenshots /root/PH-Recon/$domain/Special_subdomain /root/PH-Recon/$domain/Special_subdomain/scan /root/PH-Recon/$domain/scan  /root/PH-Recon/$domain/scan/my-jaeles /root/PH-Recon/$domain/scan/jaeles /root/PH-Recon/$domain/scan/jaeles/my-url /root/PH-Recon/$domain/scan/jaeles/url /root/PH-Recon/$domain/dri  /root/PH-Recon/$domain/scan/nuclei/Php-My-Admin /root/PH-Recon/$domain/scan/nuclei /root/PH-Recon/$domain/scan/new-nuclei /root/PH-Recon/$domain/url /root/PH-Recon/$domain/Secret-api /root/PH-Recon/$domain/gf /root/PH-Recon/$domain/xss /root/PH-Recon/$domain/sql /root/PH-Recon/$domain/js_url /root/PH-Recon/$domain/git_dork /root/PH-Recon/$domain/SQL

subfinder -d $domain -all -o /root/PH-PH-Recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/PH-PH-Recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/PH-PH-Recon/$domain/subdomain/findomain.txt
amass enum -passive -d $domain -o /root/PH-PH-Recon/$domain/subdomain/amass_sub_passive.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/PH-PH-Recon/$domain/subdomain/web.archive.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/PH-PH-Recon/$domain/subdomain/crtsub.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/PH-PH-Recon/$domain/subdomain/riddlersub.txt
curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee /root/PH-PH-Recon/$domain/subdomain/bufferoversub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/PH-PH-Recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/PH-PH-Recon/$domain/subdomain/altnamesub.txt
cat /root/PH-PH-Recon/$domain/subdomain/*.txt > /root/PH-PH-Recon/$domain/subdomain/allsub.txt
cat /root/PH-PH-Recon/$domain/subdomain/allsub.txt | uniq -u | grep $domain | tee -a /root/PH-PH-Recon/$domain/subdomain/all_srot_sub.txt
done
}
domain_enum

resolving_domains(){
for domain in $(cat $host);
do
httpx -l /root/PH-PH-Recon/$domain/subdomain/all_srot_sub.txt -threads 150 -o /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt 
done
}
resolving_domains

Subdomai_takeover(){
for domain in $(cat $host);
do
subzy run --targets /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/PH-Recon/$domain/Subomain-Takeover/sub_poc.txt
done
}
Subdomai_takeover

open_port(){
for domain in $(cat $host);
do
naabu -list /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/PH-Recon/$domain/scan/open-port.txt
naabu -list /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt -p - -exclude-ports 80,443,21,22,25 -o /root/PH-Recon/$domain/scan/filter-all-open-port.txt
done
}
open_port

web_Screenshot(){
for domain in $(cat $host);
do
cd /root/PH-Recon/$domain/Subomain-Screenshots 
gowitness file -f /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt
done
}
web_Screenshot

#Http-Request-Smugglingr(){
#for domain in $(cat $host);
#do
#cd /root/OK-VPS/tools/http-request-smuggling | python3 smuggle.py -urls /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/PH-Recon/$domain/scan/Http-Request-Smugglingr.txt
#done
#}
#Http-Request-Smugglingr

Php_My_Admin(){
for domain in $(cat $host);
do
nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/php-my-admin/phpadmin.yaml -l /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt -c 50  -o /root/PH-Recon/$domain/scan/nuclei/Php-My-Admin/php_admin.txt -v
done
}
Php_My_Admin

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/PH-PH-Recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker

vuln_scanner(){
for domain in $(cat $host);
do
nuclei -l /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt -t /root/nuclei-templates/ -c 50 -o /root/PH-PH-Recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt -o /root/PH-PH-Recon/$domain/scan/jaeles/ -v
done
}
vuln_scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt |  gauplus -t 40 | tee -a /root/PH-PH-Recon/$domain/url/gaplus-urls.txt
cat /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt | waybackurls | tee /root/PH-PH-Recon/$domain/url/waybackurls.txt
cat /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt | hakrawler | tee -a /root/PH-PH-Recon/$domain/url/hakrawler-urls.txt
gospider -S /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > /root/PH-PH-Recon/$domain/url/gospider-url.txt
cat /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/PH-PH-Recon/$domain/url/all_spiderparamters.txt
cd /root/PH-Recon/$domain/url && ./web_archive_urls.sh /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt
cat /root/PH-Recon/$domain/url/*.txt > /root/PH-Recon/$domain/url/all-url.txt
cat /root/PH-Recon/$domain/url/all-url.txt | sort --unique | grep $domain | tee /root/PH-PH-Recon/$domain/url/final-url.txt
cat /root/PH-Recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/PH-PH-Recon/$domain/url/valid_urls.txt
done
}
find_urls

Url_endpoints(){
for domain in $(cat $host);
do
cat /root/PH-PH-Recon/$domain/url/final-url.txt | cut -d "/" -f4- >> /root/PH-PH-Recon/$domain/url/url_endpoints.txt
done
}
Url_endpoints

gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/PH-PH-Recon/$domain/url/valid_urls.txt | tee /root/PH-Recon/$domain/gf/xss.txt
gf my-lfi /root/PH-PH-Recon/$domain/url/valid_urls.txt | tee /root/PH-Recon/$domain/gf/my-lfi.txt
gf sqli /root/PH-PH-Recon/$domain/url/valid_urls.txt | tee /root/PH-Recon/$domain/gf/sqli.txt
gf lfi /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/lfi.txt
gf redirect /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/rmy-lfiedirect.txt
gf aws-keys /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/aws-keys-json.txt
gf interestingsubs /root/PH-PH-Recon/$domain/subdomain/good/active_subdomain.txt |  tee /root/PH-Recon/$domain/gf/interestingsubs.txt
gf s3-buckets /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/s3-buckets.txt
gf servers /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/servers.txt
gf debug-pages /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/debug-pages.txt
gf debug_logic /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/debug_logic.txt
gf img-traversal /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/img-traversal.txt
gf php-sources /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/php-sources.txt
gf upload-fields /root/PH-PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/upload-fields.txt
gf php-errors /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/php-errors.txt
gf http-auth /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/http-auth.txt
gf idor /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/idor.txt
gf interestingparams /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/interestingparams.txt
gf interestingEXT /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/interestingEXT.txt
gf rce /root/PH-Recon/$domain/url/valid_urls.txt |  tee /root/PH-Recon/$domain/gf/rce.txt
done
}
gf_patterns

SQL(){
for domain in $(cat $host);
do
mrco24-error-sql -f /root/PH-Recon/$domain/url/valid_urls.txt -t 40 -o /root/PH-Recon/$domain/sql/error-sql-injection.txt -v
sqlmap -m /root/PH-Recon/$domain/url/valid_urls.txt --batch --risk 3  --random-agent | tee -a /root/PH-Recon/$domain/sql/sqlmap_sql_url.txt
done
}
SQL

Refactors_xss(){
for domain in $(cat $host);
do
cat /root/PH-Recon/$domain/url/valid_urls.txt | Gxss -o /root/PH-Recon/$domain/xss/gxss.txt
cat /root/PH-Recon/$domain/url/valid_urls.txt | kxss | tee -a  /root/PH-Recon/$domain/xss/kxss_url.txt
cat /root/PH-Recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/PH-Recon/$domain/xss/kxss_url_active.txt
cat /root/PH-Recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/PH-Recon/$domain/xss/kxss_dalfoxss.txt
cat /root/PH-Recon/$domain/xss/gxss.txt | dalfox pipe | tee /root/PH-Recon/$domain/xss/gxss_dalfoxss.txt
cat /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh
done
}
Refactors_xss

dir-traversal(){
for domain in $(cat $host);
do
mrco24-lfi -f /root/PH-Recon/$domain/url/valid_urls.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o /root/PH-Recon/$domain/scan/lfi.txt
done
}
dir-traversal

Bilnd_xss(){
for domain in $(cat $host);
do
nuclei -l /root/PH-Recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100  -o /root/PH-Recon/$domain/xss/header_blind_xss.txt -v
done
}
Bilnd_xss

Fuzz_Endpoint(){
for domain in $(cat $host);
do
dirsearch -l /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt -w /root/PH-Recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/PH-Recon/$domain/dri/Endpoint_Dir.txt
done
}
Fuzz_Endpoint

FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/PH-Recon/$domain/subdomain/good/active_subdomain.txt  > /root/PH-Recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active

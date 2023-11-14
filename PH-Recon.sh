#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/PH-Recon/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/PH-Recon/$domain/subdomain /root/PH-Recon/$domain/subdomain/good  /root/PH-Recon/$domain/Subomain-Takeover /root/PH-Recon/$domain/Subomain-Screenshots /root/PH-Recon/$domain/Special_subdomain /root/PH-Recon/$domain/Special_subdomain/scan /root/PH-Recon/$domain/scan  /root/PH-Recon/$domain/scan/my-jaeles /root/PH-Recon/$domain/scan/jaeles /root/PH-Recon/$domain/scan/jaeles/my-url /root/PH-Recon/$domain/scan/jaeles/url /root/PH-Recon/$domain/dri  /root/PH-Recon/$domain/scan/nuclei/Php-My-Admin /root/PH-Recon/$domain/scan/nuclei /root/PH-Recon/$domain/scan/new-nuclei /root/PH-Recon/$domain/url /root/PH-Recon/$domain/Secret-api /root/PH-Recon/$domain/gf /root/PH-Recon/$domain/xss /root/PH-Recon/$domain/sql /root/PH-Recon/$domain/js_url /root/PH-Recon/$domain/git_dork /root/PH-Recon/$domain/SQL

subfinder -d $domain -all -o /root/PH-Recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/PH-Recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/PH-Recon/$domain/subdomain/findomain.txt
amass enum -passive -d $domain -o /root/PH-Recon/$domain/subdomain/amass_sub_passive.txt
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

http_probe(){
for domain in $(cat $host);
do
cat /root/PH-Recon/$domain/subdomain/good/passive_resolving_live_sub.txt | httprobe | tee -a /root/recon/$domain/subdomain/good/active_subdomain.txt 
done
}
http_probe

Subdomai_takeover(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/active_subdomain.txt  -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/subdomain-takeover/subdomain-takeover_detect-all-takeovers.yaml -c 100 -o /root/recon/$domain/Subomain-Takeover/poc.txt -v
done
}
Subdomai_takeover

open_port(){
for domain in $(cat $host);
do
naabu -list /root/recon/$domain/subdomain/good/active_subdomain.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/open-port.txt
naabu -list /root/recon/$domain/subdomain/good/active_subdomain.txt -p - -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/filter-all-open-port.txt
done
}
open_port

web_Screenshot(){
for domain in $(cat $host);
do
cd /root/recon/$domain/Subomain-Screenshots 
gowitness file -f /root/recon/$domain/subdomain/good/active_subdomain.txt
done
}
web_Screenshot

Http-Request-Smugglingr(){
for domain in $(cat $host);
do
cd /root/OK-VPS/tools/http-request-smuggling | python3 smuggle.py -urls /root/recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/recon/$domain/scan/Http-Request-Smugglingr.txt
done
}
Http-Request-Smugglingr

Php_My_Admin(){
for domain in $(cat $host);
do
nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/php-my-admin/phpadmin.yaml -l /root/recon/$domain/subdomain/good/active_subdomain.txt -c 50  -o /root/recon/$domain/scan/nuclei/Php-My-Admin/php_admin.txt -v
done
}
Php_My_Admin

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker


vuln_scanner(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/active_subdomain.txt -t /root/nuclei-templates/ -c 50 -o /root/recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/jaeles/ -v
done
}
vuln_scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt |  gauplus -t 40 | tee -a /root/recon/$domain/url/gaplus-urls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | hakrawler | tee -a /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt
cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/active_subdomain.txt
cat /root/recon/$domain/url/*.txt > /root/recon/$domain/url/all-url.txt
cat /root/recon/$domain/url/all-url.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/recon/$domain/url/valid_urls.txt
done
}
find_urls

Url_endpoints(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/final-url.txt | cut -d "/" -f4- >> /root/recon/$domain/url/url_endpoints.txt
done
}
Url_endpoints


gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf my-lfi /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/my-lfi.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/rmy-lfiedirect.txt
gf aws-keys /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/aws-keys-json.txt
gf interestingsubs /root/recon/$domain/subdomain/good/active_subdomain.txt |  tee /root/recon/$domain/gf/interestingsubs.txt
gf s3-buckets /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/s3-buckets.txt
gf servers /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/servers.txt
gf debug-pages /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug-pages.txt
gf debug_logic /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug_logic.txt
gf img-traversal /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/img-traversal.txt
gf php-sources /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-sources.txt
gf upload-fields /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/upload-fields.txt
gf php-errors /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-errors.txt
gf http-auth /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/http-auth.txt
gf idor /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/idor.txt
gf interestingparams /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingparams.txt
gf interestingEXT /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingEXT.txt
gf rce /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/rce.txt
done
}
gf_patterns

SQL(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/error-based-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/error-based-sql-injection.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/SQLInjection_ERROR.yaml -c 100  -o /root/recon/$domain/sql/SQLInjection_ERROR.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-time-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/header-blind-time-sql-injection.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/header-blind-sql-injection.txt -v
sqlmap -m /root/recon/$domain/url/valid_urls.txt --batch --risk 3  --random-agent | tee -a /root/recon/$domain/sql/sqlmap_sql_url.txt
done
}
SQL


Refactors_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | Gxss -o /root/recon/$domain/xss/gxss.txt
cat /root/recon/$domain/url/valid_urls.txt | kxss | tee -a  /root/recon/$domain/xss/kxss_url.txt
cat /root/recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/recon/$domain/xss/kxss_url_active.txt
cat /root/recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/recon/$domain/xss/kxss_dalfoxss.txt
cat /root/recon/$domain/xss/gxss.txt | dalfox pipe | tee /root/recon/$domain/xss/gxss_dalfoxss.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh
done
}
Refactors_xss

Bilnd_xss(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100  -o /root/recon/$domain/xss/header_blind_xss.txt -v
done
}
Bilnd_xss

dir-traversal(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/dir-traversal.yaml -c 100  -o /root/recon/$domain/scan/nuclei/dir-traversal.txt -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header -v
jaeles scan -c 50 -s /root/templates/best/lfi-param-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-param -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-windows-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header-windows -v
done
}
dir-traversal

Nuclei Fuzz_Endpoint(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/fuzzing-templates/  -o /root/recon/$domain/scan/nuclei/urls_fuzzing-templates__scan.txt -v
done
}
Nuclei Fuzz_Endpoint


Fuzz_Endpoint(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/active_subdomain.txt -w /root/recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/recon/$domain/dri/Endpoint_Dir.txt
done
}
Fuzz_Endpoint

FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/active_subdomain.txt  > /root/recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active


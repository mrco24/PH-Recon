 #!/bin/bash

domain=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
resolver="root/wordlist/resolvers.txt"

domain_enum(){

mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/scan /root/recon/$domain/url /root/recon/$domain/gf

subfinder -d $domain -o /root/recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/recon/$domain/subdomain/assetfinder.txt 
amass enum -passive -d $domain -o /root/recon/$domain/subdomain/passive.txt
shuffledns -d $domain  -w $wordlist -r $resolver -o /root/recon/$domain/subdomain/shuffledns.txt 

cat /root/recon/$domain/subdomain/*.txt > /root/recon/$domain/subdomain/all.txt

}
domain_enum

resolving_domains(){
shuffledns -d $domain -list /root/recon/$domain/subdomain/all.txt -o /root/recon/$domain/subdomain/sudomain.txt -r $resolver
}
resolving_domains

http_prob(){
cat /root/recon/$domain/subdomain/sudomain.txt | httpx -threads 200 -o /root/recon/$domain/subdomain/active_subdomain.txt 
}
http_prob

scanner(){
cat /root/recon/$domain/subdomain/active_subdomain.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o /root/recon/$domain/scan/cves.txt
cat /root/recon/$domain/subdomain/active_subdomain.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o /root/recon/$domain/scan/vulnerabilities.txt
cat /root/recon/$domain/subdomain/active_subdomain.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o /root/recon/$domain/scan/technologies.txt
}
scanner

wayback_urls(){
cat /root/recon/$domain/subdomain/sudomain.txt | waybackurls | tee /root/recon/$domain/url/waybackurls.txt

cat /root/recon/$domain/url/waybackurls.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/recon/$domain/url/good_urls.txt
}
wayback_urls

valid_urls(){
fuzzer -c -u "fuff -W /root/recon/$domain/url/good_urls.txt -of csv -o /root/recon/$domain/url/ffuf_urls.txt
cat /root/recon/$domain/url/ffuf_urls.txt | grep http awk -F "," '(print $1)' >> /root/recon/$domain/url/valid_urls.txt
}
valid_urls

gf_patterns(){
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
}
gf_patterns

"""
    To extract relevant features from the given URL.
"""

# required modules
import os
import re
import ipaddress
import socket
import requests
import whois
import tldextract
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from googlesearch import search
from urllib.parse import urlparse

# constants conatin api key values
import constants

class URL_Features():
    """
    
    """
    
    def __init__(self, url):
        self.url = url
        self.features = {}
        self.response = None
        self.soup = None
        self.urlparse = None
        self.scheme = None
        self.domain = None
        self.whois = None
        self.tldextract = None
        self.root_domain = None
        self.cpr_response = None
        self.alexa_rank = None
        self.similarweb_rank = None
        self.similarweb_traffic = None

        try:
            self.response = requests.get(url, timeout=5)
            if self.response.status_code == 200:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            else:
                pass
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            print('urlparse:', self.urlparse)
            self.domain = self.urlparse.netloc
            print('domain:', self.domain)
            self.scheme = self.urlparse.scheme
        except:
            pass

        try:
            self.whois = whois.whois(self.domain)
        except:
            pass

        try:
            self.tldextract = tldextract.extract(self.url)
            print('tld_extract:', self.tldextract)
            self.root_domain = self.tldextract.domain + '.' + self.tldextract.suffix
        except:
            pass

        if self.domain:
            try:
                check_page_rank_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
                self.cpr_response = check_page_rank_response.text
            except:
                pass
        
            try:
                self.similarweb_rank = requests.get("https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={similarweb_api_key}".format(domain = self.domain.replace('www', ''), similarweb_api_key = constants.SIMILARWEB_API_KEY)).json()
                print('rank:', self.similarweb_rank)
            except:
                pass

        self.features['url'] = self.url
        self.features['url_length'] = self.url_len()
        self.features['hostname_length'] = self.hostname_len()
        self.features['is_ip'] = self.using_ip_address()
        self.features['count_dots'] = self.having_dots()
        self.features['count_hyphens'] = self.having_hyphen()
        self.features['count_at'] = self.having_at()
        self.features['count_question_mark'] = self.having_questionMark()
        self.features['count_and'] = self.having_and()
        self.features['count_equals'] = self.having_equals()
        self.features['count_underscore'] = self.having_underscore()
        self.features['count_percentage'] = self.having_percentage()
        self.features['count_slash'] = self.having_slash()
        self.features['count_www'] = self.having_www()
        self.features['http_in_path'] = self.http_in_domain()
        self.features['https_token'] = self.url_scheme()
        self.features['ratio_digits_url'] = self.ratio_digits_url()
        self.features['count_subdomains'] = self.subdomain_count()
        self.features['prefix_sufix'] = self.prefixSuffix()

        self.features['count_hyperlinks'] = self.hyperlinks_count()
        self.features['ratio_int_hyperlinks'] = self.ratio_int_hyperlink()
        self.features['ratio_ext_hyperlinks'] = self.ratio_ext_hyperlink()
        self.features['ext_favicon'] = self.ext_favicon_check()
        self.features['links_in_tags'] = self.links_in_tags()
        self.features['iframe'] = self.iframe_redirection()
        self.features['safe_anchor'] = self.safe_anchor()

        self.features['whois_reg'] = self.whois_registered_domain()
        self.features['domain_reg_len'] = self.domain_reg_length()
        self.features['domain_age'] = self.domain_age()
        self.features['similarweb_rank'] = 0 #self.website_traffic()

    #Check if a given string can be a URL 
    @staticmethod
    def is_urlPattern(url) -> bool:
        url_regex = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if re.match(url_regex, url):
            return True
        else:
            return False
    
    # URL Length
    def url_len(self):
        return len(self.url)
    
    # Hostname length of URL
    def hostname_len(self):
        url_hostname = self.tldextract.subdomain +'.'+ self.tldextract.domain +'.'+ self.tldextract.suffix
        return len(url_hostname)
    
    # Using IP Address
    def using_ip_address(self):
        try:
            ipaddress.ip_address(self.url)
            return 1
        except:
            return 0
        
    # Number of '.' in URL
    def having_dots(self):
        return self.url.count('.')
    
    # Number of '-' in URL
    def having_hyphen(self):
        return self.url.count('-')

    # Number of '@' symbol
    def having_at(self):
        return self.url.count('@')
    
    # Number of '/' in URL
    def having_slash(self):
        return self.url.count('/')
    
    # Number of '=' in URL
    def having_equals(self):
        return self.url.count('=')
    
    # Number of '_' in URL
    def having_underscore(self):
        return self.url.count('_')
    
    # Number 0f '?' in URL
    def having_questionMark(self):
        return self.url.count('?')
    
    # Number 0f '&' in URL
    def having_and(self):
        return self.url.count('&')

    # Number 0f '%' in URL
    def having_percentage(self):
        return self.url.count('%')

    # Number 0f 'www' in URL
    def having_www(self):
        return self.url.count('www')

    # http or htpps scheme
    def url_scheme(self):
        print('scheme:', self.scheme)
        if self.scheme == 'https':
            return 1
        else:
            return 0

    # Check 'https' presence in domain
    def http_in_domain(self):
        if self.domain:
            if 'https' in self.domain or 'http' in self.domain:
                return 1
            return 0
    
    # Ratio of digits to URL
    def ratio_digits_url(self):
        url_len = len(self.url)
        digits_url = sum(char.isdigit() for char in self.url)
        ratio = digits_url/url_len
        return ratio
        
    # Sub Domains and Multi Sub Domains
    def subdomain_count(self):
        if self.tldextract:
            subdomains = self.tldextract.subdomain.split('.')
            return(len(subdomains))
        
    # Having prefix suffix in domain name
    def prefixSuffix(self):
        if self.domain:
            if self.domain.count('-'):
                return 1
            else:
                return 0

    # Number of hyperlinks in HTML
    def hyperlinks_count(self):
        if self.soup:
            hyperlinks = self.soup.find_all('a')
            return len(hyperlinks)
        
    # Ratio of internal hyperlinks
    def ratio_int_hyperlink(self):
        internal_hlink_count =  0
        if self.soup:
            total_hyperlinks = self.soup.find_all('a')
            for link in total_hyperlinks:
                if 'href' in link.attrs and (link['href'].startswith('http') or link['href'].startswith('https')):
                    if self.root_domain in link['href']:
                        internal_hlink_count += 1
                else:
                    internal_hlink_count += 1
            return (internal_hlink_count/len(total_hyperlinks))
    
    # Ratio of external hyperlinks
    def ratio_ext_hyperlink(self):
        external_hlink_count = 0
        if self.soup:
            total_hyperlinks = self.soup.find_all('a')
            for link in total_hyperlinks:
                if 'href' in link.attrs and (link['href'].startswith('http') or link['href'].startswith('https')):
                    if not self.root_domain in link['href']:
                        external_hlink_count += 1
            return (external_hlink_count/len(total_hyperlinks))

    # Check for external favicon
    def ext_favicon_check(self):
        if self.soup:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    if head.link['rel'][-1] == 'icon':
                        src = head.link['href']
                        if self.root_domain in src or src.count('.')==1:
                            return 0
                        else:
                            return 1
            return 0
        
    # Script and link tags
    def links_in_tags(self):
        if self.soup:
            external_objects = 0
            total_objects = 0
            for meta in self.soup.find_all('meta', content=True):
                content = meta['content']
                if URL_Features.is_urlPattern(self.url) and self.root_domain not in content:
                    external_objects += 1
                total_objects += 1
            for links in self.soup.find_all('links', href=True):
                href = links['href']
                if self.root_domain not in href or href.count('.') > 1:
                    external_objects += 1
                total_objects += 1          
            for script in self.soup.find_all('script', src=True):
                src = script['src']
                if self.root_domain not in src or src.count('.') > 1:
                    external_objects += 1
                total_objects += 1
            percentage = external_objects/total_objects * 100
            return (percentage)
        
    # iframe Redirection
    def iframe_redirection(self):
        if self.soup:
            for iframe in self.soup.find_all('iframe', frameborder=True):
                if iframe['frameborder'] == 0:
                    return 1
            for iframe in self.soup.find_all('iframe', style=True):
                if iframe['style'] == 'display:none;visibility:hidden':
                    return 1
            return 0
        else:
            return 0

    # safe anchor
    def safe_anchor(self):
        if self.soup:
            unsafe_anchor = 0
            anchors = self.soup.find_all('a')
            for a in anchors:
                if 'href' in a.attrs and a['href'].startswith("javascript:"):
                    unsafe_anchor += 1
            percentage = (len(anchors) - unsafe_anchor)/len(anchors) * 100
            return percentage
        else:
            return 0
        
    # WHOIS registered
    def whois_registered_domain(self):
        if self.whois:
            if self.whois.status:
                return 1
            else:
                return 0
        return 0

    # Domain Registrastion length
    def domain_reg_length(self):
        if self.whois:
            expiration_dt = self.whois.expiration_date
            if type(expiration_dt) == list:
                expiration_dt = expiration_dt[0]
            reg_length = (expiration_dt - datetime.now()).days
            return (reg_length)

    # Age of Domain
    def domain_age(self):
        if self.whois:
            creation_date = self.whois.creation_date
            try:
                if len(creation_date) > 1:
                    creation_date = creation_date[0]
            except:
                pass
            today = datetime.now()
            age = (today - creation_date).days
            return age
        else:
            return -1

    # Website Traffic
    def website_traffic(self):
        pass

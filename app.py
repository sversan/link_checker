from flask import Flask, render_template, request, jsonify
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import tldextract
import whois
from datetime import datetime
import socket
import json

app = Flask(__name__)

class LinkChecker:
    def __init__(self):
        # Known malicious patterns
        self.malicious_patterns = [
            r'javascript:', 
            r'data:text/html',
            r'vbscript:',
            r'%[0-9a-fA-F]{2}',
            r'(?:\\x[0-9a-fA-F]{2})+',
            r'<script>',
            r'document\.',
            r'window\.',
            r'eval\(',
            r'exec\(',
            r'fromCharCode\(',
            r'base64_decode\('
        ]
        
        # Suspicious URL parameters
        self.suspicious_params = [
            'cmd', 'exec', 'command', 'run', 'query', 'sql',
            'q', 'search', 'id', 'file', 'document', 'folder',
            'path', 'pg', 'redirect', 'url', 'next', 'data',
            'input', 'output', 'load', 'process', 'upload'
        ]
        
        # Known malicious domains (can be extended)
        self.known_malicious_domains = set()
        
        # User agents for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def check_link(self, url):
        """Main function to check a URL for malicious content"""
        report = {
            'url': url,
            'is_malicious': False,
            'warnings': [],
            'redirect_chain': [],
            'final_url': None,
            'domain_info': None,
            'form_analysis': None,
            'parameters_analysis': None
        }
        
        try:
            # 1. Basic URL validation
            if not self._is_valid_url(url):
                report['warnings'].append("Invalid URL format")
                report['is_malicious'] = True
                return report
            
            # 2. Check for malicious patterns in URL
            url_checks = self._check_url_patterns(url)
            report['warnings'].extend(url_checks['warnings'])
            if url_checks['is_malicious']:
                report['is_malicious'] = True
            
            # 3. Analyze URL parameters
            parsed_url = urllib.parse.urlparse(url)
            params_analysis = self._analyze_parameters(parsed_url.query)
            report['parameters_analysis'] = params_analysis
            if params_analysis['is_malicious']:
                report['is_malicious'] = True
            
            # 4. Check domain reputation
            domain_info = self._analyze_domain(parsed_url.netloc)
            report['domain_info'] = domain_info
            if domain_info['is_suspicious']:
                report['warnings'].append("Suspicious domain characteristics")
                report['is_malicious'] = True
            
            # 5. Follow redirects
            redirect_info = self._follow_redirects(url)
            report['redirect_chain'] = redirect_info['chain']
            report['final_url'] = redirect_info['final_url']
            if redirect_info['is_malicious']:
                report['is_malicious'] = True
            
            # 6. Analyze page content if it's a form/button
            if parsed_url.path.endswith(('.php', '.asp', '.aspx', '.jsp', '.html')):
                content_analysis = self._analyze_page_content(url)
                report['form_analysis'] = content_analysis
                if content_analysis['is_malicious']:
                    report['is_malicious'] = True
            
        except Exception as e:
            report['warnings'].append(f"Error during analysis: {str(e)}")
            report['is_malicious'] = True
        
        return report
    
    def _is_valid_url(self, url):
        """Check if URL has valid format"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _check_url_patterns(self, url):
        """Check URL for known malicious patterns"""
        result = {
            'is_malicious': False,
            'warnings': []
        }
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result['warnings'].append(f"Malicious pattern detected: {pattern}")
                result['is_malicious'] = True
        
        # Check for IP address instead of domain
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            result['warnings'].append("URL uses IP address instead of domain name")
            result['is_malicious'] = True
        
        # Check for URL encoding tricks
        decoded_url = urllib.parse.unquote(url)
        if decoded_url != url:
            for pattern in self.malicious_patterns:
                if re.search(pattern, decoded_url, re.IGNORECASE):
                    result['warnings'].append(f"Encoded malicious pattern detected: {pattern}")
                    result['is_malicious'] = True
        
        return result
    
    def _analyze_parameters(self, query_string):
        """Analyze URL query parameters"""
        result = {
            'parameters': {},
            'is_malicious': False,
            'warnings': []
        }
        
        params = urllib.parse.parse_qs(query_string)
        result['parameters'] = params
        
        for param, values in params.items():
            # Check if parameter name is suspicious
            if any(susp_param in param.lower() for susp_param in self.suspicious_params):
                result['warnings'].append(f"Suspicious parameter name: {param}")
                result['is_malicious'] = True
            
            # Check parameter values for malicious patterns
            for value in values:
                for pattern in self.malicious_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        result['warnings'].append(f"Malicious pattern in parameter {param}: {pattern}")
                        result['is_malicious'] = True
        
        return result
    
    def _analyze_domain(self, domain):
        """Analyze domain characteristics"""
        result = {
            'domain': domain,
            'is_suspicious': False,
            'age_days': None,
            'registrar': None,
            'creation_date': None,
            'ip_address': None,
            'reverse_dns': None,
            'warnings': []
        }
        
        try:
            # Extract domain info
            extracted = tldextract.extract(domain)
            domain_name = f"{extracted.domain}.{extracted.suffix}"
            
            # Get WHOIS information
            domain_info = whois.whois(domain_name)
            
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age = (datetime.now() - creation_date).days
                result['age_days'] = age
                result['creation_date'] = str(creation_date)
                
                # New domains are more suspicious
                if age < 30:
                    result['warnings'].append(f"Domain is very new ({age} days old)")
                    result['is_suspicious'] = True
            
            result['registrar'] = domain_info.registrar
            
            # Get IP address
            ip = socket.gethostbyname(domain)
            result['ip_address'] = ip
            
            # Reverse DNS
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
                result['reverse_dns'] = reverse_dns
                
                # Check if reverse DNS matches
                if not domain.endswith(reverse_dns):
                    result['warnings'].append("Reverse DNS doesn't match domain")
                    result['is_suspicious'] = True
            except:
                pass
            
        except Exception as e:
            result['warnings'].append(f"Could not complete domain analysis: {str(e)}")
            result['is_suspicious'] = True
        
        return result
    
    def _follow_redirects(self, url):
        """Follow URL redirects and check each hop"""
        result = {
            'chain': [],
            'final_url': None,
            'is_malicious': False,
            'warnings': []
        }
        
        try:
            session = requests.Session()
            response = session.head(url, allow_redirects=True, headers=self.headers, timeout=10)
            
            # Get redirect history
            if response.history:
                for resp in response.history:
                    result['chain'].append({
                        'url': resp.url,
                        'status_code': resp.status_code,
                        'headers': dict(resp.headers)
                    })
                    
                    # Check each redirect URL
                    url_checks = self._check_url_patterns(resp.url)
                    if url_checks['is_malicious']:
                        result['is_malicious'] = True
                        result['warnings'].extend(url_checks['warnings'])
            
            result['final_url'] = response.url
            
            # Check final URL
            url_checks = self._check_url_patterns(response.url)
            if url_checks['is_malicious']:
                result['is_malicious'] = True
                result['warnings'].extend(url_checks['warnings'])
            
            # Check for open redirects
            if len(result['chain']) > 0:
                initial_domain = urllib.parse.urlparse(url).netloc
                final_domain = urllib.parse.urlparse(response.url).netloc
                
                if initial_domain != final_domain:
                    result['warnings'].append(f"Redirects to different domain: {final_domain}")
                    result['is_malicious'] = True
        
        except Exception as e:
            result['warnings'].append(f"Error following redirects: {str(e)}")
            result['is_malicious'] = True
        
        return result
    
    def _analyze_page_content(self, url):
        """Analyze page content for forms and hidden elements"""
        result = {
            'forms': [],
            'is_malicious': False,
            'warnings': []
        }
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                    'is_suspicious': False
                }
                
                # Check form action
                if form_data['action']:
                    action_checks = self._check_url_patterns(form_data['action'])
                    if action_checks['is_malicious']:
                        form_data['is_suspicious'] = True
                        result['warnings'].append(f"Malicious form action: {form_data['action']}")
                        result['is_malicious'] = True
                
                # Analyze form inputs
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'is_hidden': input_tag.get('type') == 'hidden'
                    }
                    
                    form_data['inputs'].append(input_data)
                    
                    # Check for hidden fields with suspicious names
                    if input_data['is_hidden'] and any(
                        susp_param in input_data['name'].lower() 
                        for susp_param in self.suspicious_params
                    ):
                        form_data['is_suspicious'] = True
                        result['warnings'].append(
                            f"Suspicious hidden field: {input_data['name']}"
                        )
                        result['is_malicious'] = True
                
                result['forms'].append(form_data)
        
        except Exception as e:
            result['warnings'].append(f"Error analyzing page content: {str(e)}")
            result['is_malicious'] = True
        
        return result

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        checker = LinkChecker()
        report = checker.check_link(url)
        return render_template('index.html', report=report, url=url)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Spider:
    def __init__(self, target_url, client):
        self.target_url = target_url
        self.client = client
        # Restrict crawling to the target domain
        self.domain = urlparse(target_url).netloc

    def crawl(self):
        discovered_links = set()
        discovered_forms = []
        
        response = self.client.get(self.target_url)
        if not response:
            return [], []

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract standard GET links
        for a_tag in soup.find_all('a', href=True):
            full_url = urljoin(self.target_url, a_tag['href'])
            if urlparse(full_url).netloc == self.domain:
                discovered_links.add(full_url)
                
        # Extract forms and their input fields for POST/GET params
        for form in soup.find_all('form'):
            action = form.get('action') or self.target_url
            full_action_url = urljoin(self.target_url, action)
            method = form.get('method', 'get').upper()
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    inputs.append(name)
            
            if urlparse(full_action_url).netloc == self.domain:
                discovered_forms.append({
                    "url": full_action_url,
                    "method": method,
                    "params": inputs
                })
                
        return list(discovered_links), discovered_forms
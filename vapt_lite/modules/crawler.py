import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(start_url, max_pages=15):
    """Crawls to find internal paths and returns a flat list of URLs."""
    
    if not start_url.startswith("http"):
        start_url = "http://" + start_url
        
    visited = []
    urls_to_visit = [start_url]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.5'
    }
    
    domain = urlparse(start_url).netloc
    
    while urls_to_visit and len(visited) < max_pages:
        current_url = urls_to_visit.pop(0)
        
        if current_url in visited:
            continue
            
        try:
            response = requests.get(current_url, headers=headers, timeout=5, allow_redirects=True)
            visited.append(current_url) 
            
            if response.status_code != 200:
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(current_url, href)
                
                if full_url.startswith('http') and domain in full_url:
                    if full_url not in visited and full_url not in urls_to_visit:
                        urls_to_visit.append(full_url)
                        
        except Exception:
            # Drop the URL immediately on timeout or error
            continue
            
    return visited
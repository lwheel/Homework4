import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue, PriorityQueue
from urllib import parse, request

logging.basicConfig(level=logging.DEBUG, filename='output.log', filemode='w')
visitlog = logging.getLogger('visited')
extractlog = logging.getLogger('extracted')


def parse_links(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string
            if not text:
                text = ''
            text = re.sub(r'\s+', ' ', text).strip()
            yield (parse.urljoin(root, href), text)


def parse_links_sorted(root, html):
    links = list(parse_links(root, html))
    def relevance(pair):
        _, text = pair
        return -sum(c.isalnum() for c in text) 
    return sorted(links, key=relevance)


def get_links(url):
    res = request.urlopen(url)
    return list(parse_links(url, res.read()))

#to help comparing same domains ( with www and without, strip all of them for ease)
def strip_www(domain):
    """Remove 'www.' from the start of a domain, if present."""
    return domain.lower().lstrip("www.")

def get_nonlocal_links(url):
    '''Get a list of links on the page specificed by the url,
    but only keep non-local links and non self-references.
    Return a list of (link, title) pairs, just like get_links()'''


    links = get_links(url)
    filtered = []
    root_parts = parse.urlparse(url)

    for link, text in links:
        link_parts = parse.urlparse(link)

        if link_parts.netloc and link_parts.netloc != root_parts.netloc:
            filtered.append((link, text))
            continue

        same_path = root_parts.path.rstrip('/') == link_parts.path.rstrip('/')
        is_self_ref = same_path or link_parts.fragment
        if not is_self_ref:
            filtered.append((link, text))

    return filtered



def crawl(root, wanted_content=[], within_domain=True):    
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    queue = Queue()
    queue.put(root)

    visited = set()
    extracted = []

    parsed_root = parse.urlparse(root)
    base_domain = parsed_root.netloc

    while not queue.empty():
        url = queue.get()
        if url in visited:
            continue

        try:
            req = request.urlopen(url)
            content_type = req.headers.get('Content-Type', '')

            if wanted_content and not any(t in content_type for t in wanted_content):
                continue

            html = req.read()
            visited.add(url)
            visitlog.debug(url)

            for ex in extract_information(url, html):
                extracted.append(ex)
                extractlog.debug(ex)

            for link, title in parse_links(url, html):
                parsed_link = parse.urlparse(link)
                if within_domain and parsed_link.netloc != '' and parsed_link.netloc != base_domain:
                    continue
                if link not in visited:
                    queue.put(link)

        except Exception as e:
            print(e, url)

    return list(visited), extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''

    text = str(html)
    results = []

    phone_pattern = r'\b(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b'
    for match in re.findall(phone_pattern, text):
        results.append((address, 'PHONE', match))

    email_pattern = r'\b[\w\.-]+@[\w\.-]+\.\w{2,6}\b'
    for match in re.findall(email_pattern, text):
        results.append((address, 'EMAIL', match))

    address_pattern = r'\b([A-Z][a-z]+(?: [A-Z][a-z]+)*),?\s+(?:[A-Z]{2}|[A-Z][a-z]+\.?)\s+\d{5}(?:-\d{4})?\b'
    for match in re.findall(address_pattern, text):
        city = match
        full = re.search(city + r'.{0,20}(\d{5}(?:-\d{4})?)', text)
        if full:
            results.append((address, 'ADDRESS', city + ", " + full.group(1)))

    return results



def writelines(filename, data):
    with open(filename, 'w') as fout:
        for d in data:
            print(d, file=fout)


def main():
    site = sys.argv[1]
    links = get_links(site)
    writelines('links.txt', links)

    nonlocal_links = get_nonlocal_links(site)
    writelines('nonlocal.txt', nonlocal_links)

    visited, extracted = crawl(site, wanted_content=['text/html'], within_domain=True)
    writelines('visited.txt', visited)
    writelines('extracted.txt', extracted)


if __name__ == '__main__':
    main()

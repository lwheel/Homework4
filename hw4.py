import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue
from urllib import parse, request

logging.basicConfig(level=logging.DEBUG, filename='output.log', filemode='w')
visitlog = logging.getLogger('visited')
extractlog = logging.getLogger('extracted')


def parse_links(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string or ''
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


def strip_www(domain):
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
        visited.add(url)
        visitlog.debug(url)
        try:
            req = request.urlopen(url)
            content_type = req.headers.get('Content-Type', '')
            if wanted_content and not any(t in content_type for t in wanted_content):
                continue
            html = req.read()

            for ex in extract_information(url, html):
                extracted.append(ex)
                extractlog.debug(ex)

            for link, title in parse_links(url, html):
                parsed_link = parse.urlparse(link)
                if within_domain and parsed_link.netloc and parsed_link.netloc != base_domain:
                    continue
                if link not in visited:
                    queue.put(link)

        except Exception as e:
            print(e, url)

    print(f"[DEBUG] Total extracted: {len(extracted)}")
    print(extracted)
    return list(visited), extracted

def extract_information(address, html):
    '''
    Return a list of (url, CATEGORY, VALUE) tuples where
    CATEGORY ∈ {PHONE, EMAIL, ADDRESS}.
    '''
    if isinstance(html, (bytes, bytearray)):
        html = html.decode('utf-8', errors='ignore')
    text = BeautifulSoup(html, 'html.parser').get_text(" ", strip=True)
    #scan raw html for any emails we might be missing
    raw = html

    alt = re.sub(r'(?i)\s*(\(|\[)?\s*at\s*(\)|\])?\s*', '@', text)
    alt = re.sub(r'(?i)\s*(\(|\[)?\s*dot\s*(\)|\])?\s*', '.', alt)

    #regex patterns
    phone_re   = re.compile(r'\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    email_re   = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
    address_re = re.compile(
        r'[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s*,\s*'
        r'(?:[A-Z]{2}|[A-Z][a-z]+\.?(?:\s+[A-Z][a-z]+\.?)*)\s+'
        r'\d{5}(?:-\d{4})?',
        re.IGNORECASE
    )

    results = set()
    for m in phone_re.finditer(text):
        results.add((address, 'PHONE', m.group()))
    for m in email_re.finditer(raw):
        results.add((address, 'EMAIL', m.group()))
    for m in email_re.finditer(text):
        results.add((address, 'EMAIL', m.group()))
    for m in email_re.finditer(alt):
        results.add((address, 'EMAIL', m.group()))
    for m in address_re.finditer(text):
        results.add((address, 'ADDRESS', m.group().strip()))
    return list(results)


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
    writelines('extracted.txt', extracted)
    writelines('visited.txt', visited)


if __name__ == '__main__':
    main()

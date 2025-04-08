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
            text = link.string
            if not text:
                text = ''
            text = re.sub('\s+', ' ', text).strip()
            yield (parse.urljoin(root, link.get('href')), text)


def parse_links_sorted(root, html):
    # TODO: implement
    return []


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

    # TODO: implement
    links = get_links(url)
    parsed_root = parse.urlparse(url)
    root_domain = strip_www(parsed_root.netloc)
    root_path = parsed_root.path.rstrip('/')


    filtered = []

    for link_url, title in links:
        parsed_link = parse.urlparse(link_url)
        link_domain = strip_www(parsed_link.netloc)
        # to check if its self referencing -- check same domain and same path
        same_domain = link_domain == root_domain
        same_path = parsed_link.path.rstrip('/') == root_path
        is_fragment = parsed_link.fragment != ''
        
        if same_domain and (same_path or is_fragment):
            continue  # Skip self-reference

        if not same_domain:
            filtered.append((link_url, title))
    return filtered

#uncomment the lines below marked with depth limit, to use depth limited crawling for faster testing
def crawl(root, wanted_content=[], within_domain=True, max_depth = 2):
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    # TODO: implement

    queue = Queue()

    queue.put(root) #without depth limit
    #queue.put((root, 0))  # version with depth limit


    visited = []
    visited_set = set()
    extracted = []

    parsed_root = parse.urlparse(root)
    root_domain = parsed_root.netloc.lower().lstrip("www.")


    while not queue.empty():
        url = queue.get() #version without depth limit
        #url, current_depth = queue.get() #with depth limit

        #if current_depth > max_depth: #add this in to test with DEPTH LIMIT 
        #    continue  

        parsed_url = parse.urlparse(url)
        clean_url = parsed_url.geturl()
        if clean_url in visited_set:
            continue #already visited. 
        if within_domain:
            link_domain = parsed_url.netloc.lower().lstrip("www.")
            if link_domain != root_domain:
                continue
        try:
            req = request.urlopen(url)
            content_type = req.headers.get("Content-Type", "")

            if wanted_content and not any(ct in content_type for ct in wanted_content):
                continue  # if its not the right content type, skip

            html = req.read()

            visited.append(url)
            visited_set.add(clean_url)

            visitlog.debug(url)

            for ex in extract_information(url, html):
                extracted.append(ex)
                extractlog.debug(ex)

            for link, title in parse_links(url, html):
                parsed_link = parse.urlparse(link)
                if parsed_link.geturl() == parsed_url.geturl():
                    continue  #skip self reference
                queue.put(link) #version without depth limit
                #queue.put((link, current_depth + 1))  # add this in to test with DEPTH LIMIT


        except Exception as e:
            print(e, url)

    return visited, extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''

    # TODO: implement
    results = []
    text = html.decode(errors='ignore')  # decode bytes to string 

    
    #phone number 
    for match in re.findall('\d\d\d-\d\d\d-\d\d\d\d', str(html)):
        results.append((address, 'PHONE', match))
    
    #email regex
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    for match in re.findall(email_pattern, text):
        results.append((address, 'EMAIL', match))

    #address regex
    address_pattern = r'([A-Z][a-zA-Z]+(?: [A-Z][a-zA-Z]+)*,\s*[A-Z][a-zA-Z\.]+\s+\d{5})'
    for match in re.findall(address_pattern, text):
        results.append((address, 'ADDRESS', match))

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

    visited, extracted = crawl(site)
    writelines('visited.txt', visited)
    writelines('extracted.txt', extracted)


if __name__ == '__main__':
    main()
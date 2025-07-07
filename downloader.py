import requests
from bs4 import BeautifulSoup
import os
import re
import time

def download_dlls(dll_names, download_dir):
    for dll_name in dll_names:
        print(f"Searching and downloading: {dll_name}")
        try:
            url = buscar_url_dll(dll_name)
            if url:
                descargar_dll(url, dll_name, download_dir)
            else:
                print(f"DLL not found: {dll_name}")
        except Exception as e:
            print(f"Error with {dll_name}: {e}")

def buscar_url_dll(dll_name):
    base_url = "https://es.dll-files.com/"
    search_url = f"{base_url}search/?q={dll_name.lower()}"
    
    # More realistic browser headers - try without compression first
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",  # Request uncompressed content
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"'
    }
    
    # Create a session to maintain cookies
    session = requests.Session()
    session.headers.update(headers)
    
    # First, visit the main page to establish a session
    print("Establishing session...")
    session.get(base_url)
    time.sleep(1)
    
    print(f"Searching in: {search_url}")
    resp = session.get(search_url)
    print(f"Status code: {resp.status_code}")
    print(f"Response length: {len(resp.text)} characters")
    print(f"Content-Encoding: {resp.headers.get('content-encoding', 'none')}")
    
    if resp.status_code != 200:
        return None
    
    soup = BeautifulSoup(resp.text, 'html.parser')
    print(f"Page title: {soup.title.string if soup.title else 'No title'}")
    
    # Debug: save the HTML to see what we're getting
    with open('debug_page.html', 'w', encoding='utf-8') as f:
        f.write(resp.text)
    print("Saved page content to debug_page.html for inspection")
    
    # Search for the DLL page link in search results - more flexible search
    dll_link = None
    
    # First try: exact match with .html extension
    dll_link = soup.find('a', href=lambda x: x and dll_name.lower() in x.lower() and x.endswith('.html'))
    
    # Second try: any link containing the DLL name
    if not dll_link:
        dll_link = soup.find('a', href=lambda x: x and dll_name.lower() in x.lower())
    
    # Third try: look for links in table rows (as shown in the search results)
    if not dll_link:
        table_links = soup.find_all('a', href=True)
        for link in table_links:
            if dll_name.lower() in link.get_text().lower():
                dll_link = link
                break
    
    if not dll_link:
        print("DLL page link not found in search results")
        # Debug: show all links found
        all_links = soup.find_all('a', href=True)
        print(f"Found {len(all_links)} links on the page:")
        for i, link in enumerate(all_links[:10]):  # Show first 10 links
            print(f"  {i+1}. {link.get('href')} - Text: {link.get_text().strip()}")
        
        # Also show some text content to see what we got
        print("First 500 characters of page content:")
        print(repr(resp.text[:500]))  # Use repr() to see raw characters
        return None
    
    dll_page_url = dll_link['href']
    if not dll_page_url.startswith('http'):
        dll_page_url = base_url.rstrip('/') + dll_page_url
    
    print(f"DLL page: {dll_page_url}")
    
    # Add a small delay to simulate human behavior
    time.sleep(1)
    
    # Go to the DLL page
    resp2 = session.get(dll_page_url)
    if resp2.status_code != 200:
        print(f"Could not access DLL page (status {resp2.status_code})")
        return None
    
    soup2 = BeautifulSoup(resp2.text, 'html.parser')
    
    # Debug: save the DLL page HTML
    with open('debug_dll_page.html', 'w', encoding='utf-8') as f:
        f.write(resp2.text)
    print("Saved DLL page content to debug_dll_page.html for inspection")
    
    # First, try to find direct download links in the DLL page itself
    direct_links = soup2.find_all('a', href=lambda x: x and 'download.zip.dll-files.com' in x)
    if direct_links:
        direct_url = direct_links[0]['href']
        print(f"Found direct download link: {direct_url}")
        return direct_url
    
    # If no direct links, search for download links that contain token and expires
    token_links = soup2.find_all('a', href=lambda x: x and 'token=' in x and 'expires=' in x)
    if token_links:
        direct_url = token_links[0]['href']
        print(f"Found token download link: {direct_url}")
        return direct_url
    
    # Search for download links (most recent version) - but exclude Microsoft links
    download_links = soup2.find_all('a', href=lambda x: x and '/download/' in x and 'microsoft.com' not in x)
    if not download_links:
        print("No download links found (excluding Microsoft)")
        # Show all download links for debugging
        all_download_links = soup2.find_all('a', href=lambda x: x and '/download/' in x)
        print(f"Found {len(all_download_links)} total download links:")
        for i, link in enumerate(all_download_links[:10]):
            href = link.get('href', '')
            text = link.get_text().strip()
            print(f"  {i+1}. {href} - Text: {text}")
        return None
    
    # Take the first download link (most recent, non-Microsoft)
    download_href = download_links[0]['href']
    if download_href.startswith('http'):
        download_url = download_href
    else:
        download_url = base_url.rstrip('/') + download_href
    
    print(f"Download URL: {download_url}")
    
    # Add another delay before accessing download page
    time.sleep(1)
    
    # Go to the download page to get the token
    resp3 = session.get(download_url)
    if resp3.status_code != 200:
        print(f"Could not access download page (status {resp3.status_code})")
        return None
    
    soup3 = BeautifulSoup(resp3.text, 'html.parser')
    
    # Search for the direct download link that contains the token
    direct_links = soup3.find_all('a', href=lambda x: x and 'download.zip.dll-files.com' in x)
    if not direct_links:
        # Search for links that contain token and expires
        direct_links = soup3.find_all('a', href=lambda x: x and 'token=' in x and 'expires=' in x)
    
    if not direct_links:
        print("No direct download link with token found")
        return None
    
    direct_url = direct_links[0]['href']
    print(f"Direct URL: {direct_url}")
    return direct_url

def descargar_dll(url, dll_name, download_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",  # Request uncompressed content
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
    }
    
    resp = requests.get(url, headers=headers, stream=True)
    if resp.status_code != 200:
        print(f"Could not download {dll_name} (status {resp.status_code})")
        return
    
    # Check content type
    content_type = resp.headers.get('content-type', '')
    if 'text/html' in content_type:
        print(f"Error: Downloaded HTML instead of DLL file")
        return
    
    # If it's a ZIP file, extract the DLL
    if dll_name.endswith('.zip') or 'zip' in content_type:
        file_path = os.path.join(download_dir, dll_name + '.zip')
    else:
        file_path = os.path.join(download_dir, dll_name)
    
    with open(file_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    
    # Verify that the downloaded file is not HTML
    with open(file_path, 'rb') as f:
        first_bytes = f.read(10)
        if first_bytes.startswith(b'<!DOCTYPE') or first_bytes.startswith(b'<html'):
            print(f"Error: Downloaded file is HTML, not a DLL")
            os.remove(file_path)
            return
    
    print(f"Downloaded: {os.path.basename(file_path)}") 
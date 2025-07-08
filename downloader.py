import requests
from bs4 import BeautifulSoup
import os
import re
import time
import json
import zipfile
import hashlib

def debug_print(message):
    """Print message only if debug mode is enabled"""
    if os.environ.get('DEBUG_MODE', '0') == '1':
        print(message)

def load_config():
    """Load configuration from .config.json"""
    config_path = '.config.json'
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    else:
        # Return default config
        return {
            "virustotal": {
                "api_key": "",
                "enabled": False,
                "timeout": 30
            },
            "download": {
                "extract_zip": True,
                "verify_hash": True
            }
        }

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash, api_key):
    """Check file hash with VirusTotal API"""
    if not api_key:
        print("VirusTotal API key not configured. Skipping malware check.")
        return None
    
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        "apikey": api_key,
        "resource": file_hash
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        if response.status_code == 200:
            result = response.json()
            if result.get("response_code") == 1:
                positives = result.get("positives", 0)
                total = result.get("total", 0)
                print(f"VirusTotal scan: {positives}/{total} engines detected malware")
                return result
            else:
                print("File not found in VirusTotal database")
                return None
        else:
            print(f"VirusTotal API error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return None

def extract_dll_from_zip(zip_path, dll_name, download_dir):
    """Extract DLL from ZIP file"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Look for the DLL file in the ZIP
            dll_files = [f for f in zip_ref.namelist() if f.lower().endswith('.dll')]
            
            if not dll_files:
                print("No DLL files found in ZIP")
                return None
            
            # Extract the first DLL found
            dll_file = dll_files[0]
            zip_ref.extract(dll_file, download_dir)
            
            extracted_path = os.path.join(download_dir, dll_file)
            print(f"Extracted: {dll_file}")
            return extracted_path
            
    except Exception as e:
        print(f"Error extracting ZIP: {e}")
        return None

def download_dlls(dll_names, download_dir, architecture='x64'):
    config = load_config()
    
    for dll_name in dll_names:
        print(f"Searching and downloading: {dll_name} ({architecture})")
        try:
            url = buscar_url_dll(dll_name, architecture)
            if url:
                descargar_dll(url, dll_name, download_dir, config)
            else:
                print(f"DLL not found: {dll_name}")
        except Exception as e:
            print(f"Error with {dll_name}: {e}")

def buscar_url_dll(dll_name, architecture='x64'):
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
    debug_print("Establishing session...")
    session.get(base_url)
    time.sleep(1)
    
    debug_print(f"Searching in: {search_url}")
    resp = session.get(search_url)
    debug_print(f"Status code: {resp.status_code}")
    debug_print(f"Response length: {len(resp.text)} characters")
    debug_print(f"Content-Encoding: {resp.headers.get('content-encoding', 'none')}")
    
    if resp.status_code != 200:
        return None
    
    soup = BeautifulSoup(resp.text, 'html.parser')
    debug_print(f"Page title: {soup.title.string if soup.title else 'No title'}")
    
    # Debug: save the HTML to see what we're getting
    if os.environ.get('DEBUG_MODE', '0') == '1':
        with open('debug_page.html', 'w', encoding='utf-8') as f:
            f.write(resp.text)
        debug_print("Saved page content to debug_page.html for inspection")
    
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
        if os.environ.get('DEBUG_MODE', '0') == '1':
            all_links = soup.find_all('a', href=True)
            debug_print(f"Found {len(all_links)} links on the page:")
            for i, link in enumerate(all_links[:10]):  # Show first 10 links
                debug_print(f"  {i+1}. {link.get('href')} - Text: {link.get_text().strip()}")
            
            # Also show some text content to see what we got
            debug_print("First 500 characters of page content:")
            debug_print(repr(resp.text[:500]))  # Use repr() to see raw characters
        return None
    
    dll_page_url = dll_link['href']
    if not dll_page_url.startswith('http'):
        dll_page_url = base_url.rstrip('/') + dll_page_url
    
    debug_print(f"DLL page: {dll_page_url}")
    
    # Add a small delay to simulate human behavior
    time.sleep(1)
    
    # Go to the DLL page
    resp2 = session.get(dll_page_url)
    if resp2.status_code != 200:
        print(f"Could not access DLL page (status {resp2.status_code})")
        return None
    
    soup2 = BeautifulSoup(resp2.text, 'html.parser')
    
    # Debug: save the DLL page HTML
    if os.environ.get('DEBUG_MODE', '0') == '1':
        with open('debug_dll_page.html', 'w', encoding='utf-8') as f:
            f.write(resp2.text)
        debug_print("Saved DLL page content to debug_dll_page.html for inspection")
    
    # First, try to find direct download links in the DLL page itself
    direct_links = soup2.find_all('a', href=lambda x: x and 'download.zip.dll-files.com' in x)
    if direct_links:
        direct_url = direct_links[0]['href']
        debug_print(f"Found direct download link: {direct_url}")
        return direct_url
    
    # If no direct links, search for download links that contain token and expires
    token_links = soup2.find_all('a', href=lambda x: x and 'token=' in x and 'expires=' in x)
    if token_links:
        direct_url = token_links[0]['href']
        debug_print(f"Found token download link: {direct_url}")
        return direct_url
    
    # Search for download links with architecture filtering
    download_links = soup2.find_all('a', href=lambda x: x and '/download/' in x and 'microsoft.com' not in x)
    
    if not download_links:
        print("No download links found (excluding Microsoft)")
        # Show all download links for debugging
        if os.environ.get('DEBUG_MODE', '0') == '1':
            all_download_links = soup2.find_all('a', href=lambda x: x and '/download/' in x)
            debug_print(f"Found {len(all_download_links)} total download links:")
            for i, link in enumerate(all_download_links[:10]):
                href = link.get('href', '')
                text = link.get_text().strip()
                debug_print(f"  {i+1}. {href} - Text: {text}")
        return None
    
    # Filter by architecture if specified
    if architecture:
        print(f"Filtering for {architecture} architecture...")
        filtered_links = []
        version_count = 0
        
        # Find all inner-grid divs (each represents a version)
        inner_grids = soup2.find_all('div', class_='inner-grid')
        for grid in inner_grids:
            left_pane = grid.find('div', class_='left-pane')
            right_pane = grid.find('div', class_='right-pane')
            
            if left_pane and right_pane:
                # Get the architecture value (second item in right-pane)
                arch_p = right_pane.find_all('p')
                if len(arch_p) >= 2:
                    arch_value = arch_p[1].get_text().strip()
                    version_value = arch_p[0].get_text().strip()
                    
                    # Check if this version matches our architecture
                    arch_match = False
                    if architecture == 'x86' and ('32' in arch_value or 'x86' in arch_value.lower()):
                        arch_match = True
                    elif architecture == 'x64' and ('64' in arch_value or 'x64' in arch_value.lower()):
                        arch_match = True
                    
                    if arch_match:
                        # Find the download link associated with this grid
                        # Look for the download-pane that follows this inner-grid
                        download_pane = grid.find_next_sibling('div', class_='download-pane')
                        if download_pane:
                            download_link = download_pane.find('a', href=lambda x: x and '/download/' in x)
                            if download_link:
                                filtered_links.append(download_link)
                                version_count += 1
                                # Only show the first version in normal mode
                                if version_count == 1:
                                    print(f"Found {architecture} version: {version_value} - {arch_value}")
                                else:
                                    debug_print(f"Found {architecture} version: {version_value} - {arch_value}")
        
        if filtered_links:
            download_links = filtered_links
            print(f"Found {len(filtered_links)} {architecture} versions")
        else:
            print(f"No {architecture} versions found, using first available")
    
    # Take the first download link (most recent, non-Microsoft)
    download_href = download_links[0]['href']
    if download_href.startswith('http'):
        download_url = download_href
    else:
        download_url = base_url.rstrip('/') + download_href
    
    debug_print(f"Download URL: {download_url}")
    
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
    debug_print(f"Direct URL: {direct_url}")
    return direct_url

def descargar_dll(url, dll_name, download_dir, config):
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
    
    # Extract DLL from ZIP if enabled
    if config.get("download", {}).get("extract_zip", True) and file_path.endswith('.zip'):
        print("Extracting DLL from ZIP...")
        extracted_dll_path = extract_dll_from_zip(file_path, dll_name, download_dir)
        
        if extracted_dll_path and config.get("download", {}).get("verify_hash", True):
            # Calculate hash of extracted DLL
            print("Calculating file hash...")
            file_hash = calculate_file_hash(extracted_dll_path)
            print(f"SHA-256 Hash: {file_hash}")
            
            # Check with VirusTotal if enabled
            if config.get("virustotal", {}).get("enabled", False):
                print("Checking with VirusTotal...")
                vt_result = check_virustotal(file_hash, config.get("virustotal", {}).get("api_key", ""))
                
                if vt_result:
                    positives = vt_result.get("positives", 0)
                    if positives > 0:
                        print(f"⚠️  WARNING: {positives} antivirus engines detected malware!")
                        print("Use at your own risk.")
                    else:
                        print("✅ No malware detected by VirusTotal")
                else:
                    print("⚠️  Could not verify with VirusTotal")
            else:
                print("VirusTotal scanning disabled in config") 
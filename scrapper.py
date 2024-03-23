import requests
from bs4 import BeautifulSoup
import socket
import nmap
import re
from urllib.parse import urlparse

def scrape_website(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the HTML content of the page
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract specific information from the page
            # Example: Get all the links on the page
            links = soup.find_all('a')
            
            # Extract IP address and server details
            ip_address = socket.gethostbyname(urlparse(url).netloc)
            server_details = response.headers['Server'] if 'Server' in response.headers else None
            
            # Return the extracted data
            return links, ip_address, server_details
        else:
            # If the request was not successful, print an error message
            print("Failed to retrieve webpage:", response.status_code)
            return None, None, None
    except Exception as e:
        print("Error while scraping website:", e)
        return None, None, None

def scan_ports(url):
    try:
        
        hostname = re.search(r'://(.*?)/', url).group(1)
        
        
        ip_address = socket.gethostbyname(hostname)
        
        
        nm = nmap.PortScanner()
        
        
        nm.scan(ip_address, arguments='-Pn')
        
        
        open_ports = [port for port in nm[ip_address].all_tcp() if nm[ip_address]['tcp'][port]['state'] == 'open']
        
        return open_ports
    except Exception as e:
        print("Error while scanning ports:", e)
        return []

def detect_firewall(url):
    try:
        
        hostname = re.search(r'://(.*?)/', url).group(1)
        
        
        ip_address = socket.gethostbyname(hostname)
        
        
        firewall_ports = [80, 443] 
        
        
        for port in firewall_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((ip_address, port))
            s.close()
            if result == 0:
                return f"A firewall is likely running on port {port}."
        
        return "No common firewall ports detected."
    except Exception as e:
        print("Error while detecting firewall:", e)
        return "Error detecting firewall."


url = input("Enter URL to scrape and analyze: ")


links, ip_address, server_details = scrape_website(url)
if links:
    print("Links found on the page:")
    for link in links:
        print(link.get('href'))


open_ports = scan_ports(url)
if open_ports:
    print("Open ports detected:", open_ports)
else:
    print("No open ports detected.")


firewall_info = detect_firewall(url)
print("Firewall information:", firewall_info)


print("IP Address:", ip_address)
print("Server Details:", server_details)

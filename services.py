import os
import json
from time import time
import requests
from io import BytesIO
import tarfile
from zipfile import ZipFile

CURRENT_DIR = os.getcwd()
DATA_DIR = os.path.join(CURRENT_DIR, "data")

class Services:

    def need_update(ipsetpath: str):
        """
        Function to find out if an IPset needs an update
        """
        
        # If the file does not exist
        if not os.path.isfile(os.path.join(DATA_DIR, ipsetpath)):
            return True
        
        # Get time of the last update
        with open(os.path.join(DATA_DIR, ipsetpath), "r") as file:
            last_update_time = json.load(file)["time"]

        # When the file has expired
        if int(time()) - int(last_update_time) > 3600:
            return True
        return False
    
    def update_fireholipset():
        """
        Function to update the IPset of FireHol
        """
        # List of URLs to the FireHOL IP lists
        firehol_urls = [
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level4.netset"
        ]

        # Empty list for the collected IP addresses
        firehol_ips = {"time": str(int(time())), "ips": []}

        # Loop to retrieve and process the IP lists.
        for firehol_url in firehol_urls:
            response = requests.get(firehol_url)
            if response.ok:
                # Extract the IP addresses from the response and add them to the list
                ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
                firehol_ips["ips"].extend(ips)
            else:
                response.raise_for_status()

        # Remove duplicates from the list of collected IP addresses
        firehol_ips["ips"] = list(set(firehol_ips["ips"]))
        
        # Open the JSON file in write mode and save the collected IP addresses
        with open(os.path.join(DATA_DIR, "fireholipset.json"), "w") as file:
            json.dump(firehol_ips, file)
    
    def update_ipdenyipset():
        """
        Function to update the IPset of IPDeny
        """
        # List of URLs to the IP deny IP lists (for IPv4 and IPv6).
        ipdeny_urls = [
            "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz",
            "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz"
        ]

        # Empty list for the collected IP addresses
        ipdeny_ips = {"time": str(int(time())), "ips": []}

        # Loop to retrieve and process the IP lists.
        for ipdeny_url in ipdeny_urls:
            response = requests.get(ipdeny_url)
            if response.ok:
                # Load the TAR-GZ file and extract its contents
                tar_file = BytesIO(response.content)
                with tarfile.open(fileobj=tar_file, mode="r:gz") as tar:
                    members = tar.getmembers()
                    for member in members:
                        # Check if the member is a file and has the extension ".zone".
                        if member.isfile() and member.name.endswith('.zone'):
                            # Read the contents of the file, decode it as UTF-8 and extract the IP addresses
                            file_content = tar.extractfile(member).read().decode("utf-8")
                            ips = [line.strip().split('/')[0] for line in file_content.splitlines() if line.strip() and not line.startswith("#")]
                            ipdeny_ips["ips"].extend(ips)
            else:
                response.raise_for_status()
        
        # Remove duplicates from the list of collected IP addresses
        ipdeny_ips["ips"] = list(set(ipdeny_ips["ips"]))
        
        # Open the JSON file in write mode and save the collected IP addresses
        with open(os.path.join(DATA_DIR, "ipdenyipset.json"), "w") as file:
            json.dump(ipdeny_ips, file)
    
    def update_emergingthreatsipset():
        """
        Function to update the IPset of Emerging Threats
        """
        # URL to get the list of IP's
        emergingthreats_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        
        # Request the list of IP's
        response = requests.get(emergingthreats_url)
        
        # Check if the request was successful
        if response.ok:
            # Extract the IP addresses from the response and remove duplicates
            emergingthreats_ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            emergingthreats_ips = list(set(emergingthreats_ips))
            
            # Open the JSON file in write mode and save the list of Ips.
            with open(os.path.join(DATA_DIR, "emergingthreatsipset.json"), "w") as file:
                json.dump({"time": str(int(time())), "ips": emergingthreats_ips}, file)
        else:
            response.raise_for_status()
    
    def update_myipmsipset():
        """
        Function to update the IPset of MyIP.ms
        """
        # URL to get the list of IP's
        myipms_url = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
        
        # Request the zip file
        response = requests.get(myipms_url)
        
        # Check if the request was successful
        if response.ok:
            with BytesIO(response.content) as zip_file:
                # Load the ZIP file and extract its contents
                with ZipFile(zip_file, "r") as z:
                    with z.open("full_blacklist_database.txt", "r") as txt_file:
                        content = txt_file.read().decode('utf-8')
                        myipms_ips = [line.strip().split('/')[0].split('#')[0].replace('\t', '') for line in content.splitlines() if line.strip() and not line.startswith("#")]
                        myipms_ips = list(set(myipms_ips))
            
            # Open the JSON file in write mode and save the list of Ips.
            with open(os.path.join(DATA_DIR, "myipmsipset.json"), "w") as file:
                json.dump({"time": str(int(time())), "ips": myipms_ips}, file)
        else:
            response.raise_for_status()
    
    def update_torexitnodes():
        # URL to get the list of Tor exit nodes
        torbulkexitlist_url = "https://check.torproject.org/torbulkexitlist"
        
        # Request the list of Tor exit nodes
        response = requests.get(torbulkexitlist_url)
        
        # Check if the request was successful
        if response.ok:
            # Extract the IP addresses from the response and remove duplicates
            torexitnodes_ip = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            torexitnodes_ip = list(set(torexitnodes_ip))
            
            # Open the JSON file in write mode and save the list of Tor exit nodes.
            with open(os.path.join(DATA_DIR, "torexitnodes.json"), "w") as file:
                json.dump({"time": str(int(time())), "ips": torexitnodes_ip}, file)
        else:
            response.raise_for_status()
    
    def update_all_ipsets():
        if Services.need_update("fireholipset.json"):
            try:
                Services.update_fireholipset()
            except:
                Services.update_fireholipset()
        if Services.need_update("ipdenyipset.json"):
            try:
                Services.update_ipdenyipset()
            except:
                Services.update_ipdenyipset()
        if Services.need_update("emergingthreatsipset.json"):
            try:
                Services.update_emergingthreatsipset()
            except:
                Services.update_emergingthreatsipset()
        if Services.need_update("myipmsipset.json"):
            try:
                Services.update_myipmsipset()
            except:
                Services.update_myipmsipset()
        if Services.need_update("torexitnodes.json"):
            try:
                Services.update_torexitnodes()
            except:
                Services.update_torexitnodes()
    
    def remove_seenips():
        """
        Delete all expired items of the seenips dict
        """

        # If the file does not exist
        if not os.path.isfile(os.path.join(DATA_DIR, "seenips.json")):
            return
        
        # Open/Read the file
        with open(os.path.join(DATA_DIR, "seenips.json"), "r") as file:
            seenips = json.load(file)

        # Create a copy and delete expired items
        copy_seenips = seenips.copy()
        for hashed_ip, records in seenips.items():
            new_records = []
            for record in records:
                if not int(time()) - int(record) > 14400:
                    new_records.append(record)

            copy_seenips[hashed_ip] = new_records

        # Compare with the copy to see if anything has changed
        if copy_seenips != seenips:
            with open(os.path.join(DATA_DIR, "seenips.json"), "w") as file:
                json.dump(copy_seenips, file)
    
    def remove_captchasolved(verificationage: int):
        """
        Delete all expired items of the captchasolved dict
        """

        # If the file does not exist
        if not os.path.isfile(os.path.join(DATA_DIR, "captchasolved.json")):
            return
        
        # Open/Read the file
        with open(os.path.join(DATA_DIR, "captchasolved.json"), "r") as file:
            captchasolved = json.load(file)

        # Create a copy and delete expired items
        copy_captchasolved = captchasolved.copy()
        for hashed_id, data in captchasolved.items():
            if int(time()) - int(data["time"]) > verificationage:
                del copy_captchasolved[hashed_id]

        # Compare with the copy to see if anything has changed
        if copy_captchasolved != captchasolved:
            with open(os.path.join(DATA_DIR, "captchasolved.json"), "w") as file:
                json.dump(copy_captchasolved, file)
    
    def remove_stopforumspam():
        """
        Delete all expired items of the stopforumspam dict
        """

        # If the file does not exist
        if not os.path.isfile(os.path.join(DATA_DIR, "stopforumspamcache.json")):
            return
        
        # Open/Read the file
        with open(os.path.join(DATA_DIR, "stopforumspamcache.json"), "r") as file:
            stopforumspam = json.load(file)

        # Create a copy and delete expired items
        copy_stopforumspam = stopforumspam.copy()
        for hashed_ip, content in stopforumspam.items():
            if int(time()) - int(content["time"]) > 604800:
                del copy_stopforumspam[hashed_ip]

        # Compare with the copy to see if anything has changed
        if copy_stopforumspam != stopforumspam:
            with open(os.path.join(DATA_DIR, "stopforumspamcache.json"), "w") as file:
                json.dump(copy_stopforumspam, file)

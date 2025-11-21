#!/usr/bin/env python3
"""
This script queries the panorama and outputs the results in a separate file
"""
import requests
import xml.etree.ElementTree as ET

class PanoramaClient:
    def __init__(self, host, api_key, verify_ssl: bool=False):
        self.host = host # store it as an instance variable
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}/api/"
    def get_host(self):
        return self.host
    def get_config(self):
        return {
            'host': self.host,
            'api_key': self.api_key,
            'verify_ssl': self.verify_ssl
        }
    def get_base_url(self):
        return self.base_url

    def _make_request(self, my_params):
        my_params['key'] = self.api_key
        try:        
            response = requests.get(
                self.base_url,
                params=my_params,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            root = ET.fromstring(response.content)

            #check API status
            status = root.get('status')
            if status != 'success':
                # Extract the error message from XML
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                raise Exception(f"Panorama API error: {error_text}")
            
            return root
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
        
    def get_cadidate_config(self):
        print("📤 Exporting candidate configuration from Panorama...")
        params = {type:'export', category:'configuration'}
        root = self._make_request(params)
PANORAMA = "172.16.12.30"
config = PanoramaClient(PANORAMA, "api_key", True)
config_data = config.get_config()
base_url = config.get_base_url()
test_params = {
    'type': 'op',
    'cmd': '<show><system><info></info></system></show>'
}
response=config._make_request(test_params)
print(response)
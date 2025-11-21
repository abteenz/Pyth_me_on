#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
import os

#
#
#
#
#

load_dotenv()

class PanOsClient:
    def __init__(self, host, api_key, verify_ssl: bool=False):
        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}/api/"
    
    def get_host(self):
        return self.host
    
    def show_config(self):
        return self.host, self.verify_ssl, self.api_key
    
    def _make_request(self, my_params):
        my_params['key'] = self.api_key
        try:
            response=requests.get(self.base_url, params=my_params, verify=self.verify_ssl)
            
            response.raise_for_status()

            root = ET.fromstring(response.content)
            print(response.text)

            #check the api status
            status = root.get('status')
            if status != 'success':
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknow error occured'
                raise Exception (f"Panorama API error: {error_text}")
            return root
        except requests.exceptions.RequestException as e:
                    print(Exception)
    

test_params = {
    'type': 'op',
    'cmd': '<show><system><info></info></system></show>'
}

the_key = os.getenv('PANORAMA_API_KEY')
the_host = os.getenv('PANORAMA_HOST')

client = PanOsClient(the_host, the_key)

client._make_request(test_params)





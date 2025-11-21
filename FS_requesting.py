
import requests
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
import os
from my_own import wirte_to_file

load_dotenv()


class PanOsPull():
    def __init__(self, host, api_key, ssl_verify: bool=False):

        self.host = host
        self.api_key = api_key
        self.ssl_verify = ssl_verify

        self.base_url = f"https://{self.host}/api/"
        
    def get_candidate_config(self, my_params):
        my_params['key'] = self.api_key


        response = requests.get(
            self.base_url,
            params=my_params,
            verify=self.ssl_verify,
            timeout=30
        )
        root = ET.fromstring(response.content)

        khorooji = response.text
    

        if root.get('status') != 'success':
            msg = root.find('.//msg')
            if msg is not None:
                print(msg.text)
            else:
                print("No message found")

        return khorooji
    
    def _get_lock_status(self):
        self.commit_paramas = {
            'type': 'export',
            'category': 'configuration'
}

        self.get_candidate_config(commit_params)



    


the_key = os.getenv("PANORAMA_API_KEY")
the_host = os.getenv("PANORAMA_HOST")

config_export = {
    'type': 'export',
    'category': 'configuration'
}

candidate_config_export = {
    'type': 'op',
    'cmd': '<show><config><candidate></candidate></config></show>'
}

is_pending_changes = {
    'type': 'op',
    'cmd': '<check><pending-changes></pending-changes></check>'
}


output = str(PanOsPull(the_host,the_key).get_candidate_config(is_pending_changes))

wirte_to_file().create_folder_structure(output)
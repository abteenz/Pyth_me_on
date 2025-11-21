#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime

class wirte_to_file():

    def create_folder_structure(self, content):
        self.content = content

        timestamp = datetime.now().strftime('%b%d')

        config_folder = Path('configs')
        config_folder.mkdir(exist_ok=True)

        config_file = config_folder / 'candidate.xml'
        config_file.write_text(self.content)



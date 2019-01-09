#!/usr/bin/env python3.6

__AUTHOR__ = 'Michael Hidalgo'
__VERSION__ = "1.0.0 December 2018"

"""
Install dependencies with:
pip install -r requirements.txt
"""

import os.path
import requests
import json 

class utils :
    MITRE_ATTACK_FILE_NAME = 'attack_matrix.json'
    MITRE_ATTACK_URL       = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    
    def mitre_attack_matrix_file_exists (self):
        return os.path.exists(self.MITRE_ATTACK_FILE_NAME)
    
    def write_file (self, file_contents):
        with open(self.MITRE_ATTACK_FILE_NAME, "w", encoding='utf-8') as file:
            file.write(file_contents)
        
    def download_and_save_mitre_attack_matrix(self):
        r = requests.get(self.MITRE_ATTACK_URL)
        self.write_file(r.text)
    
    def read_attack_matrix(self):
        if  not self.mitre_attack_matrix_file_exists():
            self.download_and_save_mitre_attack_matrix()
        f = open(self.MITRE_ATTACK_FILE_NAME,'r')
        return f.read()


    

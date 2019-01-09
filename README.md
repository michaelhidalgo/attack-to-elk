# attack-to-elk : A better way to visualize, filter and search MITRE ATT&CK matrix

This program exports MITRE ATT&amp;CK enterpise matrix into a ELK dashboard.

![Alt text](/img/platform.jpg?raw=true "Title")

# Installation
1. Clone this repo git@github.com:michaelhidalgo/attack-to-elk.git
2. Create a virtual environment using virtualenv env
3. Activate the virtual environment running source env/bin/activate from the root folder.
5. Install dependencies from requirements file pip3 install -r requirements.txt
5. Export following environment variables with Elasticsearch IP address and port:
 ```
   export es_hostname='Your ELK IP'
   export es_port='Your ELK port (9200 by default)'  
  ```
6. Run the program using Python3:
``` python 
python3 attack-to-elk.py
```

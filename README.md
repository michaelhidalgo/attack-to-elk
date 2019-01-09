# A better way to visualize, filter and search MITRE ATT&CK matrix

This program exports MITRE ATT&amp;CK enterpise matrix into a ELK dashboard. Check out [this blog post entry](https://blog.michaelhidalgo.info/2019/01/mitre-att-as-kibana-dashboard-part-ll.html) for having better understanding on the benefits of exporting the ATT&CK enterprise matrix into ELK.

![Alt text](/img/platform.jpg?raw=true "Title")

# Installation
1. Clone or fork this repo git@github.com:michaelhidalgo/attack-to-elk.git
2. Create a virtual environment using virtualenv:
```
virtualenv env
```

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
# Importing ELK artifacts

All visualizations, index patterns and dashboards were exported into an [artifact JSON file](https://github.com/michaelhidalgo/attack-to-elk/tree/master/elk-artifacts). 

Once you've run the script and indexing the matrix, you can go to Kibana Management -> Saved Objects and Import. From there you can choose the artifacts JSON described above and that's it.

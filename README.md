# vuln-scrap
Vuln-scrap is a python written script to scrap all published CVEs from different web repositories and store it as CSV file. The main
purpose is to scrap disclosed vulnerabilities of ICS environments. Later, generated CSV tables can be used to write
vulnerabilities report.
### Sources
At this point it supports 3 websites:
* [CISA - ICS-CERT Advisories](https://www.cisa.gov/uscert/ics/advisories) as cisa_scrap.py module
* [Zero Day Initiative - Published Advisories](https://www.zerodayinitiative.com/advisories/published/) as zdi_scrap.py module
* [PacketStorm - Advisories](packetstormsecurity.com) as ps_scrap.py module

<img src="https://user-images.githubusercontent.com/38925701/182382612-571fab73-9549-4aa8-bf18-5cf8a719eb23.png" width=25% height=25%>   <img src="https://user-images.githubusercontent.com/38925701/182382155-d17c7704-e293-48a9-ae66-4b4625abd894.svg" width=25% height=25%>   <img src="https://user-images.githubusercontent.com/38925701/182382788-bfce8c86-6dba-434d-a5c9-07d687d09910.png" width=25% height=25%>

### 

### Requirements
* Python 3.9+
* Google Chrome 103.0.5060.134+
* Modules:
  * beautifulsoup4==4.11.1
  * pandas==1.4.3
  * selenium==4.3.0
  * webdriver_manager==3.8.2

All modules can be installed automatically through [requirements](#Instructions) file.

## Instructions
Get the files from repository: 
```
$ git clone https://github.com/pedroivosilva/vuln-scrap
```
Ensure you are into the correct folder/Navigate to script directory:
```
$ cd ../path/to/the/folder/vuln-scrap
```
Install required modules:
```
$ pip install -r requirements.txt
```
Run the script:
```
$ python scrap.py [OPTION]
```
You can use ```-h``` or ```--help``` and check for available options:
```
$ python scrap.py --help
-h or --help        Displays these instructions.
-cisa               Try to scrap vulnerabilities from 'www.cisa.gov/uscert/ics/advisories to a csv file.
-zdi                Try to scrap vulnerabilities from 'www.zerodayinitiative.com' to a csv file.
-packetstorm        [IN PROGRESS]Try to scrap vulnerabilities from 'www.packetstormsecurity.com' to a csv file.
-all                Try to scrap vulnerabilities from all available sources to a single csv file.
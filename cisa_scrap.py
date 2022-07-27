from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import datetime as dt
import pandas as pd

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver2 = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver3 = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

cisa = "https://www.cisa.gov"
driver.get(cisa + "/uscert/ics/advisories")
cisa_advisories = driver.page_source
soup = BeautifulSoup(cisa_advisories)

all_cisa_vulns = () # all CISA vulnerabilities before checking its eligibility.
cisa_vulns = [] # all CISA vulnerabilities after checking its eligibility.
titles = []  # vulnerabilities titles
links = []  # vulnerabilities links

for i in soup.find_all('span', attrs={'class': 'views-field views-field-title'}):
    tag = i.find('a', href=True)
    links.append(cisa + tag['href'])
    titles.append(tag.text)
    all_cisa_vulns = all_cisa_vulns + ([tag.text, cisa + tag['href']],)

# Check if vulnerabilities previously found are within the parameters
# Release date must be < 7 days
# CVSS must be <= 7.0

for i in all_cisa_vulns:
    driver2.get(i[1])
    vuln = driver2.page_source
    vuln_soup = BeautifulSoup(vuln)

    # Original release date slicing and converting into date object for comparison.
    release_date = vuln_soup.find_all('div', attrs={'class': 'submitted meta-text'})[0]
    release_date = release_date.text.strip()
    release_date = release_date.split(': ')[1]
    release_date = dt.datetime.strptime(release_date, '%B %d, %Y').date()

    # Check if date is <= 7 days
    today = dt.date.today()
    date_delta = today - release_date

    if date_delta.days <= 7:

        # If delta is within the period, check the CVSS score.
        # CVSS is the first bold red colored word in the page. That's why it's in index 0 below
        cvss = vuln_soup.find_all('strong', attrs={'style': 'color: red;'})[0]
        cvss = float(cvss.text.split()[-1])

        d = {}
        if cvss >= 7:
            # Set already known variables.
            d['title'] = i[0]
            d['cvss'] = cvss

            # Start to scrap other informations.

            h3_vuln_soup = vuln_soup.find_all('h3')
            for x in h3_vuln_soup:
                if x.string.endswith('VULNERABILITY OVERVIEW'):
                    vulnerability_heading = x.string.rstrip(' VULNERABILITY OVERVIEW')
                else:
                    vulnerability_heading = 'ERROR'

            h4_vuln_soup = vuln_soup.find_all('h4')
            for y in h4_vuln_soup:
                if y.text.startswith(vulnerability_heading) and ('details4' not in d) and ('details3' not in d) and ('details2' not in d) and ('details1' not in d) and ('details' not in d):
                    d['details'] = y.find_next_sibling('p').string

                elif y.text.startswith(vulnerability_heading) and ('details' in d):
                    d['details1'] = y.find_next_sibling('p').string

                elif y.text.startswith(vulnerability_heading) and ('details' in d) and ('details1' in d):
                    d['details2'] = y.find_next_sibling('p').string

                elif y.text.startswith(vulnerability_heading) and ('details' in d) and ('details1' in d) and ('details2' in d):
                    d['details3'] = y.find_next_sibling('p').string

                elif y.text.startswith(vulnerability_heading) and ('details' in d) and ('details1' in d) and ('details2' in d) and ('details3' in d):
                    d['details4'] = y.find_next_sibling('p').string

                link = y.find_next_sibling('p').find_next_sibling('p')
                link = link.find_all('a', href=True)

                if ('link' not in d) and ('link1' not in d) and ('link2' not in d) and ('link3' not in d) and ('link4' not in d):
                    d['link'] = link['href']

                elif ('link1' not in d) and ('link' in d):
                    d['link1'] = link['href']

                elif ('link2' not in d) and ('link' in d) and ('link1' in d):
                    d['link2'] = link['href']

                elif ('link3' not in d) and ('link' in d) and ('link1' in d) and ('link2' in d):
                    d['link3'] = link['href']

                elif ('link4' not in d) and ('link' in d) and ('link1' in d) and ('link2' in d) and ('link3' in d):
                    d['link4'] = link['href']


            a_vuln_soup = vuln_soup.find_all('a')
            cve_count = 0
            for a in a_vuln_soup:
                if (cve_count == 0) and ('cve' not in d):
                    if str(a.text).startswith('CVE-'):
                        d['cve'] = str(a.text)
                        cve_count += 1

                elif (cve_count == 1) and ('cve1' not in d):
                    if (str(a.text).startswith('CVE-')) and (str(a.text) != d['cve']):
                        d['cve1'] = str(a.text)
                        cve_count += 1

                elif (cve_count == 2) and ('cve2' not in d):
                    if (str(a.text).startswith('CVE-')) and (str(a.text) != d['cve']) and (str(a.text) != d['cve1']):
                        d['cve2'] = str(a.text)
                        cve_count += 1

                elif (cve_count == 3) and ('cve3' not in d):
                    if (str(a.text).startswith('CVE-')) and (str(a.text) != d['cve']) and (str(a.text) != d['cve1']) and (str(a.text) != d['cve2']):
                        d['cve3'] = str(a.text)
                        cve_count += 1

                elif (cve_count == 4) and ('cve4' not in d):
                    if (str(a.text).startswith('CVE-')) and (str(a.text) != d['cve']) and (str(a.text) != d['cve1']) and (str(a.text) != d['cve2']) and (str(a.text) != d['cve3']):
                        d['cve4'] = str(a.text)
                        cve_count += 1


            child_vuln_soup = vuln_soup.find_all('li')
            for b in child_vuln_soup:
                if str(b.text).startswith('Vendor: '):
                    vendor = str(b.text).lstrip('Vendor: ')
                    d['vendor'] = vendor

                if str(b.text).startswith('Equipment: '):
                    product = str(b.text).lstrip('Equipment: ')
                    d['product'] = product

            if 'cve'not in d:
                d['cve'] = 'No CVE found!'

            if 'vendor' not in d:
                d['vendor'] = 'No vendor specified!'

            if 'product' not in d:
                d['product'] = 'No product specified!'

            if 'details' not in d:
                d['details'] = 'No details specified!'

            if 'link' not in d:
                d['link'] = 'No links provided!'


            cisa_vulns.append(d)




###############


# CVSS is the first bold red colored word in the page. That's why it's in index 0 below.

# cvss = vuln_soup.find_all('strong', attrs={'style': 'color: red;'})[0]
# cvss = float(cvss.text.split()[-1])

# Original release date slicing and converting into date object for comparison.
release_date = vuln_soup.find_all('div', attrs={'class': 'submitted meta-text'})[0]
release_date = release_date.text.strip()
release_date = release_date.split(': ')[1]
release_date = dt.datetime.strptime(release_date, '%B %d, %Y').date()

###############
df = pd.DataFrame({'Vulnerabilities': titles, 'Link': links})
df.to_csv('test.csv', index=False, encoding='utf-8')

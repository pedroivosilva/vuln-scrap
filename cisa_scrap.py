from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import datetime as dt
import pandas as pd
import json

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver2 = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
# driver3 = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

cisa = "https://www.cisa.gov"
driver.get(cisa + "/uscert/ics/advisories")
cisa_advisories = driver.page_source
soup = BeautifulSoup(cisa_advisories, 'html.parser')

all_cisa_vulns = ()  # all CISA vulnerabilities before checking its eligibility.
cisa_vulns = []  # all CISA vulnerabilities after checking its eligibility.
titles = []  # vulnerabilities titles
links = []  # vulnerabilities links

for i in soup.find_all('span', attrs={'class': 'views-field views-field-title'}):
    tag = i.find('a', href=True)
    links.append(cisa + tag['href'])
    titles.append(tag.text)
    all_cisa_vulns = all_cisa_vulns + ([tag.text, cisa + tag['href']],)

# Check if vulnerabilities previously found are within the parameters
# Release date must be < 7 days
# CVSS must be >= 7.0

for vuln_page in all_cisa_vulns:
    driver2.get(vuln_page[1])
    vuln_contents = driver2.page_source
    vuln_soup = BeautifulSoup(vuln_contents, 'html.parser')

    # Original release date slicing and converting into date object for comparison.
    release_date = vuln_soup.find_all('div', attrs={'class': 'submitted meta-text'})[0]
    release_date = release_date.text.strip()
    release_date = release_date.split(': ')[1]
    release_date = release_date.split('|')[0]
    release_date = release_date.strip()
    release_date_parsed = dt.datetime.strptime(release_date, '%B %d, %Y').date()

    # Check if date is <= 7 days
    today = dt.date.today()
    date_delta = today - release_date_parsed

    # If delta is within the period, check the CVSS score.
    # CVSS is the first bold red colored word in the page. That's why it's in index 0 below
    cvss = vuln_soup.find_all('strong', attrs={'style': 'color: red;'})[0]
    cvss = float(cvss.text.split()[-1])

    d = {}
    cve = []
    cves_list = []
    if (date_delta.days <= 7) and (cvss >= 7):
        # Set already known variables.
        d['title'] = vuln_page[0]
        d['cvss'] = cvss
        d['release_date'] = release_date

        # Deploy the main html variables to search for information.
        h3_vuln_soup = vuln_soup.find_all('h3')
        h4_vuln_soup = vuln_soup.find_all('h4')
        a_vuln_soup = vuln_soup.find_all('a', href=True)

        # Get text index (e.g. On the heading "3.2. VULNERABILITY OVERVIEW", 3.2 will be our index)
        # Initiate variable as an 'ERROR' in case it doesn't change we'll notice.
        vulnerability_heading = 'ERROR'

        # Start to scrap.
        for h3tag in h3_vuln_soup:
            if h3tag.string.endswith('VULNERABILITY OVERVIEW'):
                # Strip to cut off all characters after our index.
                vulnerability_heading = h3tag.string.rstrip(' VULNERABILITY OVERVIEW')

        # Get CVE count for this vulnerability and append it to d as cve_count.
        cve_count = 0
        for all_links in a_vuln_soup:

            if str(all_links.text).startswith('CVE-'):
                cve_count += 1
                cves_list.append(all_links.text)

            d['cve_count'] = cve_count

        # Get all cve ids, links and details and add it into another temporary dictionary d_cve.
        # Then, when the loop over, add it into d dictionary under 'cve' key as a list.
        d_cve = {}
        for cve_item in cves_list:
            cve_id = str(cve_item)
            d_cve['cve_id'] = cve_id

            for h4tag in h4_vuln_soup:
                next_parents_links = h4tag.find_next_sibling('p').find_next_sibling('p').find_all('a', href=True)

                # Get link of each cve_id.
                for link in next_parents_links:
                    if link.text == cve_id:
                        d_cve['link'] = link['href']

                # If link is not found, try to find it on another paragraph.
                if 'link' not in d_cve:
                    for link in next_parents_links:
                        second_paragraph = link.find_next_sibling('p').find_next_sibling('p')
                        second_paragraph_links = second_paragraph.find_all('a', href=True)
                        for each_link in second_paragraph:
                            link = each_link['href'].split('=')[-1]
                            if link == cve_id:
                                d_cve['link'] = link['href']
                # If link is not found again, put 'ERROR!' on link field.
                if 'link' not in d_cve:
                    d_cve['link'] = 'ERROR'

            # cve_details_list = []
            # for h4tag in h4_vuln_soup:
                if h4tag.text.startswith(vulnerability_heading):
                    detail = str(h4tag.find_next_sibling('p').string)
                    print(f'{detail}\n\n')
                    d_cve['detail'] = detail
####### A LISTA cve ESTÁ DUPLICANDO. NECESSÁRIO AJUSTAR OS DOIS FOR DESTA SEÇÃO COM O cve.append(d_cve.copy()) ######
            cve.append(d_cve.copy())

        d['cve'] = cve

        # Get vendor or vendors for each vulnerability.
        child_vuln_soup = vuln_soup.find_all('li')
        for child_item in child_vuln_soup:
            if str(child_item.text).startswith('Vendor: '):
                vendor = str(child_item.text).lstrip('Vendor: ')
                d['vendor'] = vendor
            elif str(child_item.text).startswith('Vendors: '):
                vendor = str(child_item.text).lstrip('Vendors: ')
                d['vendors'] = vendor

            if str(child_item.text).startswith('Equipment: '):
                product = str(child_item.text).lstrip('Equipment: ')
                d['product'] = product

        # Check if any key is blank for troubleshooting purposes.
        if 'cve'not in d:
            d['cve'] = 'No CVE found!'

        if ('vendor' not in d) and ('vendors' not in d):
            d['vendor'] = 'No vendor specified!'

        if 'product' not in d:
            d['product'] = 'No product specified!'

        # Add all vulnerability's information into cisa_vulns list.
        cisa_vulns.append(d.copy())
        json_cisa_vulns = json.dumps(cisa_vulns)

###############

#
# # CVSS is the first bold red colored word in the page. That's why it's in index 0 below.
#
# # cvss = vuln_soup.find_all('strong', attrs={'style': 'color: red;'})[0]
# # cvss = float(cvss.text.split()[-1])
#
# # Original release date slicing and converting into date object for comparison.
# release_date = vuln_soup.find_all('div', attrs={'class': 'submitted meta-text'})[0]
# release_date = release_date.text.strip()
# release_date = release_date.split(': ')[1]
# release_date = dt.datetime.strptime(release_date, '%B %d, %Y').date()
#
# ###############
# df = pd.DataFrame({'Vulnerabilities': titles, 'Link': links})
# df.to_csv('test.csv', index=False, encoding='utf-8')

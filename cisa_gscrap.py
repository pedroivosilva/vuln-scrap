import os
import requests as rq
from bs4 import BeautifulSoup
import time as time
import datetime as dt
import re
import pandas as pd


def cisa_df():
    now = dt.date.today()

    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                 '(KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
    headers = {'User-Agent': user_agent}

    cisa = "https://www.cisa.gov/uscert"
    get_cisa = rq.get(cisa + "/ics/advisories?items_per_page=50", headers=headers)

    if get_cisa.status_code == 200:
        cisa_get_advisories = get_cisa.text
        soup = BeautifulSoup(cisa_get_advisories, 'html.parser')
    else:
        print(f'Unexpected answer from {get_cisa.url}\nStatus Code: {get_cisa.status_code}')
        exit()

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

    print(f'\nStarting to scrap CISA vulnerabilities...')
    time.sleep(3)

    for vuln_page in all_cisa_vulns:
        get_cisa = rq.get(vuln_page[1], headers=headers)
        print('====================================================================')
        print(get_cisa.url)
        vuln_contents = get_cisa.text
        vuln_soup = BeautifulSoup(vuln_contents, 'html.parser')

        # Original release date slicing and converting into date object for comparison.
        release_date = vuln_soup.find_all('div', attrs={'class': 'submitted meta-text'})[0].text
        release_date = release_date.strip()
        release_date = release_date.split(': ')[1]
        release_date = release_date.split('|')[0]
        release_date = release_date.strip()
        release_date_parsed = dt.datetime.strptime(release_date, '%B %d, %Y').date()

        # Check if date is <= 7 days
        date_delta = now - release_date_parsed

        # If delta is within the period, check the CVSS score.
        # CVSS is the first bold red colored word in the page. That's why it's in index 0 below
        cvss = vuln_soup.find_all('strong', attrs={'style': 'color: red;'})[0]
        cvss = float(cvss.text.split()[-1])

        print(f'Release date: {release_date}')
        print(f'CVSS v3: {cvss}')

        vuln_d = {}
        if (date_delta.days <= 7) and (cvss >= 7):
            # If date and cvss are within our range, print LOG to user.
            print("LOG")

            # Set already known variables.
            vuln_d['title'] = vuln_page[0]
            vuln_d['cvss'] = cvss
            vuln_d['release_date'] = release_date

            # Deploy the main html variables to search for information.
            h3_vuln_soup = vuln_soup.find_all('h3')
            h4_vuln_soup = vuln_soup.find_all('h4')
            p_texts = vuln_soup.find_all('p')
            a_vuln_soup = vuln_soup.find_all('a', href=True)

            # Get text index (e.g. On the heading "3.2. VULNERABILITY OVERVIEW", 3.2 will be our index)
            # Initiate variable as an 'ERROR' in case it doesn't change we'll notice.
            vulnerability_heading = 'ERROR'

            # Start to scrap.
            cve_list = []
            cve_name_link = ()

            # Get CVE count for this vulnerability and append it to d as cve_count.
            for all_links in a_vuln_soup:

                # If any link starts with 'CVE-' add it to the cve_name_link tuple.
                if str(all_links.text).startswith('CVE-'):
                    cve_link_text = all_links.text
                    cve_link = all_links.get_attribute_list('href')[0]
                    cve_name_link = cve_name_link + ([cve_link_text, cve_link],)
                    print(cve_link_text)

            vuln_d['cve_count'] = len(cve_name_link)

            while len(cve_list) < len(cve_name_link):

                for h3tag in h3_vuln_soup:
                    if h3tag.string.endswith('VULNERABILITY OVERVIEW'):

                        # Strip to cut off all characters after our index.
                        vulnerability_heading = h3tag.string.rstrip(' VULNERABILITY OVERVIEW')

                # Get all cve ids, links and details and add it into another temporary dictionary d_cve.
                # Then, when the loop over, add it into d dictionary under 'cve' key as a list.
                d_cve = {}

                for cve_item in cve_name_link:
                    d_cve['cve_id'] = cve_item[0]
                    d_cve['link'] = cve_item[1]
                    cve_list.append(d_cve.copy())

            cve_cvss_list = []
            for paragraph in p_texts:
                if 'A CVSS v3 base score of ' in paragraph.text:
                    p_cve_cvss = str(paragraph.text)
                    p_cve_cvss = re.findall(r'A CVSS v3 base score of \d{1,2}.{1}\d{1}', p_cve_cvss)
                    cve_cvss = p_cve_cvss[0].split(' ')[-1]
                    cve_cvss_list.append(cve_cvss)

            for index, c in enumerate(cve_cvss_list):
                cve_list[index]['cvss'] = float(c)

            detail_list = []
            for h4tag in h4_vuln_soup:

                if h4tag.text.startswith(vulnerability_heading):
                    detail = str(h4tag.find_next_sibling('p').string)
                    detail_list.append(detail)

            for index, d in enumerate(detail_list):
                cve_list[index]['details'] = str(d)

            vuln_d['cve'] = cve_list

            # Get vendor or vendors for each vulnerability.
            child_vuln_soup = vuln_soup.find_all('li')
            for child_item in child_vuln_soup:
                if str(child_item.text).startswith('Vendor: '):
                    vendor = str(child_item.text).lstrip('Vendor: ')
                    vuln_d['vendor'] = vendor
                elif str(child_item.text).startswith('Vendors: '):
                    vendor = str(child_item.text).lstrip('Vendors: ')
                    vuln_d['vendors'] = vendor

                if str(child_item.text).startswith('Equipment: '):
                    product = str(child_item.text).lstrip('Equipment: ')
                    vuln_d['product'] = product

            # Check if any key is blank for troubleshooting purposes.
            if 'cve' not in vuln_d:
                vuln_d['cve'] = 'No CVE found!'

            if ('vendor' not in vuln_d) and ('vendors' not in vuln_d):
                vuln_d['vendor'] = 'No vendor specified!'

            if 'product' not in vuln_d:
                vuln_d['product'] = 'No product specified!'

            # Add all vulnerability's information into cisa_vulns list.
            cisa_vulns.append(vuln_d.copy())
        else:
            print("NO LOG")

    print('====================================================================')

    final_vendor = ()
    final_product = ()
    final_cve_id = ()
    final_cve_cvss = ()
    final_cve_detail = ()
    final_cve_link = ()

    for i in cisa_vulns:
        count = 0

        while count != int(i['cve_count']):

            final_vendor = final_vendor + ([i['vendor']],)
            final_product = final_product + ([i['product']],)
            final_cve_id = final_cve_id + ([i['cve'][count]['cve_id']],)

            # corrigir futuramente
            try:
                final_cve_cvss = final_cve_cvss + ([i['cve'][count]['cvss']],)
            except KeyError:
                final_cve_cvss = final_cve_cvss + ('X',)

            # corrigir futuramente
            try:
                final_cve_detail = final_cve_detail + ([i['cve'][count]['details']],)
            except KeyError:
                final_cve_detail = final_cve_detail + ('X',)

            final_cve_link = final_cve_link + ([i['cve'][count]['link']],)
            count += 1

    # Data generators for each column of table
    gen_vendor = [v[0] for v in final_vendor]
    gen_product = [p[0] for p in final_product]
    gen_cve_id = [ci[0] for ci in final_cve_id]
    gen_cve_cvss = [cc[0] for cc in final_cve_cvss]
    gen_cve_detail = [cd[0] for cd in final_cve_detail]
    gen_cve_link = [cl[0] for cl in final_cve_link]

    # f_vendor = i['vendor']
    # f_product = i['product']
    # cve_id = i['cve'][count]['cve_id']
    # cve_cvss = i['cve'][count]['cvss']
    # cve_detail = i['cve'][count]['details']
    # cve_link = i['cve'][count]['link']
    # final_vuln = final_vuln + ([f_vendor, f_product, cve_id, cve_cvss, cve_detail, cve_link],)

    df = pd.DataFrame({'Fabricante': gen_vendor, 'Produto Afetado': gen_product,
                       'CVE ID': gen_cve_id, 'CVSS Score': gen_cve_cvss,
                       'Detalhes da Vulnerabilidade': gen_cve_detail, 'Detalhes Adicionais': gen_cve_link, })

    return df


def cisa_csv(dataf, filename='CISA - Tabela de Vulnerabilidades.csv'):

    now = dt.date.today()
    now_str = now.strftime("%d-%m-%Y")
    filename = filename.split('.csv')[0]
    filename = filename + '-' + now_str + '.csv'

    dataf.to_csv(filename, index=False, encoding='utf-8')

    if filename in os.listdir():
        return filename
    else:
        return False

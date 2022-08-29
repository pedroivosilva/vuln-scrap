import os
import requests as rq
from bs4 import BeautifulSoup
import time as time
import datetime as dt
import re
import pandas as pd


def zdi_df():
    now = dt.date.today()

    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                 '(KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
    headers = {'User-Agent': user_agent}

    zdi = 'https://www.zerodayinitiative.com'
    get_zdi = rq.get(zdi + '/advisories/published/', headers=headers)

    if get_zdi.status_code == 200:
        zdi_get_advisories = get_zdi.text
        soup = BeautifulSoup(zdi_get_advisories, 'html.parser')
        print(f'\nStarting to scrap Zero Day Initiative vulnerabilities...')
        time.sleep(3)
    else:
        print(f'Unexpected answer from {get_zdi.url}\nStatus Code: {get_zdi.status_code}')
        exit()

    all_zdi_vulns = ()
    zdi_vulns = []  # all ZDI vulnerabilities after checking its eligibility (Last 7 days and CVSS >= 7)
    titles = []  # vulnerabilities titles
    links = []  # vulnerabilities links

    for i in soup.find_all('tr', attrs={'id': 'publishedAdvisories'}):

        print('====================================================================')

        # Get CVSS score of each vulnerability.
        td_cvss = float(i.find_all('td', attrs={'class': 'sort-td'})[4].text)

        # Get published date of each vulnerability.
        td_release_date = i.find_all('td', attrs={'class': 'sort-td'})[5].text

        # Try to parse dates from string format to date object format.
        try:
            release_date_parsed = dt.datetime.strptime(td_release_date, '%B %d, %Y').date()
        except ValueError:
            td_release_date = re.sub(r'Aug.', 'August', td_release_date)
            td_release_date = re.sub(r'Feb.', 'February', td_release_date)
            td_release_date = re.sub(r'Jan.', 'January', td_release_date)
            release_date_parsed = dt.datetime.strptime(td_release_date, '%B %d, %Y').date()

        # Get ZDI link of each vulnerability page.
        a_tag = i.find_all('a', href=True)[0]
        links.append(zdi + a_tag['href'])
        titles.append(a_tag.text)

        date_delta = now - release_date_parsed

        # Check if vulnerabilities found are within the parameters
        # Release date must be <= 7 days
        # CVSS must be >= 7.0
        if (date_delta.days <= 7) and (td_cvss >= 7.0):
            all_zdi_vulns = all_zdi_vulns + ([a_tag.text, zdi + a_tag['href']],)
            print(f'Release date: {td_release_date}')
            print(f'CVSS v3: {td_cvss}')
            print("LOG")
        else:
            print(f'Release date: {td_release_date}')
            print(f'CVSS v3: {td_cvss}')
            print("NO LOG")

    print('====================================================================\n')

    print(f'Getting details of {len(all_zdi_vulns)} logged vulnerabilities. Please wait...')

    for vuln_page in all_zdi_vulns:

        get_zdi_vuln = rq.get(vuln_page[1], headers=headers)

        if get_zdi_vuln.status_code == 200:

            zdi_get_vuln = get_zdi_vuln.text
            vuln_soup = BeautifulSoup(zdi_get_vuln, 'html.parser')
            tbody = vuln_soup.find_all('table', attrs={'style': 'max-width: 100%;'})
        else:
            print(f'Unexpected answer from {get_zdi_vuln.url}\nStatus Code: {get_zdi_vuln.status_code}\n')
            exit()

        vuln_d = {}
        pass
        # Set already known variables.
        vuln_d['title'] = vuln_page[0]
        vuln_d['release_date'] = td_release_date

        # Extract CVSS Score paragraph from page, split just the decimal value and parse into a float.
        cvss = tbody[0].find_all('tr')[1].find_all('td')[1].text
        cvss = cvss.strip()
        cvss = float(cvss.split(',')[0])
        vuln_d['cvss'] = cvss

        # Scrap all the other information.

        # Try to scrap CVE-ID, if it's available.

        cve_id = tbody[0].find_all('tr')[0].find_all('td')[1].text
        cve_id = cve_id.strip()
        cve_id = str(cve_id.split(',')[0])
        vuln_d['cve_id'] = cve_id

        # Scrap link under "Additional Details" section.
        try:
            cve_link = tbody[0].find_all('tr')[5].find_all('td')[1].find_all('a', href=True)
            cve_link = cve_link[0]['href']
        except IndexError:
            try:
                cve_link = tbody[0].find_all('tr')[0].find_all('td')[1].find_next()['href']
            except KeyError:
                cve_link = 'no links found!'
        finally:
            vuln_d['link'] = cve_link

        # Scrap text of "Vulnerability Details" section.
        details = tbody[0].find_all('tr')[4].find_all('p')
        detail = ''
        for paragraph in details:
            detail += paragraph.text
            detail += ' '
        vuln_d['details'] = detail

        # Scrap vendor under "Affected Vendors".
        vendor = tbody[0].find_all('tr')[2].find_next().find_next().text
        vendor = vendor.strip()
        vuln_d['vendor'] = vendor

        product = tbody[0].find_all('tr')[3].find_next().find_next().text
        product = product.strip()
        vuln_d['product'] = product

        # Check if any key is blank for troubleshooting purposes.
        if 'cve_id' not in vuln_d:
            vuln_d['cve_id'] = 'No CVE-ID found!'
        elif not vuln_d['cve_id']:
            vuln_d['cve_id'] = 'No CVE published yet!'

        if 'vendor' not in vuln_d:
            vuln_d['vendor'] = 'No vendor specified!'

        if 'product' not in vuln_d:
            vuln_d['product'] = 'No product specified!'

        # Add all vulnerability's information into zdi_vulns list.
        zdi_vulns.append(vuln_d.copy())

    final_vendor = ()
    final_product = ()
    final_cve_id = ()
    final_cve_cvss = ()
    final_cve_detail = ()
    final_cve_link = ()

    for i in zdi_vulns:
        final_vendor = final_vendor + ([i['vendor']],)
        final_product = final_product + ([i['product']],)
        final_cve_id = final_cve_id + ([i['cve_id']],)
        final_cve_cvss = final_cve_cvss + ([i['cvss']],)
        final_cve_detail = final_cve_detail + ([i['details']],)
        final_cve_link = final_cve_link + ([i['link']],)

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


def zdi_csv(dataf, filename='ZDI - Tabela de Vulnerabilidades.csv'):
    now = dt.date.today()
    now_str = now.strftime("%d-%m-%Y")
    filename = filename.split('.csv')[0]
    filename = filename + '-' + now_str + '.csv'

    dataf.to_csv(filename, index=False, encoding='utf-8')

    if filename in os.listdir():
        return filename
    else:
        return False

import sys
import cisa_scrap as cisa
import zdi_scrap as zdi
import all_scrap as scrap


def scrap_man():
    print("\nSyntax:\npython scrap.py [OPTION]\n\n")
    print("Available options:\n")
    print("-h or --help\t\tDisplays these instructions.")
    print("-cisa\t\t\tTry to scrap vulnerabilities from 'www.cisa.gov/uscert/ics/advisories to a csv file.")
    print("-zdi\t\t\tTry to scrap vulnerabilities from 'www.zerodayinitiative.com' to a csv file.")
    print("-packetstorm\t\t[IN PROGRESS]Try to scrap vulnerabilities "
          "from 'www.packetstormsecurity.com' to a csv file.")
    print("-all\t\t\tTry to scrap vulnerabilities from all available sources to a single csv file.\n\n")
    print("Created by Pedro Ivo de Oliveira Silva:\npedro.silva@global.ntt, pedroivo.osilva@proton.me")


def scrap_caller(site):

    # If -cisa parameter is given, load cisa_scrap.py module.
    if site == '-cisa':
        scrap_df = cisa.cisa_df()
        scrap_result = cisa.cisa_csv(scrap_df)
        if scrap_result.startswith("CISA"):
            return f'The file "{scrap_result}" was successfully created into the current dir.'
        else:
            return 'ERROR! Please check the cisa_scrap module script.'

    # If -zdi parameter is given, load zdi_scrap.py module.
    elif site == '-zdi':
        scrap_df = zdi.zdi_df()
        scrap_result = zdi.zdi_csv(scrap_df)
        if scrap_result.startswith("ZDI"):
            return f'The file "{scrap_result}" was successfully created into the current dir.'
        else:
            return 'ERROR! Please check the cisa_scrap module script.'

    # elif site == '-abc':
    #     if abc.cisa_csv():
    #         return 'ABC CSV file was successfully created!'
    #     else:
    #         return 'ERROR! Please check the abc_scrap module script.'

    elif site == '-all':
        print("\nScrapping all vulnerabilities from CISA and ZDI.")
        scrap_result = scrap.all_csv()
        if scrap_result.startswith("Tabela"):
            return f'\nSUCCESS!\nA single CSV file "{scrap_result}" containing all ' \
                   f'information was successfully created!'
        else:
            return 'ERROR! Please check the zdi_scrap module script.'
    else:
        return "Please specify the website identifier as an argument.\n" \
               "Example: 'python scrap.py -cisa' or python scrap.py -zdi"


if __name__ == '__main__':

    try:
        if sys.argv[1] == '-cisa' or sys.argv[1] == '-zdi' or sys.argv[1] == '-all':
            s = str(sys.argv[1])
            final_result = scrap_caller(s)
        elif sys.argv[1] == '-h' or sys.argv[1] == '--help':
            scrap_man()
        else:
            raise ValueError("\nInvalid Option. Please check instructions with -h or --help option")
    except IndexError:
        scrap_man()
    except ValueError as err:
        print(err)

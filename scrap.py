import sys
import cisa_scrap as cisa


def scrap_caller(site):
    if site == '-cisa':
        scrap_result = cisa.cisa_csv()
        if not scrap_result:
            return 'ERROR! Please check the cisa_scrap module script.'
        else:
            return f'The file {scrap_result} was successfully created into the current dir.'
    #
    # elif site == '-zdi':
    #     if zdi.cisa_csv():
    #         return 'ZeroDayInitiative CSV file was successfully created!'
    #     else:
    #         return 'ERROR! Please check the zdi_scrap module script.'
    #
    # elif site == '-abc':
    #     if abc.cisa_csv():
    #         return 'ABC CSV file was successfully created!'
    #     else:
    #         return 'ERROR! Please check the abc_scrap module script.'

    else:
        return "Please specify the website as an argument.\nExample: 'python scrap.py -cisa' or python scrap.py -zdi"


if __name__ == '__main__':
    if sys.argv[1] == '-cisa' or sys.argv[1] == '-zdi' or sys.argv[1] == '-abc':
        s = str(sys.argv[1])
        final_result = scrap_caller(s)
        print(final_result)
    else:
        print("\nSyntax:\npython scrap.py [OPTION]\n")
        print("Available options:")
        print("-cisa\tTry to scrap vulnerabilities from 'www.cisa.gov/uscert/ics/advisories to a csv file.'")
        print("-zdi\t[IN PROGRESS]Try to scrap vulnerabilities from 'www.zerodayinitiative.com' to a csv file.")
        print("-abc\t[IN PROGRESS]Try to scrap vulnerabilities from 'www.abc.com' to a csv file.")

#
# def teste(x):
#     x = x + 'FUNCIONA'
#     return x
#
#
# if __name__ == '__main__':
#     s = str(sys.argv[1])
#     print(__name__)
#     print(s)
#     print(teste(s))

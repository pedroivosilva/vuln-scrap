import sys
import datetime as dt
import cisa_scrap as cisa
import zdi_scrap as zdi
import all_scrap as scrap
import zdi_gscrap as gzdi
import cisa_gscrap as gcisa
import all_gscrap as gscrap


def scrap_man():
    print("\nSyntax:\npython scrap.py [OPTION]\n\n")
    print("Available options:\n")
    print("-h or --help\t\tDisplays these instructions.\n")
    print("Scrap opening browser and generate CSV file:")
    print("-cisa\t\t\tScrap vulnerabilities from 'www.cisa.gov/uscert/ics/advisories' w/ Chrome browser.")
    print("-zdi\t\t\tScrap vulnerabilities from 'www.zerodayinitiative.com' w/ Chrome browser.")
    print("-all\t\t\tScrap vulnerabilities from all available sources w/ Chrome browser.\n")
    print("Scrap quietly, generate CSV and log all messages to an output.log file:")
    print("--cisa-silent-log\tScrap vulnerabilities from 'www.cisa.gov/uscert/ics/advisories w/o opening browser.")
    print("--zdi-silent-log\tScrap vulnerabilities from 'www.zerodayinitiative.com' w/o opening browser.")
    print("--all-silent-log\tScrap vulnerabilities from all available sources w/o opening browser.\n\n")
    print("@Author: Pedro Ivo de Oliveira Silva:\npedroivo.osilva@proton.me")


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

    # If -all parameter is given, load all_scrap.py module.
    elif site == '-all':
        print("\nScrapping all vulnerabilities from CISA and ZDI.")
        scrap_result = scrap.all_csv()
        if scrap_result.startswith("Tabela"):
            return f'\nSUCCESS!\nA single CSV file "{scrap_result}" containing all ' \
                   f'information was successfully created!'
        else:
            return 'ERROR! Please check the zdi_scrap module script.'

    # If --cisa-silent-log parameter is given, load cisa_gscrap.py module.
    elif site == '--cisa-silent-log':
        scrap_df = gcisa.cisa_df()
        scrap_result = gcisa.cisa_csv(scrap_df)
        if scrap_result.startswith("CISA"):
            return f'The file "{scrap_result}" was successfully created into the current dir.'
        else:
            return 'ERROR! Please check the cisa_scrap module script.'

    # If --zdi-silent-log parameter is given, load zdi_gscrap.py module.
    elif site == '--zdi-silent-log':
        scrap_df = gzdi.zdi_df()
        scrap_result = gzdi.zdi_csv(scrap_df)
        if scrap_result.startswith("ZDI"):
            return f'The file "{scrap_result}" was successfully created into the current dir.'
        else:
            return 'ERROR! Please check the cisa_scrap module script.'

    # If --all-silent-log parameter is given, load all_gscrap.py module.
    elif site == '--all-silent-log':
        print("\nScrapping all vulnerabilities from CISA and ZDI.")
        scrap_result = gscrap.all_csv()
        if scrap_result.startswith("Tabela"):
            return f'\nSUCCESS!\nA single CSV file "{scrap_result}" containing all ' \
                   f'information was successfully created!'
        else:
            return 'ERROR! Please check the zdi_scrap module script.'


if __name__ == '__main__':

    now = str(dt.datetime.today().strftime('%d-%m-%Y-%H-%M-%S'))

    try:
        if sys.argv[1] == '-cisa' or sys.argv[1] == '-zdi' or sys.argv[1] == '-all':

            print("Starting to scrap, please wait...")

            # Start to scrap based on given argument.
            s = str(sys.argv[1])
            final_result = scrap_caller(s)
            print(final_result)

        elif sys.argv[1] == '--cisa-silent-log' or sys.argv[1] == '--zdi-silent-log'\
                or sys.argv[1] == '--all-silent-log':

            arg = str(sys.argv[1])
            arg = arg.split('-')[2]

            output_file = "output-" + arg + "-" + now + ".log"
            print(f"Logging all output to {output_file}.")
            print("Starting to scrap, please wait...")

            # Start to record terminal messages to a log file.
            old_stdout = sys.stdout
            log_file = open(output_file, "w")
            sys.stdout = log_file

            # Start to scrap based on given argument.
            s = str(sys.argv[1])
            final_result = scrap_caller(s)
            print(final_result)

            sys.stdout = old_stdout
            log_file.close()

            print("Finished. Please check current folder for CSV file.")

        elif sys.argv[1] == '-h' or sys.argv[1] == '--help':
            scrap_man()
        else:
            raise ValueError("\nInvalid Option. Please check instructions with -h or --help option")
    except IndexError:
        scrap_man()
    except ValueError as err:
        print(err)

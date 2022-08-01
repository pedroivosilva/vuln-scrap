import cisa_scrap as cisa
import zdi_scrap as zdi
import pandas as pd
import datetime as dt
import os


def all_csv(filename='Tabela de Vulnerabilidades.csv'):

    now = dt.date.today()
    now_str = now.strftime("%d-%m-%Y")
    filename = filename.split('.csv')[0]
    filename = filename + '-' + now_str + '.csv'

    cisa_df = cisa.cisa_df()
    zdi_df = zdi.zdi_df()

    df_concat = pd.concat([cisa_df, zdi_df], axis=0)

    df_concat.to_csv(filename, index=False, encoding='utf-8')

    if filename in os.listdir():
        return filename
    else:
        return False

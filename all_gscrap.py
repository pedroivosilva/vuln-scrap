import cisa_gscrap as gcisa
import zdi_gscrap as gzdi
import pandas as pd
import datetime as dt
import os


def all_csv(filename='Tabela de Vulnerabilidades.csv'):

    now = dt.date.today()
    now_str = now.strftime("%d-%m-%Y")
    filename = filename.split('.csv')[0]
    filename = filename + '-' + now_str + '.csv'

    cisa_df = gcisa.cisa_df()
    zdi_df = gzdi.zdi_df()

    df_concat = pd.concat([cisa_df, zdi_df], axis=0)

    df_concat.to_csv(filename, index=False, encoding='utf-8')

    if filename in os.listdir():
        return filename
    else:
        return False

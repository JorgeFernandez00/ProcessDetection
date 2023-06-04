import pandas as pd
import os
import xml.etree.ElementTree as ET

class LogData:

    def __init__(self, path, format='parquet'):
        if format == 'parquet':
            self.dataframe = self.__load_parquet__(path)
        elif format == 'xml':
            self.dataframe = self.__load_xml__(path)
        elif format == 'json':
            self.dataframe = self.__load_json__(path)
        else:
            self.dataframe = self.__load_csv__(path)

        if format == 'xml':
            self.dataframe = self.dataframe[['Image', 'ParentImage', 'ProcessGuid', 'ParentProcessGuid', 'UtcTime']]
            self.dataframe['Image'] = self.dataframe['Image'].apply(lambda x: str(x).replace('\\', '/'))
            self.dataframe['ParentImage'] = self.dataframe['ParentImage'].apply(lambda x: str(x).replace('\\', '/'))
        else:
            self.dataframe = self.dataframe[['app', 'parent_processname', 'process_guid', 'parent_process_guid', '_time']]
            self.dataframe['app'] = self.dataframe['app'].apply(lambda x: str(x).replace('\\', '/'))
            self.dataframe['parent_processname'] = self.dataframe['parent_processname'].apply(lambda x: str(x).replace('\\', '/'))
        

    def __load_parquet__(self, dir_path):
        return pd.concat([pd.read_parquet(f"{dir_path}/{file}") for file in os.listdir(dir_path)])
    
    def __load_csv__(self, file_path):
        return pd.read_csv(file_path)
    
    def __load_json__(self, file_path):
        return pd.read_json(file_path, lines=True)

    def __load_xml__(self, file_path):
        """
        Esta función implementa un procesamiento específico para los ficheros XML con los que se cuenta.
        """
        
        tree = ET.parse(file_path)
        root = tree.getroot()

        dicts = []

        for child in root:
            if child[0][1].text == '1':
                row = {}
                for child2 in child:
                    for child3 in child2:
                        if child3.tag == '{http://schemas.microsoft.com/win/2004/08/events/event}Data':
                            row.update({[x for x in child3.attrib.values()][0]: child3.text})
                        else:
                            row.update({child3.tag[55:]: child3.text})

                dicts.append(row)

        return pd.DataFrame(dicts)
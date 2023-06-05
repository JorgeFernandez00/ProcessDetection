from sparse_graph import SparseGraph
from log_data import LogData
import pandas as pd
import matplotlib.pyplot as plt

class Detector:

    def __init__(self, data_path, file_type):
        self.file_type = file_type
        if file_type == 'xml':
            self.name_field = 'Image'
            self.parent_name_field = 'ParentImage'
            self.guid_field = 'ProcessGuid'
            self.parent_guid_field = 'ParentProcessGuid'
            self.time_field = 'UtcTime'
        else:
            self.name_field = 'app'
            self.parent_name_field = 'parent_processname'
            self.guid_field = 'process_guid'
            self.parent_guid_field = 'parent_process_guid'
            self.time_field = '_time'


        print('Loading dataframe')
        self.dataframe = LogData(data_path, format=file_type).dataframe

        self.process_blacklist = pd.read_csv("../potentially_harmful_processes.csv")

    
    def run_analysis(self):
        print('Computing process path frequencies')
        self.__path_frequencies__()
        
        print('Generating graph')
        self.graph = SparseGraph(self.dataframe, file_type=self.file_type)

        print('Extracting process chains')
        self.process_chains = self.graph.get_chains()

        print('Computing chain frequency')
        self.frequencies = self.chain_frequency(self.process_chains)

        # El enfoque de extraer el x% de cadenas más infrecuentes no sirve mientras exista una mayoría de cadenas que aparece una sóla vez.
        # Se descarta un número muy elevado de cadenas que pueden ser potencialmente maliciosas.
        # Sólo se estaría cogiendo un trozo de una región de la distribución donde la frecuencia es plana.
        # last_10_percent_index = int(len(self.frequencies) * 0.9)
        # last_20_percent_index = int(len(self.frequencies) * 0.8)

        # least_frequent_10_percent = self.frequencies[last_10_percent_index:]
        # least_frequent_20_percent = self.frequencies[last_20_percent_index:]

        # print(least_frequent_20_percent)

        print('Computing scores')
        self.score_df = pd.DataFrame(columns=['chain', 'occurrences', 'chain_probability', 'strange_paths', 'harmful_processes', 'total_score'])
        self.score_df['chain'] = self.frequencies['Chain']
        self.score_df['occurrences'] = self.frequencies['Count']
        self.score_df['chain_probability'] = self.score_df.apply(lambda x: self.chain_probability(x['chain']), axis = 1)
        self.score_df['strange_paths'] = self.score_df.apply(lambda x: self.strange_paths(x['chain']), axis=1)
        self.score_df['harmful_processes'] = self.score_df.apply(lambda x: self.potentially_harmful(x['chain']), axis=1)
        self.score_df['total_score'] = self.score_df.apply(lambda x: (1-x['chain_probability'])*0.3 + x['strange_paths']*0.2 + x['harmful_processes']*0.5, axis=1)

    def chain_frequency(self, chains):
        chain_list = []
        for entry in chains.items():
            chain = entry[1]
            
            names = []
            for position in chain:
                guid = self.graph.processes[position]

                name = self.dataframe[self.dataframe[self.guid_field] == guid][self.name_field].values
                
                if len(name) == 0:
                    name = self.dataframe[self.dataframe[self.parent_guid_field] == guid][self.parent_name_field].values

                name = ''.join(name[0])
                names.append(name)
            
            chain_list.append(names)

        frequencies = {}

        for named_chain in chain_list:
            key = tuple(named_chain)
            if frequencies.get(key) is None:
                frequencies.update({key: 1})
            else:
                frequencies.update({key: frequencies.get(key) + 1})

        sorted_chains = dict(sorted(frequencies.items(), key=lambda item: item[1], reverse=True))

        chains_df = pd.DataFrame(sorted_chains.items(), columns=['Chain', 'Count'])

        return chains_df


    def __path_frequencies__(self):
        """
        Alters the dataframe attribute adding a new column with the frequency for the path from where the process was instantiated
        """
        names = self.dataframe[self.name_field].values

        paths = []
        processes = []
        for name in names:
            idx = len(name)
            for char in name[::-1]:
                if char != '/':
                    idx -= 1
                else:
                    break

            proc = name[idx:]
            path = name[:idx]

            processes.append(proc)
            paths.append(path)

        df = pd.DataFrame(columns=['path', 'process'])
        df['path'] = paths
        df['process'] = processes
        df[self.name_field] = self.dataframe[self.name_field].values

        count_series = df.groupby(['path', 'process', self.name_field]).size()
        occurrences_df = count_series.to_frame(name='occurrences').reset_index()

        probabilities = []
        for _, row in occurrences_df.iterrows():
            # Dataframe que contiene únicamente las filas del proceso en cuestión
            process_df = pd.DataFrame(occurrences_df)[occurrences_df['process'] == row['process']]
            total = process_df['occurrences'].sum()
            
            probabilities.append(row['occurrences'] / total)

        occurrences_df['probability'] = probabilities

        self.dataframe['path_probability'] = self.dataframe.apply(lambda x: float(occurrences_df[occurrences_df[self.name_field] == x[self.name_field]]['probability'].values), axis=1)

    def chain_probability(self, chain):
        # TODO: Chain part of bigger chains?
        value = float(self.frequencies[self.frequencies['Chain'] == chain]['Count'] / self.frequencies['Count'].sum())
        return value
    
    def potentially_harmful(self, chain):
        """
        Returns a binary score based on the presence of processes that could be used for living off the land techniques
        """

        split_chain = []
        for name in chain:
            idx = len(name)
            for char in name[::-1]:
                if char != '/':
                    idx -= 1
                else:
                    break

            proc = name[idx:]
            split_chain.append(proc)

        n_suspicious = 0
        for process in self.process_blacklist['Process']:
            if process in split_chain:
                n_suspicious += 1

        ratio = n_suspicious / len(split_chain)

        if ratio == 0:
            return 0
        elif ratio < 0.3:
            return 0.5
        elif ratio < 0.6:
            return 0.75
        else:
            return 1


    def strange_paths(self, chain):
        """
        Returns a score based on the presence of strange paths (file system) in process instantiations
        """
        for process in chain[:-1]:
            process_path_probability = self.dataframe[self.dataframe[self.name_field] == process]['path_probability'].values

            if process_path_probability[0] < 0.3:
                return 1
                
        return 0


import networkx as nx
from pyvis.network import Network

def generate_network(graph_df, parent_col, child_col, weight_col=None, export=False, file_name="network.html", edge_scale=1):
    if weight_col is not None:
        graph_df['weight'] = graph_df[weight_col]
        graph_df['weight'] = graph_df['weight'].apply(lambda x: x * edge_scale)
    else:
        graph_df['weight'] = [1] * len(graph_df)
        graph_df['weight'] = graph_df['weight'].apply(lambda x: x * edge_scale)

    graph = nx.from_pandas_edgelist(graph_df,
                                    source=parent_col,
                                    target=child_col,
                                    edge_attr='weight',
                                    create_using=nx.DiGraph)

    if export:
        #nx.write_gexf(graph, "../launchedProcesses.gexf")
        net = Network(directed=True)
        net.from_nx(graph)
        net.show_buttons()
        net.save_graph(f"../output/{file_name}")

    return graph


if __name__ == "__main__":
    detector = Detector(data_path='../raw/windows-sysmon.xml', file_type='xml')

    # Carga de logs de ataque
    atack_data = pd.read_json

    attack_df = pd.read_json("../raw/empire_launcher_vbs_2020-09-04160940.json", lines=True)

    attack_event_1_df = attack_df[attack_df['EventID'] == 1]

    trimmed_attack_df = attack_event_1_df[['UtcTime', 'ProcessGuid', 'Image', 'ParentProcessGuid', 'ParentImage' ]]

 
    trimmed_attack_df['Image'] = trimmed_attack_df['Image'].apply(lambda x: str(x).replace('\\', '/'))
    trimmed_attack_df['Image'] = trimmed_attack_df['Image'].apply(lambda x: ''.join(x))
    trimmed_attack_df['ParentImage'] = trimmed_attack_df['ParentImage'].apply(lambda x: str(x).replace('\\', '/'))
    trimmed_attack_df['ParentImage'] = trimmed_attack_df['ParentImage'].apply(lambda x: ''.join(x))
    
  
    print('\n\n Results before introducing attack data')
    print(detector.dataframe.size)
    detector.run_analysis()
    sorted_df = detector.score_df.sort_values(by='total_score', ascending=False).reset_index()
    print(sorted_df.head(30))
    print(f'Most anomalous chain: {sorted_df.iloc[0]["chain"]}')
    sorted_df['total_score'].hist(bins=100)
    plt.show()
    sorted_df.to_csv('../output/Output without attack data.csv')

    print(detector.dataframe.columns)
    graph_df = detector.dataframe.copy()
    no_attack_data_network = generate_network(graph_df=graph_df, parent_col='ParentImage', child_col='Image', export=True, file_name='no_attack_data.html')

    print('Results after introducing attack data')
    detector.dataframe = detector.dataframe.append(trimmed_attack_df, ignore_index=True)
    print(detector.dataframe.size)
    detector.run_analysis()
    sorted_df = detector.score_df.sort_values(by='total_score', ascending=False).reset_index()
    print(sorted_df.head(30))
    print(f'Most anomalous: {sorted_df.iloc[0]["chain"]}')
    sorted_df['total_score'].hist(bins=100)
    plt.show()
    sorted_df.to_csv('../output/Output with empire launcher.csv')

    graph_df = detector.dataframe.copy()
    empire_attack_data_network = generate_network(graph_df=graph_df, parent_col='ParentImage', child_col='Image', export=True, file_name='empire_attack_data.html')
    




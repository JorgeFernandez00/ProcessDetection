from scipy import sparse
from scipy.sparse.csgraph import depth_first_order
import pandas as pd

class SparseGraph:

    def __init__(self, dataframe, file_type):
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

        self.dataframe = dataframe.copy()

        self.processes = pd.concat([self.dataframe[self.guid_field], self.dataframe[self.parent_guid_field]], ignore_index=True).unique()

        self.guid_to_idx = {}

        idx = 0
        for guid in self.processes:
            self.guid_to_idx.update({guid: idx})
            idx += 1

        self.dataframe['mat_idx_child'] = self.dataframe[self.guid_field].map(lambda x: self.guid_to_idx.get(x))
        self.dataframe['mat_idx_parent'] = self.dataframe[self.parent_guid_field].map(lambda x: self.guid_to_idx.get(x))
    
        self.matrix = sparse.lil_matrix((len(self.processes), len(self.processes)))

        n_row = 0
        for row in self.dataframe.iterrows():
            idx1 = row[1]['mat_idx_parent']
            idx2 = row[1]['mat_idx_child']
            
            n_row += 1

            value = self.matrix._get_intXint(row=idx1, col=idx2)
            if value == 0:
                self.matrix._set_intXint(row=idx1, col=idx2, x=self.matrix._get_intXint(idx1, idx2) + 1)


    def leaf_nodes(self):
        sums = self.matrix.sum(axis=1)
        leaf_indexes = []

        position = 0
        for idx in sums:
            if idx.item() == 0:
                leaf_indexes.append(position)

            position += 1

        return leaf_indexes
    

    def get_chains(self):
        # Procedimiento de búsqueda de cadenas:
        # - Extraer nodos hoja
        # - Trasponer la matriz
        # - Búsqueda en profundidad desde nodos hoja (no debería tener ramificaciones dado que ningún proceso es creado por más de un padre)

        leaf_indexes = self.leaf_nodes()
        transposed = self.matrix.transpose()

        chains = {}

        for idx in leaf_indexes:
            search = depth_first_order(transposed, idx)[0]
            nodes = []
            for node in search:
                nodes.append(node)
                
            chains.update({idx: nodes})
        
        return chains

            
        
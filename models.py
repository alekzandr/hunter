from sklearn.cluster import MeanShift, estimate_bandwidth

class ms:
    def __init__(self, data, bandwidth, seeds=None, bin_seeding=False, min_bin_freq=1, cluster_all=False, n_jobs=1):
        self.data = data
        self.bandwidth = self.set_bandwidth()
        self.seeds = seeds
        self.bin_seeding = bin_seeding
        self.min_bin_freq = min_bin_freq
        self.cluster_all = cluster_all
        self.n_jobs = n_jobs
        self.model = Meanshift(self.bandwidth, self.seeds, self.bin_seeding, self.min_bin_freq, self.cluster_all, self.n_jobs)
        self.labels = None
        
    def set_bandwidth(self, self.data, quantile=0.3, n_samples=None, random_state=None, n_jobs=1)
        self.bandwidth = estimate_bandwidth(converted_stream_table, quantile, n_samples, n_jobs)
    
    def fit(self, data=self.data, new_data=None):
        if new_data:
            self.data = data
        self.model.fit(data)
        self.labels = self.model.fit.labels_
    
    def predict(self, data)
        return self.model.predict(data)
        
    
        
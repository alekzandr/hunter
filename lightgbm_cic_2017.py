import os
import gc
from functools import partial, wraps
from datetime import datetime as dt
import warnings
warnings.simplefilter('ignore', FutureWarning)

import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)

import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.model_selection import StratifiedKFold
from sklearn import preprocessing
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

import lightgbm as lgb
import cic_2017_setup

gc.collect()

dtypes = {
    "destination_port":               "int32",
"flow_duration":                  "int32",
"total_fwd_packets":              "int32",
"total_backward_packets":         "int32",
"total_length_of_fwd_packets":    "int32",
"total_length_of_bwd_packets":    "int32",
"fwd_packet_length_max":         "int32",
"fwd_packet_length_min":          "int32",
"fwd_packet_length_mean":         "float32",
"fwd_packet_length_std":          "float32",
"bwd_packet_length_max":          "int32",
"bwd_packet_length_min":          "int32",
"bwd_packet_length_mean":         "float32",
"bwd_packet_length_std":          "float32",
"flow_bytes/s":                   "float32",
"flow_packets/s":                 "float32",
"flow_iat_mean":                  "float32",
"flow_iat_std":                   "float32",
"flow_iat_max":                   "int32",
"flow_iat_min":                   "int32",
"fwd_iat_total":                  "int32",
"fwd_iat_mean":                   "float32",
"fwd_iat_std":                    "float32",
"fwd_iat_max":                    "int32",
"fwd_iat_min":                    "int32",
"bwd_iat_total":                  "int32",
"bwd_iat_mean":                   "float32",
"bwd_iat_std":                    "float32",
"bwd_iat_max":                    "int32",
"bwd_iat_min":                    "int32",
"fwd_psh_flags":                  "int32",
"bwd_psh_flags":                  "int32",
"fwd_urg_flags":                  "int32",
"bwd_urg_flags":                  "int32",
"fwd_header_length":              "int32",
"bwd_header_length":              "int32",
"fwd_packets/s":                  "float32",
"bwd_packets/s":                  "float32",
"min_packet_length":              "int32",
"max_packet_length":              "int32",
"packet_length_mean":             "float32",
"packet_length_std":              "float32",
"packet_length_variance":         "float32",
"fin_flag_count":                 "int32",
"syn_flag_count":                 "int32",
"rst_flag_count":                 "int32",
"psh_flag_count":                 "int32",
"ack_flag_count":                 "int32",
"urg_flag_count":                 "int32",
"cwe_flag_count":                 "int32",
"ece_flag_count":                 "int32",
"down/up_ratio":                  "int32",
"average_packet_size":            "float32",
"avg_fwd_segment_size":           "float32",
"avg_bwd_segment_size":           "float32",
"fwd_header_length.1":            "int32",
"fwd_avg_bytes/bulk":             "int32",
"fwd_avg_packets/bulk":           "int32",
"fwd_avg_bulk_rate":             "int32",
"bwd_avg_bytes/bulk":             "int32",
"bwd_avg_packets/bulk":           "int32",
"bwd_avg_bulk_rate":              "int32",
"subflow_fwd_packets":            "int32",
"subflow_fwd_bytes":              "int32",
"subflow_bwd_packets":            "int32",
"subflow_bwd_bytes":              "int32",
"init_win_bytes_forward":         "int32",
"init_win_bytes_backward":        "int32",
"act_data_pkt_fwd":               "int32",
"min_seg_size_forward":           "int32",
"active_mean":                    "float32",
"active_std":                     "float32",
"active_max":                     "int32",
"active_min":                     "int32",
"idle_mean":                      "float32",
"idle_std":                       "float32",
"idle_max":                       "int32",
"idle_min":                       "int32",
"label":                          "category"
}

le = preprocessing.LabelEncoder()
path = "/Users/kyletopasna/Documents/hunter/ISCX CIC/CIC-IDS-2017/"
train = pd.read_csv(path + "train.csv", dtype=dtypes, nrows=2000000)

TARGET = 'label'

def modeling_cross_validation(params, X, y, nr_folds=5):
    clfs = list()
    oof_preds = np.zeros(X.shape[0])
    # Split data with kfold
    kfolds = StratifiedKFold(n_splits=nr_folds, shuffle=False, random_state=42)
    for n_fold, (trn_idx, val_idx) in enumerate(kfolds.split(X, y)):
        X_train, y_train = X.iloc[trn_idx], y.iloc[trn_idx]
        X_valid, y_valid = X.iloc[val_idx], y.iloc[val_idx]

        print("Fold {}".format(n_fold+1))
        
        model = lgb.LGBMClassifier(**params)
        model.fit(
            X_train, y_train,
            eval_set=[(X_valid, y_valid)],
            verbose=200,
            early_stopping_rounds=150
        )

        clfs.append(model)
        oof_preds[val_idx] = model.predict(X_valid, num_iteration=model.best_iteration_)
        
    score = f1_score(y, oof_preds)
    print("f1 score: {}".format(score))
    print("accuracy score: {}".format(accuracy_score(y, oof_preds)))
    print("precision score: {}".format(precision_score(y, oof_preds)))
    print("recall score: {}".format(recall_score(y, oof_preds)))

    return clfs, score
	

def predict_cross_validation(test, clfs):
    sub_preds = np.zeros(test.shape[0])
    for i, model in enumerate(clfs, 1):    
        test_preds = model.predict_proba(test, num_iteration=model.best_iteration_)
        sub_preds += test_preds[:,1]

    sub_preds = sub_preds / len(clfs)
    ret = pd.Series(sub_preds)
    return ret
	
	
def predict_test_chunk(features, clfs, dtypes, filename='tmp.csv', chunks=100000):
    
    print("Writing test predictions to file")
    for i_c, df in enumerate(pd.read_csv('test.csv', chunksize=chunks, dtype=dtypes, iterator=True)):

        df.set_index(TARGET_INDEX, inplace=True)


        preds_df = predict_cross_validation(df[features], clfs)
        preds_df = preds_df.to_frame(TARGET)
    
        if i_c == 0:
            preds_df.to_csv(filename, header=True, mode='a')
        else:
            preds_df.to_csv(filename, header=False, mode='a')
        
        del preds_df
        gc.collect()
    print("Done")
    
    
model_params = {
            'device': 'cpu', 
        "objective": "multiclass",
        "boosting_type": "gbdt", 
        #"learning_rate": 0.03,
        #"max_depth": 8,
        #"num_leaves": 200,
        #"n_estimators": 2500,
        #"bagging_fraction": 0.7,
        #"feature_fraction": 0.7,
        #"bagging_freq": 5,
        #"bagging_seed": 2018,
        #'min_child_samples': 80, 
        #'min_child_weight': 100.0, 
        #'min_split_gain': 0.1, 
        #'reg_alpha': 0.005, 
        #'reg_lambda': 0.1, 
        #'subsample_for_bin': 25000, 
        #'min_data_per_group': 100, 
        #'max_cat_to_onehot': 4, 
        #'cat_l2': 25.0, 
        #'cat_smooth': 2.0, 
        #'max_cat_threshold': 32, 
        #"random_state": 1,
        #"silent": True,
        #"metric": "multi_logloss",
    }    
    
train_features = list()

train_features = [f for f in train.columns if f != TARGET]

le.fit(train[TARGET])
train[TARGET] = le.transform(train[TARGET])

clfs, score = modeling_cross_validation(model_params, train[train_features], train[TARGET], nr_folds=5)
filename = 'Predictions{:.6f}_{}_{}.csv'.format(score, 'LGBM', dt.now().strftime('%Y-%m-%d-%H-%M'))
train = None
gc.collect()
predict_test_chunk(train[train_features], clfs, dtypes, filename=filename, chunks=500000)
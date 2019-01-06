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

import lightgbm as lgb
import cic_2017_setup

_, train = cic_2017_setup.setup()

TARGET = 'labels'

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
        
    score = model.best_score
    print(score)
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
    
    for i_c, df in enumerate(pd.read_csv("test.csv", 
                                         chunksize=chunks, 
                                         dtype=dtypes, 
                                         iterator=True)):
        

        preds_df = predict_cross_validation(df[features], clfs)
        preds_df = preds_df.to_frame(TARGET)
        
        print("Writing test predictions to file")
        
        if i_c == 0:
            preds_df.to_csv(filename, header=True, mode='a')
        else:
            preds_df.to_csv(filename, header=False, mode='a')
        
        del preds_df
        gc.collect()
        print("Grabbin more tests")
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

clfs, score = modeling_cross_validation(model_params, train[train_features], train[TARGET], nr_folds=5)
filename = 'subm_{:.6f}_{}_{}.csv'.format(score, 'LGBM', dt.now().strftime('%Y-%m-%d-%H-%M'))
train = None
gc.collect()
predict_test_chunk(train_features, clfs, dtypes, filename=filename, chunks=500000)
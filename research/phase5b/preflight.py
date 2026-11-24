"""Fit one 1,000-row CPU sanity model on a domain-disjoint development sample."""
import argparse, time
from pathlib import Path
from threadpoolctl import threadpool_limits
from train import load_uci, unique_training, balance, model_for, private

p=argparse.ArgumentParser(); p.add_argument('--uci',required=True); a=p.parse_args()
_,train,validation=load_uci(private(a.uci)); train=balance(unique_training(train),1000)
start=time.perf_counter()
with threadpool_limits(limits=2): model_for('logistic').fit(train.x,train.y)
print({'rows':len(train.y),'features':train.x.shape[1],'class_counts':{'legitimate':int((train.y==0).sum()),'phishing':int(train.y.sum())},'fit_seconds':round(time.perf_counter()-start,4),'validation_domains_disjoint':not bool(set(train.groups)&set(validation.groups)),'cpu_threads_max':2})

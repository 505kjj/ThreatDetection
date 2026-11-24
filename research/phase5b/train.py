"""CPU-bounded Phase 5B general phishing retraining; all paths are private."""
import argparse, json, os, sys, time, hashlib, threading
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, roc_auc_score, confusion_matrix
from threadpoolctl import threadpool_limits
import joblib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research'))
sys.path.insert(0, str(ROOT / 'research' / 'phase3d'))
from experiment_data import read_manifest, load_partition, sha256
from benchmark import Rows, external, unique_training, balance, model_for, disjoint
from experiment_metrics import classify, negative_domain_scores, threshold_at_target

def private(path):
    p = Path(path).resolve()
    if p.is_relative_to(ROOT): raise ValueError('Private data and outputs must remain outside Git')
    return p

def load_uci(directory):
    d = directory / 'development'; m = read_manifest(d)
    tr = load_partition(d, m, 'train'); va = load_partition(d, m, 'validation')
    return m, Rows(np.pad(tr.features, ((0,0),(0,1))), tr.labels, tr.groups, np.full(len(tr.labels),'',dtype='U1')), Rows(np.pad(va.features,((0,0),(0,1))),va.labels,va.groups,np.full(len(va.labels),'',dtype='U1'))

def load_phresh(directory):
    m=json.loads((directory/'manifest.json').read_text()); tr=external(directory,'train',m['partitions']['train']); va=external(directory,'validation',m['partitions']['validation']); disjoint(tr,va); return m,tr,va

def fit_eval(name, cohort, train, calibration, evals, out, seed):
    x,y=train.x,train.y
    model=model_for(name)
    begin=time.perf_counter()
    with threadpool_limits(limits=2): model.fit(x,y)
    fit_s=time.perf_counter()-begin
    dest=out/'models'/f'{cohort}-{name}.joblib'; dest.parent.mkdir(exist_ok=True)
    joblib.dump(model,dest,compress=3)
    cal=model.predict_proba(calibration.x)[:,1]
    thresholds={str(t):threshold_at_target(negative_domain_scores(calibration.y,cal,calibration.groups),t,.05) for t in (.01,.001)}
    reports={}
    for source,data in evals.items():
        start=time.perf_counter(); scores=model.predict_proba(data.x)[:,1]; elapsed=time.perf_counter()-start
        pred=scores>=.5; cm=confusion_matrix(data.y,pred,labels=[0,1]).tolist()
        reports[source]={'rows':len(data.y),'positive':int(data.y.sum()),'precisionRecallAuc':float(average_precision_score(data.y,scores)),
          'rocAuc':float(roc_auc_score(data.y,scores)),'threshold05':classify(data.y,scores,data.groups,.5),'confusionMatrixTN_FP_FN_TP':cm,
          'recallAtFprConstraints':{str(t):(None if thresholds[str(t)]['threshold'] is None else classify(data.y,scores,data.groups,thresholds[str(t)]['threshold'])) for t in thresholds},
          'scoreQuantiles':{str(q):float(np.quantile(scores,q)) for q in [0,.1,.5,.9,1]},
          'inferenceMsPerUrl':1000*elapsed/len(data.y)}
    return {'cohort':cohort,'model':name,'rows':len(y),'classCounts':{'legitimate':int((y==0).sum()),'phishing':int(y.sum())},'fitSeconds':fit_s,'compressedModelBytes':dest.stat().st_size,'modelSha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'thresholdCalibration':thresholds,'evaluation':reports}

def main():
    p=argparse.ArgumentParser();p.add_argument('--uci',required=True);p.add_argument('--phresh',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    uci=private(a.uci);phresh=private(a.phresh);out=private(a.output);out.mkdir(parents=True,exist_ok=False)
    os.environ.update(OMP_NUM_THREADS='2',MKL_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='-1')
    um,ut,uv=load_uci(uci);pm,pt,pv=load_phresh(phresh)
    # Fixed 20k balanced source samples, per existing Phase 3D CPU protocol.
    ud=unique_training(ut);pd=unique_training(pt)
    disjoint(ud,pd);disjoint(ud,pv);disjoint(pd,uv)
    cohorts={'uci':balance(ud,20000),'phresh':balance(pd,20000),'mixed':Rows(np.concatenate([balance(ud,10000).x,balance(pd,10000).x]),np.concatenate([balance(ud,10000).y,balance(pd,10000).y]),np.concatenate([balance(ud,10000).groups,balance(pd,10000).groups]),np.concatenate([balance(ud,10000).families,balance(pd,10000).families]))}
    manifest={'createdUtc':datetime.now(timezone.utc).isoformat(),'seed':143,'featureVersion':'url-lexical-v1','featureCount':14,'uciTrainSha256':um['train']['sha256'],'uciValidationSha256':um['validation']['sha256'],'phreshTrainSha256':pm['partitions']['train']['sha256'],'phreshValidationSha256':pm['partitions']['validation']['sha256'],'phreshFinalTestUsed':False,'phase3fArchiveUsed':False,'crossSourceDomainOverlap':0,'trainingRows':{k:len(v.y) for k,v in cohorts.items()},'selection':'Phase3D fixed CPU model configurations; no hyperparameter selection against cross-source evaluations'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    result=[]
    with threadpool_limits(limits=2):
      for c,tr in cohorts.items():
        cal={'uci':uv,'phresh':pv}[c] if c!='mixed' else pv
        for model in ('logistic','forest','xgboost'):
          result.append(fit_eval(model,c,tr,cal,{'uci-validation':uv,'phresh-validation':pv},out,143));print(f'{c} {model} done',flush=True)
    (out/'results.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'output':str(out),'runs':len(result),'trainRows':manifest['trainingRows']}),flush=True)
if __name__=='__main__': main()

import unittest
from train import load_uci, load_phresh, private
from pathlib import Path

class Phase5BDataContractTests(unittest.TestCase):
    def test_pinned_private_cohorts_and_common_schema(self):
        root=Path(r'C:\Users\kj\threat-detection-experiments')
        _,ut,uv=load_uci(root/'phiusiil-v1'/'dataset')
        _,pt,pv=load_phresh(root/'phase-3d-v1'/'phresh')
        self.assertEqual(ut.x.shape[1],15)
        self.assertEqual(pt.x.shape[1],15)
        self.assertEqual(set(ut.y),{0,1})
        self.assertFalse(set(ut.groups)&set(pt.groups))
        self.assertFalse(set(ut.groups)&set(pv.groups))
        self.assertFalse(set(pt.groups)&set(uv.groups))
        self.assertEqual(len(uv.y),37269)
        self.assertEqual(len(pv.y),51059)

    def test_private_path_rejects_git_checkout(self):
        with self.assertRaises(ValueError): private(Path(__file__).resolve().parents[2])

if __name__=='__main__': unittest.main()

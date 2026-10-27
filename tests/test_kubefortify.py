import unittest,yaml,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from kubefortify import scan
class Tests(unittest.TestCase):
 def test_unsafe(self):
  root=pathlib.Path(__file__).resolve().parents[1]
  rules={x['rule'] for x in scan(yaml.safe_load((root/'examples/unsafe.yml').read_text()))}
  self.assertTrue({'host-network','privileged','mutable-image'}<=rules)
 def test_safe_pod(self):
  doc={'kind':'Pod','metadata':{'name':'ok'},'spec':{'containers':[{'name':'x','image':'nginx:1.27','securityContext':{'privileged':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True}}]}}
  self.assertEqual(scan(doc),[])

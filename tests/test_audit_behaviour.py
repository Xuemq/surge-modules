"""Representative contracts for the reviewed post-assembly conflict repairs."""
import json,re,unittest
from pathlib import Path
from surge_merge.core import parse_module,params
ROOT=Path(__file__).resolve().parents[1]

class AuditBehaviour(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.m=parse_module((ROOT/'modules/merged.optimized.sgmodule').read_bytes(),'release')
 def matches(self,section,url):
  return [e for e in self.m.entries if e.section==section and e.pattern and re.search(e.pattern,url)]
 def response(self,url):
  return [e for e in self.matches('Script',url) if params(e.raw.partition('=')[2]).get('type')=='http-response']
 def test_baidu_one_binary_handler(self):
  es=self.response('https://newclient.map.baidu.com/client/phpui2/?qt=ads')
  self.assertEqual(len(es),1); self.assertEqual(params(es[0].raw.partition('=')[2])['binary-body-mode'],'true')
 def test_umetrip_exact_path_and_scheme(self):
  es=[e for e in self.m.entries if e.section=='Script' and 'umetrip_ads.js' in e.raw];self.assertEqual(len(es),1)
  p=es[0].pattern
  for host in ('home.umetrip.com','114.115.217.129'):
   for scheme in ('http','https'):
    self.assertTrue(re.search(p,f'{scheme}://{host}/gateway/api/umetrip/native'))
  for u in ('http://114.115.217.129/unrelated','http://other.net/home.umetrip.com/gateway/api/umetrip/native','htt://home.umetrip.com/gateway/api/umetrip/native'):
   self.assertFalse(re.search(p,u))
 def test_amdc_http_not_shadowed_by_noop(self):
  es=self.response('http://amdc.m.taobao.com/amdc/mobileDispatch');self.assertEqual(len(es),1)
  self.assertIn('/amdc.js',es[0].raw)
  self.assertFalse(any('/header.js' in e.raw for e in self.m.entries if e.section=='Script'))
 def test_kfc_one_working_reject(self):
  es=self.matches('URL Rewrite','https://res.kfc.com.cn/advertisement/a');self.assertEqual(len(es),1)
  self.assertIn('reject',es[0].raw)
 def test_jd_start_retains_json_handler(self):
  u='https://api.m.jd.com/client.action?functionId=start'
  self.assertEqual(self.matches('Map Local',u),[])
  es=self.response(u);self.assertEqual(len(es),1);self.assertIn('/jingdong.js',es[0].raw)
  self.assertTrue(self.matches('Map Local',u.replace('https:','http:')))
 def test_taobao_https_and_http_each_once(self):
  for scheme in ('http','https'):
   self.assertEqual(len(self.response(scheme+'://poplayer.template.alibaba.com/test.json')),1)
 def test_representative_disjoint_fallbacks(self):
  urls=['https://t7z.cupid.iqiyi.com/mixer?a','http://abc.cupid.iqiyi.com/mixer?a',
    'https://api.coolapk.com/v6/feed/detail?a','https://api.coolapk.com/v6/main/init',
    'https://api.zhihu.com/answers/v2/1','https://page-info.zhihu.com/answers/v2/1',
    'https://api.zhihu.com/topstory/recommend','https://web-render.zhihu.com/topstory/recommend',
    'https://api.zhihu.com/articles/v2/1','https://api.zhihu.com/articles/v3/1',
    'https://api.zhihu.com/topstory/hot-lists/total','http://api.zhihu.com/topstory/hot-lists/total',
    'https://api.zhihu.com/next-render','http://api.zhihu.com/next-render']
  for u in urls:
   with self.subTest(url=u):self.assertEqual(len(self.response(u)),1)
 def test_exact_mitm_delta(self):
  policy=json.loads((ROOT/'merged-policy.json').read_bytes())['reviewed_repairs']
  self.assertEqual(policy['mitm']['add_hosts'],['mcsp.cloudpnr.com','saas-ad.cloudpnr.com','iqushangwang.8quan.com','vue3-api.zhixiny.cn'])
 def test_domain_coverage_proofs_and_serialization(self):
  for name in ('fmz-policy.json','merged-policy.json'):
   policy=json.loads((ROOT/name).read_bytes())['reviewed_repairs']
   self.assertEqual(sum(i['kind']=='covered-domain' for i in policy['entries']),406)
   for i in policy['entries']:
    if i['replacement'] and 'pattern=' in i['replacement']:
     p=params(i['replacement'].partition('=')[2]);self.assertIn('script-path',p)
     if i['kind']=='disjoint-pattern':self.assertNotIn(',',p['pattern'])

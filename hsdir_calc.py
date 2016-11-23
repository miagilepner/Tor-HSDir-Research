#!/usr/bin/env python
from stem.descriptor import DocumentHandler
from stem.descriptor import parse_file
from stem.descriptor.reader import DescriptorReader
from stem import Flag
import os
import base64
import binascii 
import bisect 
import calc_ids
import datetime, calendar
import tarfile
import json

#returns a list of the 3 hsdirs closest to but larger than digest
def getDirs(digest, hsdirs_sorted, hsdirs_keys):
  dirlist = []
  decode_digest = base64.b32decode(digest,1)
  hsdir_size = len(hsdirs_sorted)
  for i in range(hsdir_size):
    if i==hsdir_size-1 and hsdirs_keys[i] < decode_digest:
      dirlist.extend([hsdirs_sorted[0], hsdirs_sorted[1], hsdirs_sorted[2], hsdirs_sorted[3]])
    else:
      if hsdirs_keys[i] >= decode_digest:
        dirlist.extend([hsdirs_sorted[i], hsdirs_sorted[(i+1)%hsdir_size], hsdirs_sorted[(i+2)%hsdir_size], hsdirs_sorted[(i+3)%hsdir_size]])
        break
  return dirlist  

#analyzes HSDirs for a month at a time 
#finds 3 HSDirs for digest_one and 3 for digest_two
#outputs all details for these HSDirs
def analyzeHSDirs(entry, digest):
  digests = digest[1]
  digest_one = digests[0]
  digest_two = digests[1]
  cons = next(parse_file(entry, document_handler=DocumentHandler.DOCUMENT))
  descriptors = cons.routers.items()
  hsdirs = [desc[1] for desc in descriptors if Flag.HSDIR in desc[1].flags]
  hsdirs_sorted = sorted(hsdirs, key=lambda descriptor:binascii.unhexlify(descriptor.fingerprint))
  hsdirs_keys = [binascii.unhexlify(descriptor.fingerprint) for descriptor in hsdirs_sorted]
  onelist = getDirs(digest_one, hsdirs_sorted, hsdirs_keys)
  twolist = getDirs(digest_two, hsdirs_sorted, hsdirs_keys)
  dirlist = onelist+twolist
  return createDict(dirlist) 

def createDict(dirlist):
  json_data = {}
  i = 0
  for item in dirlist:
    i=i+1
    item_dict = {}
    item_dict['nickname'] = item.nickname
    item_dict['fingerprint'] = item.fingerprint
    item_dict['published'] = str(item.published)
    item_dict['address'] = item.address
    item_dict['or_port'] = item.or_port
    item_dict['dir_port'] = item.dir_port
    item_dict['flags'] = []
    for flag in item.flags:
      item_dict['flags'].append(flag) 
    item_dict['version_line'] = item.version_line 
    if hasattr(item, 'bandwidth'):
      item_dict['bandwidth'] = item.bandwidth
    if hasattr(item, 'exit_policy'):
      item_dict['exit_policy'] = item.exit_policy._policy
    if hasattr(item, 'measured'):
      item_dict['measured'] = item.measured
    if hasattr(item, 'identifier_type'):
      item_dict['identifier_type'] = item.identifier_type 
    json_data[i] = item_dict
  return json_data

#gets digests and calls analyzeHSDirs
def run(onion_address):
  months = 12 
  digestList = calc_ids.findDigests(onion_address, months)
  if not os.path.exists("/home/mge/%s" % onion_address):
    os.mkdir("/home/mge/%s" % onion_address)
  for dig in digestList:
    newdate = dig[0]
    if dig[0].hour == 23:
      newdate = dig[0] + datetime.timedelta(hours=1)
    monthNum = ""
    monthNum = str(newdate.month)
    if newdate.month < 10:
      monthNum = "0%s" % monthNum
    hrNum = str(newdate.hour)
    if newdate.hour<10:
      hrNum = "0%s" % hrNum
    dayNum = str(newdate.day)
    if newdate.day < 10:
      dayNum = "0%s" % dayNum
    if os.path.exists("/home/mge/%s/%d-%s-%s-%s.json" % (onion_address, newdate.year, monthNum, dayNum, hrNum)):
      continue
    tarName = "/home/mge/old_consensus/consensuses-%d-%s.tar.xz" % (newdate.year, monthNum)
    tarFileName = "consensuses-%d-%s/%s/%d-%s-%s-%s-00-00-consensus" % (newdate.year, monthNum, dayNum, newdate.year, monthNum, dayNum, hrNum) 
    with tarfile.open(tarName, mode='r:xz') as tf:
      try:
        f = tf.extractfile(tf.getmember(tarFileName))
      except:
        print("FAILED: %s" % tarFileName)
        continue
      data = analyzeHSDirs(f, dig)
      output = open("/home/mge/%s/%d-%s-%s-%s.json" % (onion_address, newdate.year, monthNum, dayNum, hrNum), 'w') 
      json.dump(data, output)
      f.close()
      tf.members = []
run("easycoinsayj7p5l.onion")
run("jzn5w5pac26sqef4.onion")
run("y3fpieiezy2sin4a.onion")
run("qkj4drtgvpm7eecl.onion")
run("ow24et3tetp6tvmk.onion")
run("shopsat2dotfotbs.onion")
run("bj6sy3n7tbt3ot2f.onion")
run("abbujjh5vqtq77wg.onion")
run("2ogmrlfzdthnwkez.onion")
run("xfnwyig7olypdq5r.onion")
run("ybp4oezfhk24hxmb.onion")
run("vfqnd6mieccqyiit.onion")
run("en35tuzqmn4lofbk.onion")
run("rso4hutlefirefqp.onion")
run("newpdsuslmzqazvr.onion")
run("smoker32pk4qt3mx.onion")
run("fzqnrlcvhkgbdwx5.onion")
run("kbvbh4kdddiha2ht.onion")
run("s5q54hfww56ov2xc.onion")
run("ll6lardicrvrljvq.onion")
run("25ffhnaechrbzwf3.onion")
run("mobil7rab6nuf7vx.onion")
run("tuu66yxvrnn3of7l.onion")
run("tfwdi3izigxllure.onion")
run("2kka4f23pcxgqkpv.onion")
run("3dbr5t4pygahedms.onion")
run("k4btcoezc5tlxyaf.onion")
run("ejz7kqoryhqwosbk.onion")
run("xqz3u5drneuzhaeo.onion")
run("kpvz7ki2v5agwt35.onion")
run("dppmfxaacucguzpc.onion")
run("ekwreugkil5ncyyh.onion")
run("eqt5g4fuenphqinx.onion")
run("xmh57jrzrnw6insl.onion")
run("hpuuigeld2cz2fd3.onion")
run("x7yxqg5v4j6yzhti.onion")
run("p3lr4cdm3pv4plyj.onion")
run("6dyi4t72u7y6g763.onion")
run("53otrkyvae462lhb.onion")
run("4eiruntyxxbgfv7o.onion")
run("4v6veu7nsxklglnu.onion")
run("a5ec6f6zcxtudtch.onion")
run("c4wcxidkfhvmzhw6.onion")
run("jhiwjjlqpyawmpjx.onion")
run("k54ids7luh523dbi.onion")
run("sc3njt2i2j4fvqa3.onion")
run("ajqaivfxtqy3fdlr.onion")
run("nel2xugswcy7qv7r.onion")
run("hv2ow7li345lki5w.onion")
run("wjngphmzk6mr2pt5.onion")
run("lotjbov3gzzf23hc.onion")
run("34uvre3xzku2eanr.onion")
run("f3ew3p7s6lbftqm5.onion")
run("i7hknwg4up2jhdkx.onion")
run("p7d2k2xiioailnuu.onion")
run("squareh565qgkioq.onion")
run("utovvyhaflle76gh.onion")
run("xfq5l5p4g3eyrct7.onion")
run("clsvtzwzdgzkjda7.onion")
run("3terbsb5mmmdyhse.onion")
run("g7pz322wcy6jnn4r.onion")
run("jchlju4s5zi5i425.onion")
run("js6ogt27wjnbsdux.onion")
run("kwv7z64xyiva22fw.onion")
run("mtn2fcv7yerki2op.onion")
run("pdjcu4js2y4azvzt.onion")
run("pw5odgnkkhsuslol.onion")
run("rvomgbplxtz4e7jv.onion")
run("tag3ulp55xczs3pn.onion")
run("wdnqg3ehh3hvalpe.onion")
run("ybi5yfcdw6mxqlvn.onion")
run("zgmxllflvb7oza7t.onion")
run("dts563ge5y7c2ika.onion")
run("wuvdsbmbwyjzsgei.onion")
run("qlzkoetmfgl3vgjf.onion")
run("am4wuhz3zifexz5u.onion")
run("duskgytldkxiuqc6.onion")
run("nwycvryrozllb42g.onion")
run("p2uekn2yfvlvpzbu.onion")
run("kpynyvym6xqi7wz2.onion")
run("hb4pm4eznzhd6mts.onion")
run("d6mbioyge4posl7r.onion")
run("zw3crggtadila2sg.onion")
run("od6j46sy5zg7aqze.onion")
run("wyxwerboi3awzy23.onion")
run("uzz3h4ruguwza4fr.onion")
run("3mrdrr2gas45q6hp.onion")
run("3suaolltfj2xjksb.onion")
run("65bgvta7yos3sce5.onion")
run("ci3hn2uzjw2wby3z.onion")
run("q2uftrjiuegl4ped.onion")
run("qm3monarchzifkwa.onion")
run("stlw74hqbtzoshyg.onion")
run("tghtnwsywvvhromy.onion")
run("wx3wmh767azjjl4v.onion")
run("npieqpvpjhrmdchg.onion")
run("freesidehsb4g5vg.onion")
run("k6gsb4ibatcico35.onion")
run("6g2osf4l534bozmu.onion")
run("b2psupe2rienya5n.onion")
run("cxoz72fgevhfgitm.onion")
run("tdgknw25wqm5sbhg.onion")
run("utup22qsb6ebeejs.onion")
run("b6kpigzhrdhibmos.onion")
run("yeeshafbtyf7aipe.onion")
run("tjbxptkkgx2qmeqz.onion")
run("74ypjqjwf6oejmax.onion")
run("tovfhccd4sv3kez4.onion")
run("fkyvwpu7ccsorke2.onion")
run("hq3hmoa4thdplmta.onion")
run("6sgjmi53igmg7fm7.onion")
run("2ddjd7xsni7pefcx.onion")
run("2wjsnwzoeiae4iyf.onion")
run("cx4vwijytopjvedi.onion")
run("pdjfyv7v3pn34w4f.onion")
run("r2tjckbrme3yeenx.onion")
run("gx72uexxlkzofk6p.onion")
run("wi7o5wxt4ked7soq.onion")
run("leakager742hufco.onion")
run("sx3jvhfgzhw44p3x.onion")
run("zbnnr7qzaxlk5tms.onion")
run("vv7pabmmyr2vnflf.onion")
run("ibhg35kgdvnb7jvw.onion")
run("kenny7svk4sg2mcj.onion")
run("3g2upl4pq6kufc4m.onion")
run("fcl3t6t66uv3u4og.onion")
run("iwdmsbpxclyjhi4e.onion")
run("2zyakjq2hvtbg6qd.onion")
run("qyy2n2lqpc5l524q.onion")
run("oj3nqbmyudyl4mgn.onion")
run("ie4hf3qxzoazywoi.onion")
run("zitanihpqsvi2lav.onion")
run("zqiirytam276uogb.onion")
run("xxieg3mbvoh26pvs.onion")
run("r33rs4kqbjvdxuk2.onion")
run("v7ovl2hciwt72lqi.onion")
run("l4tay4mx3vyjdn4i.onion")
run("6jzwxsoxmlefkkkl.onion")
run("7pwhaqsxbjdj27gx.onion")
run("7ymfzygewl4n6usp.onion")
run("ar3ubs6cg6an4ylt.onion")
run("deurfnquin7mvni2.onion")
run("j4ddjgxetfx2ybcx.onion")
run("qdsuildbdofkrhe3.onion")
run("jbsex4wngjpo5i27.onion")
run("vjelr2xdaqsgslzr.onion")
run("rzb5nlpvy5oqnket.onion")
run("pibn3ueheubjxv2z.onion")
run("uaga3aoawaj6hohg.onion")
run("cwesjxczvcvwvapz.onion")
run("n2qxamb4ujm53cas.onion")
run("qubsrxat5qsaw5u5.onion")
run("ont6bv4bg7rtgaos.onion")
run("nemlq3kd36frgvzp.onion")
run("xlmg6p4ueely7mhh.onion")
run("w56hjpxn45yzohqa.onion")
run("y4bzva6k3l2l7rla.onion")
run("2dn2dmxt5uwnxz3j.onion")
run("kd6qr7xh42coxooq.onion")
run("s6cco2jylmxqcdeh.onion")
run("uqtinqynmibpoa2s.onion")
run("fcnwebggxt2d3h64.onion")
run("wd43uqrbjwe6hpre.onion")
run("zce2gyru25cvynqc.onion")

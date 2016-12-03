import calc_ids
import json
import socket 
from collections import Counter
import calc_ids
import statistics
from datetime import timedelta
import base64

def difference(one, two):
  if one<two:
    return two-one
  return two-one

def transformTimestamp(newdate):
  if newdate.hour == 23:
    newdate = newdate+datetime.timedelta(hours=1)
  monthNum = ""
  monthNum = str(newdate.month)
  if newdate.month < 10:
    monthNum = "0%s" % monthNum 
  hrNum = str(newdate.hour)
  if newdate.hour < 10:
    hrNum = "0%s" % hrNum
  dayNum = str(newdate.day)
  if newdate.day < 10:
    dayNum = "0%s" % dayNum
  suffix = "%d-%s-%s-%s" % (newdate.year, monthNum, dayNum, hrNum)
  return suffix

#this is ugly. i'll fix it later
def findDigestDistance(onion, suffix, digestList, hsdirs):
  hash_json = open("/home/mge/hashrings/%s.json" % suffix, "r")
  hashring = json.load(hash_json)
  diff_ones = []
  diff_fours = []
  hash_len = len(hashring)
  for i in range(hash_len):
    diff_four = difference(int(hashring[i],16), int(hashring[(i+4) % hash_len],16))
    diff_one = difference(int(hashring[i],16), int(hashring[(i+1) % hash_len],16))
    diff_ones.append(diff_one)
    diff_fours.append(diff_four)
  mean_one = statistics.mean(diff_ones)
  mean_four = statistics.mean(diff_fours)     
  div_one = statistics.stdev(diff_ones)
  div_four = statistics.stdev(diff_fours)
  digests = []
  for digest in digestList:
    newdate = digest[0] 
    timeval = transformTimestamp(newdate)
    if timeval == suffix:
      digests = digest[1]
  digests[0] = base64.b32decode(digests[0],1)
  digests[1] = base64.b32decode(digests[1],1)
  digests[0] = int.from_bytes(digests[0],byteorder='big')
  digests[1] = int.from_bytes(digests[1],byteorder='big')
  one_one = int(hsdirs['1']['fingerprint'],16) - digests[0]
  two_one = int(hsdirs['5']['fingerprint'],16) - digests[1]
  one_four = int(hsdirs['4']['fingerprint'],16) - digests[0]
  two_four = int(hsdirs['8']['fingerprint'],16) - digests[1] 
  z_ones = []
  z_fours = []
  z_ones.append((one_one-mean_one)/div_one)
  z_ones.append((two_one-mean_one)/div_one)
  z_fours.append((one_four-mean_four)/div_four)
  z_fours.append((two_four-mean_four)/div_four)
   
  hash_json.close()
  return z_ones, z_fours

def findReverseDNS(onion, suffix, hsdirs):
  domains = []
  for i,hsdir in hsdirs.items():
    if i == '4' or i == '8':
      continue
    try:
      domain = socket.gethostbyaddr(hsdir['address'])[0] 
    except socket.herror:
      print("FAILED: %s" % hsdir['address'])
      continue
    parts = domain.split(".")[-2:]
    domains.append(".".join(parts))
  c = Counter(domains)
  return c.most_common() 
 
def findSimilarTraits(hsdirs):
  #test for nicknames that are the same
  nicknames = []
  
  #test for ports that are the same 
  or_ports = []
  dir_ports = []
  
  #test for variance of bandwidth
  bandwidths = []
  
  #test for same policies
  exits = [] 
  for i,hsdir in hsdirs.items():
    if i == '4' or i == '8':
      continue
    nicknames.append(hsdir['nickname'])
    or_ports.append(hsdir['or_port'])
    dir_ports.append(hsdir['dir_port'])
    if 'bandwidth' in hsdir:
      bandwidths.append(hsdir['bandwidth'])
    if 'exit_policy' in hsdir:
      exits.append(hsdir['exit_policy'])
  common_nick = Counter(nicknames).most_common()
  common_or = Counter(or_ports).most_common()
  common_dir = Counter(dir_ports).most_common()
  common_exits = Counter(exits).most_common()
  var_band = statistics.variance(bandwidths)
  return common_nick, common_or, common_dir, common_exits, var_band


def run():
  onions = open("descriptor_list.txt", "r")
  for onion in onions:
    folder = make_hashring.stripOnion(onion)
    data = os.listdir("/home/mge/%s" % folder)
    digests = calc_ids.findDigests(onion, 12) 
    for datum in data:
      datum = datum.strip(".json")
      dates = datum.split("-")
      yr = dates[0]
      mon = dates[1]
      day = dates[2]
      hr = dates[3]
      suffix = "%s-%s-%s-%s" % (yr, mon, day, hr)    
      hsdirs_json = open("/home/mge/%s/%s.json" % (onion, suffix), "r")  
      hsdirs = json.load(hsdirs_json)
      
      z_ones, z_fours = findDigestDistance(onion, suffix, digests, hsdirs)
      dns = findReverseDNS(onion, suffix, hsdirs)
      common_nick, common_or, common_dir, common_exits, var_band = findSimilarTraits(hsdirs)
      hsdirs_json.close()
  onions.close()
 
def test():
  onion = "duskgytldkxiuqc6.onion"
  digests = calc_ids.findDigests(onion, 12) 
  suffix = "2016-10-14-14"
  hsdirs_json = open("/home/mge/%s/%s.json" % (onion, suffix), "r")  
  hsdirs = json.load(hsdirs_json)

  z_ones, z_fours = findDigestDistance(onion, suffix, digests, hsdirs)
  print("========== %s statistics =========" % onion)
  print("z_ones: "+str(z_ones))
  print("z_fours :"+str(z_fours))
 
  dns = findReverseDNS(onion, suffix, hsdirs)
  print("dns: "+str(dns))
  common_nick, common_or, common_dir, common_exits, var_band = findSimilarTraits(hsdirs)
  print("common_nick: "+str(common_nick))
  print("common_or: "+str(common_or))
  print("common_dir: "+str(common_dir))
  print("common_exits: "+str(common_exits))
  print("var_band: "+str(var_band))
  hsdirs_json.close()

test() 

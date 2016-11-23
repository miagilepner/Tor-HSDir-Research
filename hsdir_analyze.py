import calc_ids
import json
import socket 
from collections import Counter
import make_hashring
import calc_ids
import statistics

def difference(one, two):
  if one<two:
    return two-one
  return two-one

#this is ugly. i'll fix it later
def findDigestDistance(onion, suffix, hsdirs):
  hash_json = open("/home/mge/hashrings/%s.json" % suffix, "r")
  hashring = json.load(hash_json)
  diff_ones = []
  diff_fours = []
  hash_len = len(hashring)
  for i in range(hash_len):
    diff_one = difference(hashring[i], hashring[(i+4) % hash_len])
    diff_one = difference(hashring[i], hashring[(i+1) % hash_len])
    diff_ones.append(diff_one)
    diff_fours.append(diff_four)
  mean_one = statistics.mean(diff_ones)
  mean_four = statistics.mean(diff_fours)     
  div_one = statistics.stdev(diff_ones)
  div_four = statistics.stdev(diff_fours)

  #TODO
  digests = calc_ids.digestsByDate(onion, suffix)

  one_one = hsdirs[1]['fingerprint'] - digests[0]
  two_one = hsdirs[5]['fingerprint'] - digests[0]
  one_four = hsdirs[4]['fingerprint'] - digests[0]
  two_four = hsdirs[8]['fingerprint'] - digests[0] 
  z_ones = []
  z_fours = []
  z_ones.append((one_one-mean_one)/div_one)
  z_ones.append((one_two-mean_one)/div_one)
  z_fours.append((one_four-mean_four)/div_four)
  z_fours.append((two_four-mean_four)/div_four)
   
  close(hash_json)
  return z_ones, z_fours

def findReverseDNS(onion, suffix, hsdirs):
  domains = []
  for i,hsdir in hsdirs:
    if i == 4 or i == 8:
      continue
    domain = socket.gethostbyaddr(hsdir['address'])[0] 
    parts = domain.split(".")[-2:]
    domains.append(parts.join("."))
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
  for i,hsdir in hsdirs:
    if i == 4 or i == 8:
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
  var_band = variance(bandwidths)
  return common_nick, common_or, common_dir, common_exits, var_band

def findAge(suffix, hsdirs):

def run():
  onions = open("descriptor_list.txt", "r")
  for onion in onions:
    folder = make_hashring.stripOnion(onion)
    data = os.listdir("/home/mge/%s" % folder)
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
      z_ones, z_fours = findDigestDistance(onion, suffix, hsdirs) 

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

#returns a list of the 3 hsdirs closest to but larger than digest
def getDirs(digest, hsdirs_sorted, hsdirs_keys):
  dirlist = []
  hsdir_size = len(hsdirs_sorted)
  i=bisect.bisect_left(hsdirs_keys, base64.b32decode(digest,1))
  if i!=hsdir_size:
    if i+3 < hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[i+1])
      dirlist.append(hsdirs_sorted[i+2])
      dirlist.append(hsdirs_sorted[i+3])
    elif i+2 < hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[i+1])
      dirlist.append(hsdirs_sorted[i+2])
      dirlist.append(hsdirs_sorted[0])
    elif i+1 < hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[i+1])
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
    elif i<hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
      dirlist.append(hsdirs_sorted[2])
  else:
    if digest >= hsdirs_keys[hsdir_size-1]:
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
      dirlist.append(hsdirs_sorted[2])
      dirlist.append(hsdirs_sorted[3])
    elif digest == hsdirs_keys[hsdir_size-1]:
      dirlist.append(hsdirs_sorted[hsdir_size-1])
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
      dirlist.append(hsdirs_sorted[2])
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
  return dirlist

def createJSON(dirlist):
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
    json_data[i] = item_dict
  return json_data

#gets digests and calls analyzeHSDirs
def run(onion_address):
  months = 1 
  digestList = calc_ids.findDigests(onion_address, months)
  for dig in digestList:
    newdate = dig[0]
    if dig[0].hour == 23:
      newdate = dig[0] + datetime.timedelta(hours=1)
    monthNum = ""
    monthNum = str(newdate.month)
    if newdate.month < 10:
      monthNum = "0%s" % monthNum
    hr = newdate.hour
    dayNum = str(newdate.day)
    if newdate.day < 10:
      dayNum = "0%s" % dayNum
    tarName = "/home/mge/old_consensus/consensuses-%d-%s.tar.xz" % (newdate.year, monthNum)
    tarFileName = "consensuses-%d-%s/%s/%d-%s-%s-%d-00-00-consensus" % (newdate.year, monthNum, dayNum, newdate.year, monthNum, dayNum, hr) 
    with tarfile.open(tarName, mode='r:xz') as tf:
      f = tf.extractfile(tf.getmember(tarFileName))
      analyzeHSDirs(f, dig)
      f.close()
      tf.members = []
      return 
run("3g2upl4pq6kufc4m.onion")

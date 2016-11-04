#!/usr/bin/env python
from stem.descriptor import DocumentHandler
from stem.descriptor.reader import DescriptorReader
from stem import Flag
import os
import binascii 
import bisect 
import calc_ids
import datetime, calendar

#returns a list of the 3 hsdirs closest to but larger than digest
def getDirs(digest, hsdirs_sorted, hsdirs_keys):
  dirlist = []
  hsdir_size = len(hsdirs_sorted)
  i=bisect_left(hsdirs_keys, digest)
  if i!=hsdir_size:
    if i+2 < hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[i+1])
      dirlist.append(hsdirs_sorted[i+2])
    elif i+1 < hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[i+1])
      dirlist.append(hsdirs_sorted[0])
    elif i<hsdir_size:
      dirlist.append(hsdirs_sorted[i])
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
  else:
    if digest_one > hsdirs_keys[hsdir_size-1]:
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
      dirlist.append(hsdirs_sorted[2])
    elif digest_one == hsdirs_keys[hsdir_size-1]:
      dirlist.append(hsdirs_sorted[hsdir_size-1])
      dirlist.append(hsdirs_sorted[0])
      dirlist.append(hsdirs_sorted[1])
  return dirlist 

#analyzes HSDirs for a month at a time 
#finds 3 HSDirs for digest_one and 3 for digest_two
#outputs all details for these HSDirs
def analyzeHSDirs(fileList, digests):
  dirlist = []
  descriptors = DescriptorReader("../old_consensus/%s" % filename, document_handler=DocumentHandler.DOCUMENT)
  #descriptors = parse_file('../old_consensus/%s' % filename) 
  hsdirs = filter(lambda descriptor:Flag.HSDIR in descriptor.flags, descriptors)
  hsdirs_sorted = sorted(hsdirs, key=lambda descriptor:binascii.unhexlify(descriptor.digest),reverse=True)
  hsdirs_keys = [binascii.unhexlify(descriptor).digest for descriptor in hsdirs_sorted]
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

#digests should be calculated for a specific number of months
def run(onion_address):
  months = 1 
  digestList = calc_ids.findDigests(onion_address, months)
  fileList = []
  for dig in digestList:
    monthNum = ""
    monthNum = str(dig[0].month)
    if dig[0].month < 10:
      monthNum = "0%s" % monthNum
    fileName = "consenuses-%d-%s.tar.xz" % (dig[0].year, monthNum)
    if fileName not in fileList:
      fileList.append(fileName) 
  analyzeHSDirs(fileList, digestList) 

run("3g2upl4pq6kufc4m.onion")

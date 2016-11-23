from stem.descriptor import DocumentHandler
from stem.descriptor import parse_file
from stem.descriptor.reader import DescriptorReader
import os
import tarfile
import binascii
import json

def getHashRing(entry):
  cons = next(parse_file(entry, document_handler=DocumentHandler.DOCUMENT))
  descriptors = cons.routers.items()
  fingerprints = [desc[1].fingerprint for desc in descriptors]
  return fingerprints

def stripOnion(onion):
  new_onion = onion[3:]
  return new_onion[2:-3]

def openFiles():
  onions = open("descriptor_list.txt", "r")
  for onion in onions:
    folder = stripOnion(onion)
    data = os.listdir("/home/mge/%s" % folder)
    for datum in data:
      datum = datum.strip(".json")
      dates = datum.split("-")
      yr = dates[0]
      mon = dates[1]
      day = dates[2]
      hr = dates[3]
      if os.path.exists("/home/mge/hashrings/%s-%s-%s-%s" % (yr, mon, day, hr)):
        continue
      tarName = "/home/mge/old_consensus/consensuses-%s-%s.tar.xz" % (yr, mon)
      tarFileName = "consensuses-%s-%s/%s/%s-%s-%s-%s-00-00-consensus" % (yr, mon, day, yr, mon, day, hr)
      with tarfile.open(tarName, mode='r:xz') as tf:
        try:
          f = tf.extractfile(tf.getmember(tarFileName))
        except:
          print("FAILED: %s" % tarFileName)
          continue
        fingerprints = getHashRing(f)
        output = open("/home/mge/hashrings/%s-%s-%s-%s.json" % (yr, mon, day, hr), 'w')
        json.dump(fingerprints, output) 
        f.close()
        tf.members = []
  onions.close()
  return

openFiles()

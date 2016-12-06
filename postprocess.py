import make_hashrings
import os 
import json

def record_highest():

def vertical_similarity():

def horizontal_similarity():

def category_score()

def process():
  onions = open("descriptor_list.txt", "r")
  for oni in onions:
    onion = make_hashrings.stripOnion(oni)
    data = os.listdir("/home/mge/%s" % onion)
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
      hsdirs_json.close()

def group_by_category():
  categories_to_onions = {} 
  onions_to_categories = {} 
  onions = open("descriptor_categories.txt", "r")
  current_category = ""
  for oni in onions:
    if oni.startswith("=="):
      cat = oni.strip("==")
      current_category = cat
      categories_to_onions[current_category] = [] 
    else:    
      onion = make_hashrings.stripOnion(oni)
      categories_to_onions[current_category].append(onion)
      onions_to_categories[onion] = current_category 
  onions.close()
   

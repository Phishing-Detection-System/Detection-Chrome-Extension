import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests

# 12.Web traffic (Web_Traffic)
# def web_traffic(url):
#   try:
#     #Filling the whitespaces in the URL if any
#     url = urllib.parse.quote(url)
#     print(url)
#     rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
#         "REACH")['RANK']
#     rank = int(rank)
#   except TypeError:
#         return 1
#   if rank <100000:
#     return 1
#   else:
#     return 0
  
# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age


def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1

# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1





def extract(url,label):
   
   
   features = []
   dns = 0
   try:domain_name = whois.whois(urlparse(url).netloc)
   except:dns = 1
   features.append(dns)
#    features.append(web_traffic(url))
   features.append(1 if dns == 1 else domainAge(domain_name))
   features.append(1 if dns == 1 else domainEnd(domain_name))
   try:response = requests.get(url)
   except:response = ""
   features.append(iframe(response))
   features.append(mouseOver(response))
   features.append(rightClick(response))
   features.append(forwarding(response))
   return features



url = []
url.append('http://www.testingmcafeesites.com')
url.append('https://pypi.org/project/python-whois')
legit = []
for i in range(2):
    tempurl = url[i]
    legit.append(extract(tempurl,0))
print(legit)
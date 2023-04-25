# Load the required packages

import pandas as pd
import numpy as np
import sys
import re

from urllib.parse import urlparse,urlencode
from bs4 import BeautifulSoup
from datetime import datetime
import ipaddress
import whois
import urllib
import urllib.request
import tldextract

import pickle


class FeatureExtract:

# This class contains the methods that extract the required features
# Across the entire dataset, 0 indicates legitimate url and 1 indicates phishing url
# Legitimate - 0; Phishing - 1


    def __init__(self):
        pass

    
    def rank(self,url):

        # Method to check rank of the URL by connecting to the alexa rank API
        # Returns 0 if the rank is less than 100000 for the given URL else returns 1
        
        try:
            
            #Filling the whitespaces in the URL if any
            
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&url=" + url).read(), "xml").find(
                "REACH")['RANK']
            rank = int(rank)
        except TypeError:
            return 1
        if rank <100000:
            return 0
        else:
            return 1
        

    def isIP(self,url):
        
        # Method to check if an IP is found in the URL
        # Returns 1 if IP is found in the given URL else returns 0
        
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip
    

    def isValid(self,domain_name):
        
        # Method to check the validity of the URL domain
        # Returns 1 if age of the domain is less than 6 else returns 0
        
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


    def domain_reg_len(self,domain_name):
        
        # Method to check the expiration of the URL domain
        # Returns 1 if the domain has expired else returns 0
        
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


    def isat(self,url):
        
        # Method to check for '@' in the URL
        # Returns 1 if found else returns 0
        
        if "@" in url:
            return 1    
        else:
            return 0    


    def isRedirect(self,url):
        
        # Method to check for '//' in the URL
        # Returns 1 if found within length of 7 for the given URL or if 'http' is found else returns 0
        
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0


    def haveDash(self,url):
        
        # Method to check for '-' in the URL
        # Returns 1 if found else returns 0
        
        if '-' in urlparse(url).netloc:
            return 1            
        else:
            return 0   
    

    def no_sub_domain(self,url):
        
        # Method to check number of subdomains in the URL
        # Returns 0 if number of subdomains is 1 else returns 1

        url = str(url)
        url = url.replace("www.","")
        url = url.replace("."+tldextract.extract(url).suffix,"")
        count = url.count(".")
        if count==1:
            return 0
        else:
            return 1



    def httpDomain(self,url):
        
        # Method to check for 'https' in the URL
        # Returns 1 if found else returns 0

        domain = urlparse(url).netloc
        if 'http' in domain:
            return 1
        else:
            return 0


    def LongURL(self,url):
        
        # Method to checks the length of the URL
        # Returns 0 if the length is less than 54 else returns 1

        if len(url) < 54:
            return 0           
        else:
            return 1            


    def tinyURL(self,url):
        
        # Method to check if the URL belong to shortening services
        # Returns 1 if found else returns 0
        
        #listing shortening services
    
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return 0





class PredictURL(FeatureExtract):
    
    # This class inherits FeatureExtract class to access all its methods
    # The main classification of the URL is done via the methods of this class
    
    def __init__(self):
        pass
        
    
    def predict(self,url):
        
        # Method to call all the methods in the FeatureExtract class to 
        #get the features of the given URL and appends it to an np array
        # Returns the result of classification by calling the classify function
        
        feature = []
        dns = 0
        
        # URL is passed to whois API to fetch the domain name 
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
       
        #Domain based features (3)
        
        feature.append(self.rank(url))
        feature.append(1 if dns == 1 else self.isValid(domain_name))
        feature.append(1 if dns == 1 else self.domain_reg_len(domain_name))

        #Address bar based features (5)
    
        feature.append(self.isRedirect(url))
        feature.append(self.haveDash(url))
        feature.append(self.no_sub_domain(url))
        feature.append(self.LongURL(url))
        feature.append(self.tinyURL(url))
        
        return self.classify(np.array(feature).reshape((1,-1)))
        
    
    def __getstate__(self):

        # this method is called when you are
        # going to pickle the class, to know what to pickle
        
        state = self.__dict__.copy()
        
        # don't pickle the parameter fun. otherwise will raise 
        # AttributeError: Can't pickle local object 'Process.__init__.<locals>.<lambda>'
        
        return state
    
    
    def __setstate__(self, state):
        
        self.__dict__.update(state)

        
    def classify(self,features):
        
        #Method to classify the URL, given its features.
        #It loads the saved mode in the pickle file to perform the classification
        
        # Load the pickle file
        
        pick_file = open('phishing_classifier.pkl', 'rb') 
        Pickled_sample_Model = pickle.load(pick_file)
        pick_file.close()
    
        # Classify the URL features using the loaded pickle file
        
        result = Pickled_sample_Model.predict(features)
        if result == 0:
            return "Given website is a legitimate site"
        else:
            return "Given website is a phishing site"
    
# Main function

def main():

    pass

if __name__ == "__main__":
    main()

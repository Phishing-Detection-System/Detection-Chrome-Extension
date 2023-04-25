# A Comparision of Supervised Machine Learning Models to detect Phishing Websites

**Objective**

Ever since the emergence of the Internet, phishing, a fraudulent practice is always an area of concern. We have approached via machine learning to address this problem. Through this project, we comapre many supervised machine learning algorithms on an publicly available dataset that has equal number of phishing and legitimate URLs and have identified a model which effectively classifies if the given URL is a phishing site or not.

**Data Collection**

We acquired the data from Kaggle, a public data source. The dataset has 71677 unique URLs with some of the required features. It is a imbalanced dataset hence we balanced it with random sampling.

Data source : https://www.kaggle.com/aman9d/phishing-data

This base dataset is available in 'Main_dataset.csv' of this repository

**Feature Enginnering**

We extracted few of the domain based features and address bar features for the URLs in the base dataset. A decision tree was applied on this data to obtain the feature importance and the unecessary features were deleted from the dataset. This data is further split for training and testing.

Based on the document, 'Phishing Website Features.docx' in this repository, the values of each feature were converted to 0 for legitimate site and 1 for phishing site. The respective feature extraction process are in 'feature_exxtraction.py' file of this repository.

This new datastet is available in 'phishing_feature_engg.csv' of this repository

To understand the relationships and the correlation of the data, visualisations using Lux package in Python was done. These visualisations are available in 'Visualization_Lux_Phishing_Sites_Detection.ipynb' file of this repository.

**Model Development**

The supervised machine learning algorithms used for this analysis are
Logistic Regression
Naive Bayes Classifier
Support Vector Machines
Decision Tree Classifier
Random Forest Classifier
XGBoost Classifier
Neural Network

These models were trained and tested on the feature extracted dataset and evaluations were done to identify the model with high performance. XGBoost algorithm had a good accuracy and fast testing time compared to the other algorithms. Later a grid search was done on the XGBoost for hyper parameter tuning.

The entire code for this project is available in 'Detecting_phishing_websites.ipynb' file of this repository.

**Results**

After fine tuning, XGBoost classifer was chosen as the final model with an accuracy of 82.4%. This model was saved as the final model through pickle module of Python. This file is available as 'phishing_classifier.pkl' in this repository.

**Future Work**

The saved model can be extended to a browser extension or can be added as a plugin to the internet security providers in order to to warn the users to avoid the phishing sites by efficiently identifying them.

**Required Installations**

**Softwares**

Jupyter notebook, Python 3 and above

**Python packages**

sklearn, numpy, pandas, pickle

lux, seaborn, matplotlib, xgboost

BeautifulSoup, whois, urllib, tldextract


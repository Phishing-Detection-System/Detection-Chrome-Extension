from featureExtractor import PredictURL

from fastapi import FastAPI

import validators

classification = PredictURL()
app = FastAPI()

@app.get("/api")
def hello(url: str=""):
  if not validators.url(url):
    return {'msg':'Invalid URL'}
  ans = classification.predict(url)
  return {ans}
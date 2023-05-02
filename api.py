from featureExtractor import PredictURL

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import validators

classification = PredictURL()
app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api")
def hello(url: str=""):
  if not validators.url(url):
    return {'msg':'Invalid URL'}
  ans = classification.predict(url)
  return {ans}

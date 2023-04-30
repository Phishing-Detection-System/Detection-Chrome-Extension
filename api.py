from featureExtractor import PredictURL
classification = PredictURL()


from fastapi import FastAPI
app = FastAPI()

@app.get("/api")
def hello(url: str):
  ans = classification.predict(url)
  return {ans}
from fastapi import FastAPI


app = FastAPI()


@app.get("/")
def hello():
    return {"message": "Hello Atul this is AWS Connection new change"}

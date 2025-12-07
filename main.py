from fastapi import FastAPI


app = FastAPI()


@app.get("/")
def hello():
    return {"message": "This is the first change Atul Rawat ji"}

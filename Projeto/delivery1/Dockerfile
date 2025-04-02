FROM python:3.8-slim

WORKDIR /delivery1

COPY . /delivery1

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "-m", "api.app"]

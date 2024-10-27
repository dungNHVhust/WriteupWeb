FROM python:2.7-alpine

WORKDIR /app

RUN apk add --no-cache gcc g++ musl-dev linux-headers

COPY . /app/

RUN pip install --no-cache-dir -r requirements.txt


RUN chmod +x /app/app.py


RUN rm /usr/bin/wget && RANDOM_NAME=$(head /dev/urandom | tr -dc a-z0-9 | head -c 12) && \
    mv /app/flag.txt /app/$RANDOM_NAME


EXPOSE 8082


ENTRYPOINT ["python", "/app/app.py"]

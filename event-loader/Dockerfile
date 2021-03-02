# --- Base python on alpine ---
FROM python:alpine3.13 AS base

LABEL description="Event-Loader for Worload Security"
LABEL maintainer="markus_winkler@trendmicro.com"

# Create app directory
WORKDIR /app

# --- Dependencies ---
FROM base as dependencies

# Copy requirements.txt
COPY requirements.txt ./

# Install app dependencies
RUN apk add --update --no-cache --virtual .build-deps \
        g++ libxml2 libxml2-dev && \
    apk add libxslt-dev && \
    pip3 install --upgrade pip && \
    pip3 install -r /app/requirements.txt && \
    apk del .build-deps

# --- Copy files/build ---
FROM dependencies AS build
WORKDIR /app

# Copy files required for the app to run, see .dockerignore
COPY . .

# --- Release with alpine ---
FROM python:alpine3.13 AS release
WORKDIR /app

COPY --from=dependencies /app/requirements.txt ./
COPY --from=dependencies /root/.cache /root/.cache

RUN apk add libxslt-dev && \
    pip3 install -r /app/requirements.txt

COPY --from=build /app/ ./

# Tell the port number the container should expose
#EXPOSE 5000

# Run the application
CMD ["python3", "/app/event_loader.py"]

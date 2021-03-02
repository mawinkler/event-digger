#!/bin/bash

docker build -t mawinkler/event-loader:latest .
docker push mawinkler/event-loader:latest

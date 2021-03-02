#!/bin/bash

docker build -t mawinkler/event-digger:latest .
docker push mawinkler/event-digger:latest

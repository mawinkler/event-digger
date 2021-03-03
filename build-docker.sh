#!/bin/bash

# build the event-loader container
docker build -t mawinkler/event-loader:latest event-loader
docker push mawinkler/event-loader:latest

# build the event-digger container
docker build -t mawinkler/event-digger:latest event-digger
docker push mawinkler/event-digger:latest

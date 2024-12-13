#!/bin/bash

# Build the Docker image
docker build -t risk-assessment .

# Run the Docker container
docker run --rm risk-assessment

#!/bin/bash

PROJECT_ROOT=$(cd $(dirname $0) && pwd)
# If the directory contains /usr/local/bin, it means it was executed via symlink.
if [[ $PROJECT_ROOT == *"usr/local/bin"* ]]; then
    PROJECT_ROOT=$(dirname $(readlink $0))
fi

docker build -t gcc_container:1.0.0 $PROJECT_ROOT

docker run -it gcc_container:1.0.0 bash

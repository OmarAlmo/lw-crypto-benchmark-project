#!/bin/bash

PROJECT_ROOT=$(cd $(dirname $0) && pwd)
# If the directory contains /usr/local/bin, it means it was executed via symlink.
if [[ $PROJECT_ROOT == *"usr/local/bin"* ]]; then
    PROJECT_ROOT=$(dirname $(readlink $0))
fi

OP=$1
if [ $OP = "build" ]; then 
    docker run -it -v "$(pwd)"/data_file_set:/data_file_set gcc_container:1.0.0 bash
fi

docker build -t gcc_container:1.0.0 $PROJECT_ROOT

# docker run -it -v "$(pwd)"/data_file_set:/data_file_set gcc_container:1.0.0 bash
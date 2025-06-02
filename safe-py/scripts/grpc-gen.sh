#!/usr/bin/env bash

set -e
set -x

cd src
uv sync # need to run this to make sure mypy-protobuf is installed
python -m grpc_tools.protoc \
  -Isafe/stubs=../../proto \
  --python_out=. \
  --grpc_python_out=. \
  --mypy_out=. \
  ../../proto/safe.proto

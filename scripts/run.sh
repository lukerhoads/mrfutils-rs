#!/bin/bash

cargo build
RUST_LOG=info ./target/debug/mrfutils --dolt-dir="$1"
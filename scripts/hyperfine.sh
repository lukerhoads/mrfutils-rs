#!/bin/bash

cargo build 
hyperfine "./target/debug/mrfutils --dolt-dir=\"$1\""
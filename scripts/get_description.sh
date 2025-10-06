#!/bin/bash
grep description Cargo.toml | awk -F' = ' '{print $2}' | tr -d '"'
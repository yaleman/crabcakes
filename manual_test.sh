#!/bin/bash


./inner_test_pkill_instance.sh

./inner_test_main.sh  || echo "❌ Test failed ❌"

./inner_test_pkill_instance.sh
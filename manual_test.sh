#!/bin/bash


./scripts/integration/inner_test_pkill_instance.sh

./scripts/integration/inner_test_main.sh  || echo "❌ Test failed ❌"

./scripts/integration/inner_test_pkill_instance.sh
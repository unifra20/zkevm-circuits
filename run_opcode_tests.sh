#!/bin/bash

#cargo test -- --list --format=terse | grep evm::opcodes:: | rev | cut -c7- | rev | xargs -I {} cargo test --package bus-mapping --lib -- {} --exact --nocapture

cargo test -- --list --format=terse | grep evm_circuit::execution:: | rev | cut -c7- | rev | xargs -I {} cargo test --release --package zkevm-circuits --lib -- {} --exact --nocapture

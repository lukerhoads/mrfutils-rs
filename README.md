# `mrfutils-rs`

Rust port of `mrfutils`, a Python script for processing files for the [quest](https://www.dolthub.com/repositories/dolthub/quest) data bounty.

## Prerequisites
To run this, you must first install [Rust](https://www.rust-lang.org/tools/install). 
This runs on nightly, so then you must run 
```shell
rustup default nightly
```
to set the toolchain to nightly.

## Configuration

```
Usage: mrfutils [OPTIONS] --dolt-dir <DOLT_DIR>

Options:
      --input-file <INPUT_FILE>    [default: ./input.txt]
      --codes-file <CODES_FILE>    [default: ./codes.csv]
      --npi-file <NPI_FILE>        [default: ./npis.csv]
      --n-workers <N_WORKERS>      [default: 4]
      --offset-file <OFFSET_FILE>
      --line-pos <LINE_POS>
      --direction <DIRECTION>
      --dolt-dir <DOLT_DIR>
      --mock
  -p, --performance-graph
  -h, --help                       Print help information
```

To configure `mrfutils-rs`, you must configure the filter codes and NPIs.

Then, you need to set the `DOLT_DIR` environment variable or pass it directly. This represents the directory where your dolt repository is.

Do this by running
```shell
export DOLT_DIR=${DOLT_DIR_HERE}
```

Finally, you can run the program using the run script.
```shell
sh ./scripts/run.sh $DOLT_DIR
```

If you want to supply extra arguments, either build and run the binary or directly run it by doing
```shell
RUST_LOG=info cargo run -- {OPTIONS_HERE}
```
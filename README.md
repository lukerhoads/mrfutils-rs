# `mrfutils-rs`

Rust port of `mrfutils`, a Python script for processing files for the [quest](https://www.dolthub.com/repositories/dolthub/quest) data bounty.

## Configuration

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

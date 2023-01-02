// TODO:
// Another sub module binary that prepares the input file
// Preferably have a status bar

// Show file processing times, graph them based on logs
// Performance tracking - RAM, CPU, graphs - through logs? - thorugh --perf flag
// Structured logging - check out https://github.com/tokio-rs/tracing
// Takes NPI and code filters
// Graceful shutdown

// Architecture
// One thread iterates over the file using limited visibility for better efficiency
// A channel receives the file URLs, and Rayon triggers a function to process it

#![feature(slice_take)]
#![feature(string_remove_matches)]
#![feature(exit_status_error)]

mod utils;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use log::{info, warn};
use anyhow::Context;
use flate2::read::GzDecoder;
use rev_buf_reader::RevBufReader;
use tempfile::Builder;
use urlparse::urlparse;
use uuid::Uuid;
use rayon::prelude::*;
use clap::Parser;

use utils::*;

struct FileProcessor {
    dolt_dir: String,
    code_whitelist: Vec<String>,
    npi_whitelist: Vec<String>,
}

impl FileProcessor {
    pub fn new(dolt_dir: String, code_loc: &str, npi_loc: &str) -> anyhow::Result<Self> {
        let mut rdr = csv::Reader::from_path(code_loc).context("Unable to open code file")?;
        let mut codes = vec![];
        for result in rdr.records() {
            let record = result?;
            codes.push(record.as_slice().to_string());
        }

        let mut rdr = csv::Reader::from_path(npi_loc).context("Unable to open npi file")?;
        let mut npis = vec![];
        for result in rdr.records() {
            let record = result?;
            npis.push(record.as_slice().to_string());
        }

        Ok(FileProcessor { 
            dolt_dir: dolt_dir,
            code_whitelist: codes, 
            npi_whitelist: npis,
        })
    }

    // TODO: filtering files (codes.csv and the other one)

    // This function will process an in-network file, and submit the entries
    // to the interface implementation that handles them.
    pub fn process_in_network_file(&self, url: String) -> anyhow::Result<()> {
        // Create temporary directory
        let file_uuid = Uuid::new_v4();
        let tmp_dir = Builder::new()
            .prefix(&file_uuid.to_string())
            .tempdir()
            .context("Unable to create temporary directory.")?;

        // Parse url for file metadata
        let url_parsed = urlparse(url.clone());
        let path = Path::new(&url_parsed.path);
        let extension = path
            .extension()
            .context("Unable to get file extension")?
            .to_str()
            .unwrap_or("");
        let file_name = path
            .file_name()
            .context("Unable to get file name")?
            .to_str()
            .unwrap_or("");

        // TODO: think about chunks, optimization of download
        // Download the file and extract it if it is compressed
        let file_name_path = tmp_dir.path().join(file_name);
        let mut file =
            File::create(file_name_path).context("Unable to create target file in temp directory.")?;
        let mut response = reqwest::blocking::get(url.clone()).context("Unable to get target file.")?;
        if extension.contains("json.gz") {
            let gz = GzDecoder::new(response);
            let mut reader = BufReader::new(gz);
            io::copy(&mut reader, &mut file).context("Unable to copy decompressed target file")?;
        } else if extension.contains("json") {
            response
                .copy_to(&mut file)
                .context("Could not copy response to file")?;
        } else {
            return Err(anyhow::Error::msg("Unrecognized file extension."))
        }

        let file_name_path = tmp_dir.path().join(file_name);
        let newfile = File::open(file_name_path).expect("Unable to open target file");
        let value: ijson::IValue =
            serde_json::de::from_reader(newfile).expect("Unable to deserialize target file.");

        // Filename hash, filename, and url extraction
        let file_hash = make_hash(format!("{{\"filename\": \"{}\"}}", file_name));
        let dolt_sql_command = format!(
            "insert into files values ('{}', '{}', '{}')",
            file_hash, file_name, url
        );
        execute_command(&self.dolt_dir, &dolt_sql_command)?;

        // Plans
        let keys = vec![
            "last_updated_on",
            "reporting_entity_name",
            "reporting_entity_type",
            "version",
        ];
        let blob_obj = value.as_object().unwrap();
        let mut vals: BTreeMap<&str, String> = BTreeMap::new();
        for (_, key) in keys.iter().enumerate() {
            let blopaa = blob_obj.get(*key);
            if let Some(bla) = blopaa {
                vals.insert(*key, bla.as_string().unwrap().to_string());
            }
        }

        let opt_string_keys = vec![
            "plan_name",
            "plan_id_type",
            "plan_id",
            "plan_market_type"
        ];
        for (_, key) in opt_string_keys.iter().enumerate() {
            let val = extract_string_val(&value, key);
            if let Some(vaaa) = val {
                vals.insert(key, vaaa);
            }
        }

        let null_string = "NULL".to_string();
        let plan_hash = make_hash(common_json(&vals));
        let dolt_sql_command = format!(
            "insert into plans values ('{}', '{}', '{}', {}, {}, {}, {}, '{}', '{}')",
            plan_hash, 
            vals.get("reporting_entity_name").unwrap_or(&null_string), 
            vals.get("reporting_entity_type").unwrap_or(&null_string),
            surround(vals.get("plan_name")),
            surround(vals.get("plan_id")),
            surround(vals.get("plan_id_type")),
            surround(vals.get("plan_market_type")),
            vals.get("last_updated_on").unwrap_or(&null_string),
            vals.get("version").unwrap_or(&null_string),
        );
        execute_command(&self.dolt_dir, &dolt_sql_command)?;

        // Plans files
        let dolt_sql_command = format!(
            "insert into plans_files values ({}, {})",
            plan_hash,
            file_hash,
        );
        execute_command(&self.dolt_dir, &dolt_sql_command)?;

        // In network
        let in_network = blob_obj.get("in_network")
            .unwrap()
            .as_array()
            .unwrap();

        // this is where heavy batch optimizations could be made, definitely have vecs that fill up with data
        // and batch insert
        // either fork this into a new thread and wait for new values with a channel
        in_network.par_iter().map(|inobj| -> anyhow::Result<()> {
            // Billing codes
            let keys = vec![
                "billing_code",
                "billing_code_type",
                "billing_code_type_version",
            ];
            let mut vals: BTreeMap<&str, String> = BTreeMap::new();
            for (_, key) in keys.iter().enumerate() {
                let val = extract_string_val(inobj, key);
                if let None = val {
                    let err_str = format!("Required key null: {}", key);
                    return Err(anyhow::Error::msg(err_str))
                }
                vals.insert(key, val.unwrap());
            }
            let code_hash = make_hash(common_json(&vals));
            let dolt_sql_command = format!(
                "insert into codes values ('{}', '{}', '{}', '{}')",
                code_hash, 
                vals.get("billing_code_type_version").unwrap_or(&"NULL".to_string()),
                vals.get("billing_code").unwrap_or(&"NULL".to_string()),
                vals.get("billing_code_type").unwrap_or(&"NULL".to_string()), 
            );
            execute_command(&self.dolt_dir, &dolt_sql_command)?;

            let negotiated_rates = inobj.get("negotiated_rates")
                .unwrap()
                .as_array()
                .unwrap();
            negotiated_rates.into_iter().map(|nrobj| -> anyhow::Result<()> {
                let prices = nrobj.get("negotiated_prices")
                    .unwrap()
                    .as_array()
                    .unwrap();

                let mut price_values: Vec<(String, String, String, String, String, String, String, String)> = vec![];
                prices.into_iter().map(|pobj| -> anyhow::Result<()> {
                    let req_keys = vec![
                        "billing_class",
                        "expiration_date",
                        "negotiated_type",
                    ];

                    let mut pvals: BTreeMap<&str, String> = BTreeMap::new();
                    for (_, key) in req_keys.iter().enumerate() {
                        let val = extract_string_val(pobj, key);
                        if let None = val {
                            let err_str = format!("Required key null: {}", key);
                            return Err(anyhow::Error::msg(err_str))
                        }
                        pvals.insert(key, val.unwrap());
                    }

                    let opt_string_keys = vec![
                        "additional_information",
                    ];
                    for (_, key) in opt_string_keys.iter().enumerate() {
                        let val = extract_string_val(pobj, key);
                        if let Some(vaaa) = val {
                            pvals.insert(key, vaaa);
                        }
                    }

                    let number_keys = vec![
                        "negotiated_rate"
                    ];
                    for (_, key) in number_keys.iter().enumerate() {
                        let val = extract_number_val(pobj, key);
                        if let Some(vaaa) = val {
                            pvals.insert(key, vaaa);
                        }
                    }

                    // Both optional arrays, insert as serialized values
                    let optional_keys = vec![
                        "service_code",
                        "billing_code_modifier",
                    ];

                    for (_, key) in optional_keys.iter().enumerate() {
                        let kjj = pobj.get(*key);
                        if let Some(vjj) = kjj {
                            let arr_val = vjj.as_array().unwrap();
                            let json_val = common_json(arr_val);
                            pvals.insert(key, json_val);
                        }
                    }

                    let price_hash = make_hash(common_json(&pvals));
                    price_values.push((
                        price_hash,
                        pvals.get("billing_class").unwrap_or(&null_string).to_string(),
                        pvals.get("negotiated_type").unwrap_or(&null_string).to_string(),
                        surround(pvals.get("service_code")),
                        pvals.get("expiration_date").unwrap_or(&null_string).to_string(),
                        surround(pvals.get("additional_information")),
                        surround(pvals.get("billing_code_modifier")),
                        pvals.get("negotiated_rate").unwrap_or(&null_string).to_string(),
                    ));

                    Ok(())
                }).collect::<anyhow::Result<()>>()?;

                if price_values.len() > 0 {
                    let price_sql_values: Vec<String> = price_values.iter().map(|price| {
                        format!("('{}', '{}', '{}', '{}', '{}', {}, '{}', {}, {}, '{}')", 
                            file_hash,
                            code_hash,
                            price.0,
                            price.1,
                            price.2,
                            price.3,
                            price.4,
                            price.5,
                            price.6,
                            price.7,
                        )
                    }).collect();
                    let dolt_sql_command = format!("insert into prices values {}", price_sql_values.join(", "));
                    execute_command(&self.dolt_dir, &dolt_sql_command)?;
                }

                let mut pg_values: Vec<(String, String, String, String)> = vec![];
                if let Some(pgblah) = nrobj.get("provider_groups") {
                    if let Some(pgblahs) = pgblah.as_array() {
                        if pgblahs.len() > 0 {
                            pgblahs.into_iter().for_each(|pg| {
                                let tin_obj = pg.as_object().unwrap().get("tin").unwrap();
                                let tin_type = tin_obj.get("type").unwrap().as_string().unwrap().to_string();
                                let tin_value = tin_obj.get("value").unwrap().as_string().unwrap().to_string();
                                let npi_nums = common_json(pg.get("npi").unwrap().as_array().unwrap());
                                let mut pg_map = BTreeMap::new();
                                pg_map.insert("npi_numbers", npi_nums.as_str());
                                pg_map.insert("tin_type", tin_type.as_str());
                                pg_map.insert("tin_value", tin_value.as_str());
                                let hash = make_hash(common_json(&pg_map));
                                pg_values.push((
                                    hash, 
                                    tin_type,
                                    tin_value,
                                    npi_nums
                                ));
                            });
                
                            let provider_groups_sql_values: Vec<String> = pg_values.iter().map(|pg| 
                                format!("('{}', '{}', '{}', '{}')", pg.0, pg.1, pg.2, pg.3)
                            ).collect();
                            let dolt_sql_command = format!("insert into provider_groups values {}", provider_groups_sql_values.join(", "));
                            execute_command(&self.dolt_dir, &dolt_sql_command)?;
                        }
                    }
                }

                let mut price_pg_rows: Vec<(&str, &str)> = vec![];
                price_values.iter().for_each(|(pv_hash, _, _, _, _, _, _, _)| {
                    pg_values.iter().for_each(|(pg_hash, _, _, _)| {
                        price_pg_rows.push((pg_hash.as_str(), pv_hash.as_str()))
                    });
                });
                if price_pg_rows.len() > 0 {
                    let price_pg_rows_values: Vec<String> = price_pg_rows.iter().map(|pg| 
                        format!("('{}', '{}')", pg.0, pg.1)
                    ).collect();
                    let dolt_sql_command = format!("insert ignore into prices_provider_groups values {}", price_pg_rows_values.join(", "));
                    execute_command(&self.dolt_dir, &dolt_sql_command)?;
                }

                Ok(())
            }).collect::<anyhow::Result<()>>()?;

            Ok(())
        }).collect::<anyhow::Result<()>>()?;

        tmp_dir
            .close()
            .expect("Unable to close temporary directory.");
        Ok(())
    }
}

fn compute_offset(input_file: &str, position: Position) -> usize {
    match position {
        Position::Middle(line) => {
            let init_grep = Command::new("grep")
                .args(["-b", "-n", "", input_file])
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to launch first grep command");
            let final_grep = Command::new("grep")
                .arg(format!("^{}:", line))
                .stdin(
                    init_grep
                        .stdout
                        .expect("Unable to get stdout from previous grep command."),
                )
                .output()
                .expect("Failed to launch second grep command");
            String::from_utf8_lossy(&final_grep.stdout)
                .into_owned()
                .split(":")
                .nth(1)
                .expect("Unable to access offset element of extraction result.")
                .parse()
                .expect("Unable to parse resulting position.")
        }
        _ => 0,
    }
}

// Position stores the cursor location as a byte offset
#[derive(Debug, Clone, Copy)]
enum Position {
    Start,
    Middle(usize),
    End,
}

// Direction indicates whether to parse the file moving up or down
#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Backward,
}

#[derive(Parser, Default, Debug)]
#[clap(author="Luke Rhoads", about="Rust port of MRFUtils")]
struct Args {
    #[clap(long)]
    offset_file: Option<String>,

    #[clap(long, default_value = "./input.txt")]
    input_file: String,

    #[clap(long, default_value = "./codes.csv")]
    codes_file: String,

    #[clap(long, default_value = "./npis.csv")]
    npi_file: String,

    #[clap(long)]
    line_pos: Option<String>,

    #[clap(long)]
    direction: Option<String>,

    #[clap(long)]
    dolt_dir: String
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let default_offset_file = ".offset";
    let npi_file = args.npi_file;
    let codes_file = args.codes_file;
    let offset_file_location = args.offset_file;
    let input_file_location = &args.input_file;
    let direction = if let Some(dir) = args.direction {
        if dir.contains("backward") {
            Direction::Backward
        } else {
            Direction::Forward
        }
    } else {
        Direction::Forward
    };
    let line_pos = if let Some(pos) = args.line_pos {
        if let Ok(num) = pos.parse::<usize>() {
            Position::Middle(num)
        } else if pos == "end" {
            Position::End 
        } else {
            Position::Start 
        }
    } else {
        Position::Start
    };
    let mut max_line_pos: Option<usize> = None;

    let input = File::open(input_file_location)?;
    let buf = BufReader::new(input);

    let total_lines = buf.lines().count();
    let line_pos_number = match line_pos {
        Position::Start => 0,
        Position::Middle(n) => n,
        Position::End => total_lines,
    };
    let line_pos = match line_pos {
        Position::Start => Position::Start,
        Position::Middle(num) => {
            if num == total_lines {
                Position::End
            } else if num == 0 {
                Position::Start
            } else {
                Position::Middle(num)
            }
        }
        Position::End => Position::End,
    };
    if matches!(direction, Direction::Backward) && matches!(line_pos, Position::Start) {
        panic!("Unable to go backwards from start position.");
    } else if matches!(direction, Direction::Forward) && matches!(line_pos, Position::End) {
        panic!("Unable to go forwards from end position.");
    } else if max_line_pos.is_some() {
        if matches!(direction, Direction::Forward) && max_line_pos.unwrap() < line_pos_number {
            panic!("Cannot have a max line position less than the current line position when the direction is forward.");
        } else if matches!(direction, Direction::Backward)
            && max_line_pos.unwrap() > line_pos_number
        {
            panic!("Cannot have a max line position greater than the current line position when the direction is backward.");
        } if max_line_pos.unwrap() > 0 {
            max_line_pos = Some(total_lines);
        }
    }

    let offset_loc = offset_file_location.unwrap_or(default_offset_file.to_string());
    let byte_offset: Option<usize> = {
        info!("Attempting to recover saved cursor location...");
        if let Ok(file) = File::open(offset_loc) {
            let mut reader = BufReader::new(file);
            let mut offset_string = String::new();
            reader
                .read_line(&mut offset_string)
                .context("Unable to read line from recovery file.")?;
            if let Ok(res) = offset_string.parse() {
                info!("{}", "Successfully discovered saved cursor location.");
                Some(res)
            } else {
                None
            }
        } else {
            None
        }
    };

    let byte_offset = byte_offset.unwrap_or_else(|| {
        info!("Computing offset...");
        let new_line_pos = if let Position::Middle(num) = line_pos {
            if matches!(direction, Direction::Backward) {
                Position::Middle(num + 1)
            } else {
                Position::Middle(num)
            }
        } else {
            line_pos
        };
        compute_offset(input_file_location, new_line_pos)
    });

    let mut input = File::open(input_file_location)?;
    input
        .seek(match line_pos {
            Position::Start => SeekFrom::Start(0),
            Position::Middle(_) => SeekFrom::Start(byte_offset as u64),
            Position::End => SeekFrom::End(0),
        })
        .expect("Unable to seek position in buffer.");
    let mut offset_buf: Box<dyn BufRead> = match direction {
        Direction::Forward => Box::new(BufReader::new(input)),
        Direction::Backward => Box::new(RevBufReader::new(input)),
    };

    let mut curr_line = match line_pos {
        Position::Start => 1,
        Position::Middle(line) => line,
        Position::End => total_lines,
    };

    let processor = FileProcessor::new(args.dolt_dir, &codes_file, &npi_file)?;
    loop {
        if curr_line == 0 || (max_line_pos.is_some() && max_line_pos.unwrap() == curr_line) {
            break;
        }
        let url = {
            let mut line = String::new();
            offset_buf
                .as_mut()
                .read_line(&mut line)
                .context("Unable to read until next newline")?;
            line
        };
        
        let start = Instant::now();
        if let Err(e) = processor.process_in_network_file(url.clone()) {
            info!("{}", e.to_string());
            continue;
        };
        let duration = start.elapsed();
        info!("Processed {} in {:?}s", url, duration);

        if curr_line < total_lines && matches!(direction, Direction::Forward) {
            curr_line += 1;
        } else if curr_line > 0 && matches!(direction, Direction::Backward) {
            curr_line -= 1;
        } else {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        assert_eq!(
            "538167972721089466",
            make_hash(format!("{{\"filename\": \"hello\"}}"))
        );

        let mut testmap = BTreeMap::new();
        testmap.insert("filename", "hello");
        assert_eq!(
            "538167972721089466",
            make_hash(common_json(&testmap))
        )
    }
}

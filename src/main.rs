// TODO:
// Another sub module binary that prepares the input file
// Preferably have a status bar

// Show file processing times, graph them based on logs
// Performance tracking - RAM, CPU, graphs - through logs? - thorugh --perf flag
// Structured logging - check out https://github.com/tokio-rs/tracing
// Takes NPI and code filters
// Graceful shutdown
// Config file

// Architecture
// One thread iterates over the file using limited visibility for better efficiency
// A channel receives the file URLs, and Rayon triggers a function to process it

#![feature(slice_take)]
#![feature(string_remove_matches)]
#![feature(exit_status_error)]

mod utils;

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::Context;
use clap::Parser;
use flate2::read::GzDecoder;
use ijson::{IArray, IObject, IValue};
use log::info;
use rayon::prelude::*;
use rev_buf_reader::RevBufReader;
use tempfile::{Builder, TempDir};
use urlparse::urlparse;
use uuid::Uuid;

use utils::*;

struct FileProcessor {
    executor: CommandExecutor,
    code_whitelist: Option<Vec<String>>,
    npi_whitelist: Option<Vec<String>>,
}

impl FileProcessor {
    pub fn new(
        dolt_dir: String,
        mock: bool,
        code_loc: &str,
        npi_loc: &str,
    ) -> Self {
        let rdr = csv::Reader::from_path(code_loc).ok();
        let codes = if let Some(mut rd) = rdr {
            let mut codes = vec![];
            for result in rd.records() {
                let record = result.unwrap();
                codes.push(record.as_slice().to_string());
            }
            if codes.len() > 0 { Some(codes) } else { None }
        } else {
            None
        };

        let rdr = csv::Reader::from_path(npi_loc).ok();
        let npis = if let Some(mut rd) = rdr {
            let mut npis = vec![];
            for result in rd.records() {
                let record = result.unwrap();
                npis.push(record.as_slice().to_string());
            }
            if npis.len() > 0 { Some(npis) } else { None }
        } else {
            None 
        };

        FileProcessor {
            executor: CommandExecutor::new(dolt_dir, mock),
            code_whitelist: codes,
            npi_whitelist: npis,
        }
    }

    fn download(&self, url: &str) -> anyhow::Result<(TempDir, String)> {
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
        let mut file = File::create(file_name_path)
            .context("Unable to create target file in temp directory.")?;
        let mut response =
            reqwest::blocking::get(url.clone()).context("Unable to get target file.")?;
        if !response.status().is_success() {
            return Err(anyhow::Error::msg("Bad response from server."));
        }
        if extension.contains("json.gz") {
            let gz = GzDecoder::new(response);
            let mut reader = BufReader::new(gz);
            io::copy(&mut reader, &mut file).context("Unable to copy decompressed target file")?;
        } else if extension.contains("json") {
            response
                .copy_to(&mut file)
                .context("Could not copy response to file")?;
        } else {
            return Err(anyhow::Error::msg("Unrecognized file extension."));
        }

        Ok((tmp_dir, file_name.to_string()))
    }

    // This function will process an in-network file, and submit the entries
    pub fn process_in_network_file(&self, url: String) -> anyhow::Result<()> {
        let (tmp_dir, file_name) = self.download(url.as_str())?;

        let file_name_path = tmp_dir.path().join(file_name.as_str());
        let newfile = File::open(file_name_path).expect("Unable to open target file");
        let value: ijson::IValue =
            serde_json::de::from_reader(newfile).expect("Unable to deserialize target file.");

        // Filename hash, filename, and url extraction
        let file_hash = make_hash(format!("{{\"filename\": \"{}\"}}", file_name.as_str()));
        let dolt_sql_command = format!(
            "insert into files values ('{}', '{}', '{}')",
            file_hash,
            file_name,
            url.as_str()
        );
        self.executor.execute_command(&dolt_sql_command)?;

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

        let opt_string_keys = vec!["plan_name", "plan_id_type", "plan_id", "plan_market_type"];
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
        self.executor.execute_command(&dolt_sql_command)?;

        // Provider references
        let provider_references = blob_obj.get("provider_references");
        let pr_map = if let Some(pr) = provider_references {
            let prs = pr
                .as_array()
                .context("Unable to unwrap provider reference array")?;
            Some(
                self.process_provider_references(prs)
                    .context("Unable to process provider references"),
            )
        } else {
            None
        };

        // Plans files
        let dolt_sql_command = format!(
            "insert into plans_files values ({}, {})",
            plan_hash, file_hash,
        );
        self.executor.execute_command(&dolt_sql_command)?;

        // In network
        let in_network = blob_obj.get("in_network").unwrap().as_array().unwrap();

        // this is where heavy batch optimizations could be made, definitely have vecs that fill up with data
        // and batch insert
        // either fork this into a new thread and wait for new values with a channel
        in_network
            .par_iter()
            .map(|inobj| -> anyhow::Result<()> {
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
                        return Err(anyhow::Error::msg(err_str));
                    }
                    vals.insert(key, val.unwrap());
                }

                // Skip items that are not in the codes list
                if let Some(code_filter) = &self.code_whitelist {
                    let cmpstr = format!(
                        "{}{}",
                        vals.get("billing_code_type").unwrap(),
                        vals.get("billing_code").unwrap()
                    );
                    if !code_filter.contains(&cmpstr) {
                        return Ok(())
                    }
                }

                let code_hash = make_hash(common_json(&vals));
                let dolt_sql_command = format!(
                    "insert into codes values ('{}', '{}', '{}', '{}')",
                    code_hash,
                    vals.get("billing_code_type_version")
                        .unwrap_or(&"NULL".to_string()),
                    vals.get("billing_code").unwrap_or(&"NULL".to_string()),
                    vals.get("billing_code_type").unwrap_or(&"NULL".to_string()),
                );
                self.executor.execute_command(&dolt_sql_command)?;

                let negotiated_rates = inobj.get("negotiated_rates").unwrap().as_array().unwrap();
                negotiated_rates
                    .into_iter()
                    .map(|nrobj| -> anyhow::Result<()> {
                        // Skip rates that are meant to be filtered out
                        let mut pg_values: Vec<(String, String, String, String)> = vec![];
                        let mut pgs = IArray::new();
                        if let Some(pgblah) = nrobj.get("provider_groups") {
                            if let Some(pgblahs) = pgblah.as_array() {
                                for pgblaa in pgblahs.iter() {
                                    pgs.push(pgblaa.clone())
                                }
                            }
                        }

                        // Add provider_references that were stored earlier
                        if let Some(prblah) = nrobj.get("provider_references") {
                            if let Some(prmap) = &pr_map {
                                if let Ok(map) = prmap {
                                    let prrefs = prblah.as_array().unwrap();
                                    prrefs.into_iter().for_each(|prref| {
                                        let key = prref.as_number().unwrap().to_usize().unwrap();
                                        if let Some(pg) = map.get(&key) {
                                            for ipg in pg.as_array().unwrap().iter() {
                                                pgs.push(ipg.clone());

                                            }
                                        }
                                    })
                                }
                            }
                        }

                        let pgs: Vec<IValue> = pgs.into_iter().map(|pg| {
                            // Map to pg with invalid npis stripped 
                            let npis = pg.get("npi").unwrap().as_array().unwrap();
                            let new_npis = IArray::from_iter(npis.into_iter().filter(|npi| {
                                if let Some(whitelist) = &self.npi_whitelist {
                                    whitelist.contains(&npi.as_number().unwrap().to_usize().unwrap().to_string())
                                } else {
                                    true
                                }
                            }).map(|i| i.clone()));
                            if new_npis.len() == 0 {
                                return None
                            };
                            let mut cloned_pg = pg.as_object().unwrap().clone();
                            cloned_pg.remove("npi");
                            let mut newp = cloned_pg.clone();
                            newp.insert("npi", new_npis);
                            Some(IValue::from(newp.clone()))
                        }).flatten().collect();

                        if pgs.len() > 0 {
                            pgs.into_iter().for_each(|pg| {
                                let pg = pg.as_object().unwrap();
                                let tin_obj = pg.get("tin").unwrap();
                                let tin_type = tin_obj
                                    .get("type")
                                    .unwrap()
                                    .as_string()
                                    .unwrap()
                                    .to_string();
                                let tin_value = tin_obj
                                    .get("value")
                                    .unwrap()
                                    .as_string()
                                    .unwrap()
                                    .to_string();
                                let npi_nums =
                                    common_json(pg.get("npi").unwrap().as_array().unwrap());
                                let mut pg_map = BTreeMap::new();
                                pg_map.insert("npi_numbers", npi_nums.as_str());
                                pg_map.insert("tin_type", tin_type.as_str());
                                pg_map.insert("tin_value", tin_value.as_str());
                                let hash = make_hash(common_json(&pg_map));
                                pg_values.push((hash, tin_type, tin_value, npi_nums));
                            });

                            let provider_groups_sql_values: Vec<String> = pg_values
                                .iter()
                                .map(|pg| {
                                    format!(
                                        "('{}', '{}', '{}', '{}')",
                                        pg.0, pg.1, pg.2, pg.3
                                    )
                                })
                                .collect();
                            let dolt_sql_command = format!(
                                "insert into provider_groups values {}",
                                provider_groups_sql_values.join(", ")
                            );
                            self.executor.execute_command(&dolt_sql_command)?;
                        } else {
                            return Ok(())
                        }

                        let prices = nrobj.get("negotiated_prices").unwrap().as_array().unwrap();
                        let mut price_values: Vec<(
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                            String,
                        )> = vec![];
                        prices
                            .into_iter()
                            .map(|pobj| -> anyhow::Result<()> {
                                let req_keys =
                                    vec!["billing_class", "expiration_date", "negotiated_type"];

                                let mut pvals: BTreeMap<&str, String> = BTreeMap::new();
                                for (_, key) in req_keys.iter().enumerate() {
                                    let val = extract_string_val(pobj, key);
                                    if let None = val {
                                        let err_str = format!("Required key null: {}", key);
                                        return Err(anyhow::Error::msg(err_str));
                                    }
                                    pvals.insert(key, val.unwrap());
                                }

                                let opt_string_keys = vec!["additional_information"];
                                for (_, key) in opt_string_keys.iter().enumerate() {
                                    let val = extract_string_val(pobj, key);
                                    if let Some(vaaa) = val {
                                        pvals.insert(key, vaaa);
                                    }
                                }

                                let number_keys = vec!["negotiated_rate"];
                                for (_, key) in number_keys.iter().enumerate() {
                                    let val = extract_number_val(pobj, key);
                                    if let Some(vaaa) = val {
                                        pvals.insert(key, vaaa);
                                    }
                                }

                                // Both optional arrays, insert as serialized values
                                let optional_keys = vec!["service_code", "billing_code_modifier"];

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
                                    pvals
                                        .get("billing_class")
                                        .unwrap_or(&null_string)
                                        .to_string(),
                                    pvals
                                        .get("negotiated_type")
                                        .unwrap_or(&null_string)
                                        .to_string(),
                                    surround(pvals.get("service_code")),
                                    pvals
                                        .get("expiration_date")
                                        .unwrap_or(&null_string)
                                        .to_string(),
                                    surround(pvals.get("additional_information")),
                                    surround(pvals.get("billing_code_modifier")),
                                    pvals
                                        .get("negotiated_rate")
                                        .unwrap_or(&null_string)
                                        .to_string(),
                                ));

                                Ok(())
                            })
                            .collect::<anyhow::Result<()>>()?;

                        if price_values.len() > 0 {
                            let price_sql_values: Vec<String> = price_values
                                .iter()
                                .map(|price| {
                                    format!(
                                        "('{}', '{}', '{}', '{}', '{}', {}, '{}', {}, {}, '{}')",
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
                                })
                                .collect();
                            let dolt_sql_command = format!(
                                "insert into prices values {}",
                                price_sql_values.join(", ")
                            );
                            self.executor.execute_command(&dolt_sql_command)?;
                        }

                        let mut price_pg_rows: Vec<(&str, &str)> = vec![];
                        price_values
                            .iter()
                            .for_each(|(pv_hash, _, _, _, _, _, _, _)| {
                                pg_values.iter().for_each(|(pg_hash, _, _, _)| {
                                    price_pg_rows.push((pg_hash.as_str(), pv_hash.as_str()))
                                });
                            });
                        if price_pg_rows.len() > 0 {
                            let price_pg_rows_values: Vec<String> = price_pg_rows
                                .iter()
                                .map(|pg| format!("('{}', '{}')", pg.0, pg.1))
                                .collect();
                            let dolt_sql_command = format!(
                                "insert ignore into prices_provider_groups values {}",
                                price_pg_rows_values.join(", ")
                            );
                            self.executor.execute_command(&dolt_sql_command)?;
                        }

                        Ok(())
                    })
                    .collect::<anyhow::Result<()>>()?;

                Ok(())
            })
            .collect::<anyhow::Result<()>>()?;

        tmp_dir
            .close()
            .context("Unable to close temporary directory.")?;
        Ok(())
    }

    fn process_provider_references(&self, refs: &IArray) -> anyhow::Result<HashMap<usize, IValue>> {
        let mut pr_map: HashMap<usize, IValue> = HashMap::new();
        refs.into_iter()
            .map(|pr| {
                let mut unfetched = vec![];
                if let Some(loc) = pr.get("location") {
                    unfetched.push(loc.as_string().unwrap());
                }

                let mut provider_groups = vec![];
                let provider_group_id = pr
                    .get("provider_group_id")
                    .unwrap()
                    .as_number()
                    .unwrap()
                    .to_usize()
                    .unwrap();

                if unfetched.len() > 0 {
                    for unfetch in unfetched.into_iter() {
                        info!("Downloading remote file {}", unfetch.as_str());
                        let (tmp_dir, file_name) = self.download(unfetch.as_str())?;
                        let file_name_path = tmp_dir.path().join(file_name.as_str());
                        let newfile = File::open(file_name_path).expect("Unable to open provider file");
                        let value: ijson::IValue = serde_json::de::from_reader(newfile)
                            .expect("Unable to deserialize provider file.");
                        let mut pg_fetched = self.process_provider_groups(&value);
                        provider_groups.append(&mut pg_fetched);
                        tmp_dir
                            .close()
                            .context("Unable to close temporary directory.")?;
                    }
                } else {
                    provider_groups.append(&mut self.process_provider_groups(pr));
                }
                
                pr_map.insert(provider_group_id, IValue::from(provider_groups));
                Ok(())
            })
            .collect::<anyhow::Result<()>>()?;
        Ok(pr_map)
    }

    fn process_provider_groups(&self, obj: &IValue) -> Vec<IObject> {
        if let Some(pg) = obj.get("provider_groups") {
            let pg_array = pg.as_array().unwrap();
            pg_array
                .into_iter()
                .map(|pg| {
                    let npis = pg.get("npi").unwrap().as_array().unwrap();
                    let npis = if let Some(np_filter) = self.npi_whitelist.clone() {
                        let iter = npis.into_iter().filter(|npi| {
                            let npi = npi.as_number().unwrap().to_usize().unwrap();
                            np_filter.contains(&npi.to_string())
                        });
                        IArray::from_iter(iter.map(|i| i.clone()))
                    } else {
                        npis.clone()
                    };

                    let mut obj = IObject::new();
                    obj.insert("npi", IValue::from(npis.clone()));
                    obj.insert("tin", pg.get("tin").unwrap().clone());
                    obj
                })
                .collect()
        } else {
            Vec::new()
        }
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

impl From<Option<String>> for Position {
    fn from(value: Option<String>) -> Self {
        if let Some(pos) = value {
            if let Ok(num) = pos.parse::<usize>() {
                Position::Middle(num)
            } else if pos == "end" {
                Position::End
            } else {
                Position::Start
            }
        } else {
            Position::Start
        }
    }
}

// Direction indicates whether to parse the file moving up or down
#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Backward,
}

impl From<Option<String>> for Direction {
    fn from(value: Option<String>) -> Self {
        if let Some(dir) = value {
            if dir.contains("backward") {
                Direction::Backward
            } else {
                Direction::Forward
            }
        } else {
            Direction::Forward
        }
    }
}

#[derive(Parser, Default, Debug)]
#[clap(author = "Luke Rhoads", about = "Rust port of MRFUtils")]
struct Args {
    #[clap(long, default_value = "./input.txt")]
    input_file: String,

    #[clap(long, default_value = "./codes.csv")]
    codes_file: String,

    #[clap(long, default_value = "./npis.csv")]
    npi_file: String,

    #[clap(long)]
    offset_file: Option<String>,

    #[clap(long)]
    line_pos: Option<String>,

    #[clap(long)]
    direction: Option<String>,

    #[clap(long)]
    dolt_dir: String,

    #[arg(long)]
    mock: bool,

    #[arg(long, short)]
    performance_graph: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let default_offset_file = ".offset";
    let npi_file = args.npi_file;
    let codes_file = args.codes_file;
    let offset_file_location = args.offset_file;
    let input_file_location = &args.input_file;
    let direction = Direction::from(args.direction);
    let line_pos = Position::from(args.line_pos);
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
        }
        if max_line_pos.unwrap() > 0 {
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

    let processor = FileProcessor::new(args.dolt_dir, args.mock, &codes_file, &npi_file);
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
        assert_eq!("538167972721089466", make_hash(common_json(&testmap)))
    }
}

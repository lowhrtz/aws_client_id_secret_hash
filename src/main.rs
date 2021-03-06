// aws_client_id_secret_hash
// Copyright (C) 2020 Giancarlo DiMino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use base64::encode;
use clap::{Arg, App};
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Default configuration file name
const DEFAULT_CONFIG: &str = "aws_client.cfg";

fn main() {
    let matches = App::new("AWS ClientID Secret Hash")
        .version("1.0")
        .author("Giancarlo DiMino <giancarlo@lowhrtz.com>")
        .about("Creates aws-usable hash from clientid clientsecret and username")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .value_name("FILE_PATH")
             .help(format!("Path of the config file (default: ./{})", DEFAULT_CONFIG).as_str())
             .takes_value(true))
        .arg(Arg::with_name("username")
            .help("Username of user")
            .required(true)
            .index(1))
        .get_matches();
    let config_path = matches.value_of("config").unwrap_or(DEFAULT_CONFIG);
    // The unwrap on the following line will never result in an error because clap ensures username will always exist
    let username = matches.value_of("username").unwrap();
    let config = Config::parse_config(config_path);
    //println!("{:?}", config);
    let client_id = config.client_id.as_str();
    let client_secret = config.client_secret.as_bytes();

    let mut message = String::from(username);
    message.push_str(client_id);
    let message = message.as_bytes();

    // Create HMAC-SHA256 instance
    let mut mac = HmacSha256::new_varkey(client_secret)
        .expect("HMAC can take key of any size");
    mac.input(message);

    let result = mac.result();
    let code_bytes = result.code();
    // Base64 encode the code byte array and print
    println!("{}", encode(code_bytes));
}

#[derive(Debug)]
/// Structure to contain items from the config file
struct Config {
    client_id: String,
    client_secret: String,
}

impl Config {
    /// Parses the config file
    fn parse_config(config_path: &str) -> Config {
        //println!("{}", config_path);
        let ini = ini::Ini::load_from_file(config_path);
        let ini = match ini {
            Ok(i) => i,
            Err(_) => Config::create_config(config_path),
        };

        // Retreive properties
        // Instead of `let props = ini.general_section();`
        // the following 5 lines give more control over flow.
        let empty_props = ini::ini::Properties::new();
        let props = match ini.section::<String>(None) {
            Some(p) => p,
            None => &empty_props,
        };
        //println!("{}", props.len());

        let missing_text = "directive missing from the configuration file.\n\
                            Either add the directive to the file or \
                            move the file and run this again.";
        let client_id = match props.get("client_id") {
            Some(clid) => clid.to_string(),
            None => {
                eprintln!("WARNING: client_id {}", missing_text);
                String::new()
            },
        };
        let client_secret = match props.get("client_secret") {
            Some(clsec) => clsec.to_string(),
            None => {
                eprintln!("WARNING: client_secret {}", missing_text);
                String::new()
            },
        };

        Config {
            client_id,
            client_secret,
        }
    }

    /// Creates a new config file based on user prompts
    fn create_config(config_path: &str) -> ini::Ini {
        let mut client_id = String::new();
        let mut client_secret = String::new();

        eprintln!("aws_client_id_secret_hash:");
        eprintln!("The default or supplied configuration file doesn't exist.");
        eprintln!("Enter the info to generate it.");
        eprintln!("Client ID:");
        match std::io::stdin().read_line(&mut client_id) {
            Ok(_) => {},
            Err(e) => eprintln!("Problem with input: {}", e),
        }
        
        eprintln!("Client Secret:");
        match std::io::stdin().read_line(&mut client_secret) {
            Ok(_) => {},
            Err(e) => eprintln!("Problem with input: {}", e),
        }
        //println!("{} {}", client_id.trim(), client_secret.trim());

        let mut new_ini = ini::Ini::new();
        new_ini.with_section::<String>(None)
            .set("client_id", client_id.trim())
            .set("client_secret", client_secret.trim());
        match new_ini.write_to_file(config_path) {
            Ok(_) => {},
            Err(e) => eprintln!("Error writing configuration file! {}", e),
        };

        new_ini
    }
}

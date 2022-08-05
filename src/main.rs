use hex_literal::hex;
use sha2::{ Digest, Sha256 };
use std::{ fmt::{ Debug, LowerHex } };

use clap::{ arg, Command };

fn main() {
    // let arg2 = Arg::with_name("help")
    // 	.help("Print the Help information")
    // 	.required(true)
    // 	.short('h')
    // 	.value_name("help");

    // let matches = App::new("Simple-pow")
    // 	.version("0.0.1")
    // 	.author("Alfredo Javier Lopez Herize <alfredolopez80@gmail.com>" )
    // 	.about("Simple proof of work")
    // 	.arg(arg1)
    // 	.arg(arg2)
    // 	.get_matches();

    let _matches = Command::new("simple-pow")
        .version("0.0.1")
        .author("Alfredo Javier Lopez Herize <alfredolopez80@gmail.com>")
        .about("Simple proof of work")
        .arg(arg!(-s --string <STRING>  "String to be hashed with SHA256 and Getting ans Simple Proof of Work"))
        .after_long_help(
            "CLI permit to getting SHA256 hash of the prefix combined with the original string of bytes, has two last bytes as 0xca, 0xfe, in two lines, the first line is the prefix, the second line is the prefix in hexadecimal, the hash is the hash of the original string of bytes more the prefix,"
        )
        .get_matches();

    if _matches.is_present("string") {
        let mut bytes = [0u8; 64];
        let _string = _matches.get_one::<String>("string").unwrap();
        // println!("String Capturada 1 {:?}",_string);
        hex::decode_to_slice(_string, &mut bytes as &mut [u8]).expect(
            "please provide a valid 64-byte hex string"
        );
        if let Ok((prefix, solution)) = simple_pow(bytes) {
            println!("{:x}\n{:08x}", solution, prefix);
        }
    } else {
        help();
    }
}

fn help() {
    println!("provide a 64 byte hex as the sole parameter");
}

fn simple_pow(bytes: [u8; 64]) -> Result<(u32, impl Debug + LowerHex), ()> {
    const CAFE: [u8; 2] = hex!("cafe");

    for prefix in 0..u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(prefix.to_be_bytes());
        hasher.update(bytes);
        let finalized = hasher.finalize();
        if CAFE == finalized[finalized.len() - 2..finalized.len()] {
            return Ok((prefix, finalized));
        }
    }
    Err(())
}

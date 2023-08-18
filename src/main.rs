use clap::Parser;
mod commands;
use commands::{GenerateCmd, SignCmd, VerifyCmd};

#[derive(Debug, Parser)]
#[clap(
	name = "crypto",
	author = "Quantum Blockchains Team",
	about = "Utility for generating, sign and verification message with Dilithium keys",
	version = "1.0.0"
)]
pub enum Subkey {
	Generate(GenerateCmd),
	Sign(SignCmd),
	Verify(VerifyCmd),
}

#[tokio::main]
async fn main() {
	match  Subkey::parse() {
		Subkey::Generate(cmd) => {
			match cmd.run().await {
				Ok(_) => {},
				Err(err) => println!("ERROR: {:?}", err),
			}
		},
		Subkey::Sign(cmd) => {
			match cmd.run() {
				Ok(_) => {},
				Err(err) => println!("ERROR: {:?}", err),
			}
		}
		Subkey::Verify(cmd) => {
			match cmd.run() {
				Ok(_) => {},
				Err(err) => println!("ERROR: {:?}", err),
			}
		}
	};
}
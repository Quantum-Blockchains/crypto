use clap::Parser;
mod commands;
use commands::{GenerateCmd, PublicCmd, SignCmd, VerifyCmd};


#[derive(Debug, Parser)]
#[clap(
	name = "crypto",
	author = "Quantum Blockchains Team",
	about = "Utility for generating, sign and verification message with Dilithium keys",
	version = "1.0.0"
)]
pub enum Subkey {
	/// Generate key pair
	Generate(GenerateCmd),
	/// Pull the public key from the pair
	Public(PublicCmd),
	/// Sign the message
	Sign(SignCmd),
	/// Message verification
	Verify(VerifyCmd),
}

fn main() {
	match  Subkey::parse() {
		Subkey::Generate(cmd) => cmd.run(),
		Subkey::Public(cmd) => cmd.run(),
		Subkey::Sign(cmd) => cmd.run(),
		Subkey::Verify(cmd) => cmd.run(),
	};
}
use clap::Parser;
mod commands;
use commands::{GenerateCmd, PublicCmd, SignCmd, VerifyCmd};


#[derive(Debug, Parser)]
#[clap(
	name = "subkey",
	author = "Parity Team <admin@parity.io>",
	about = "Utility for generating and restoring with Substrate keys",
	version
)]
pub enum Subkey {
	/// Generate a random account
	Generate(GenerateCmd),
	Public(PublicCmd),
	Sign(SignCmd),
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
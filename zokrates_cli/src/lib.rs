#[macro_use]
extern crate lazy_static;

mod ops;
mod constants;
mod helpers;

use clap::{App, AppSettings};
use std::ffi::OsString;
use crate::ops::*;

pub fn cli<I: IntoIterator<Item=T>, T: Into<OsString> + Clone>(args: Option<I>) -> Result<(), String> {
    // cli specification using clap library
    let matches = App::new("ZoKrates")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(env!("CARGO_PKG_VERSION"))
        .author("Jacob Eberhardt, Thibaut Schaeffer, Stefan Deml, Darko Macesic")
        .about("Supports generation of zkSNARKs from high level language code including Smart Contracts for proof verification on the Ethereum Blockchain.\n'I know that I show nothing!'")
        .subcommands(vec![
            compile::subcommand(),
            check::subcommand(),
            compute_witness::subcommand(),
            setup::subcommand(),
            export_verifier::subcommand(),
            generate_proof::subcommand(),
            print_proof::subcommand(),
            verify::subcommand()]);

    let matches = match args {
        Some(args) => matches.get_matches_from(args),
        None => matches.get_matches()
    };

    match matches.subcommand() {
        ("compile", Some(sub_matches)) => compile::exec(sub_matches)?,
        ("check", Some(sub_matches)) => check::exec(sub_matches)?,
        ("compute-witness", Some(sub_matches)) => compute_witness::exec(sub_matches)?,
        #[cfg(any(feature = "bellman", feature = "ark", feature = "libsnark"))]
        ("setup", Some(sub_matches)) => setup::exec(sub_matches)?,
        ("export-verifier", Some(sub_matches)) => export_verifier::exec(sub_matches)?,
        #[cfg(any(feature = "bellman", feature = "ark", feature = "libsnark"))]
        ("generate-proof", Some(sub_matches)) => generate_proof::exec(sub_matches)?,
        ("print-proof", Some(sub_matches)) => print_proof::exec(sub_matches)?,
        #[cfg(any(feature = "bellman", feature = "ark", feature = "libsnark"))]
        ("verify", Some(sub_matches)) => verify::exec(sub_matches)?,
        _ => unreachable!(),
    };

    Ok(())
}
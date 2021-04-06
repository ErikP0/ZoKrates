//
// @file bin.rs
// @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de>
// @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
// @date 2017

use zokrates_cli::cli;
use std::ffi::OsString;

fn main() {
    cli::<Vec<_>, OsString>(None).unwrap_or_else(|e| {
        println!("{}", e);
        std::process::exit(1);
    })
}

#[cfg(test)]
mod tests {
    extern crate glob;
    use self::glob::glob;

    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::string::String;
    use zokrates_core::compile::{compile, CompilationArtifacts, CompileConfig};
    use zokrates_core::ir;
    use zokrates_field::Bn128Field;
    use zokrates_fs_resolver::FileSystemResolver;

    #[test]
    fn compile_examples() {
        let builder = std::thread::Builder::new().stack_size(8388608);

        builder
            .spawn(|| {
                for p in glob("./examples/**/*").expect("Failed to read glob pattern") {
                    let path = match p {
                        Ok(x) => x,
                        Err(why) => panic!("Error: {:?}", why),
                    };

                    if !path.is_file() {
                        continue;
                    }

                    assert!(path.extension().expect("extension expected") == "zok");

                    let should_error = path.to_str().unwrap().contains("compile_errors");

                    println!("Testing {:?}", path);

                    let file = File::open(path.clone()).unwrap();

                    let mut reader = BufReader::new(file);

                    let mut source = String::new();
                    reader.read_to_string(&mut source).unwrap();

                    let stdlib = std::fs::canonicalize("../zokrates_stdlib/stdlib").unwrap();
                    let resolver = FileSystemResolver::with_stdlib_root(stdlib.to_str().unwrap());
                    let res = compile::<Bn128Field, _>(
                        source,
                        path,
                        Some(&resolver),
                        &CompileConfig::default(),
                    );
                    assert_eq!(res.is_err(), should_error);
                }
            })
            .unwrap();
    }

    #[test]
    fn execute_examples_ok() {
        //these examples should compile and run
        for p in glob("./examples/test*").expect("Failed to read glob pattern") {
            let path = match p {
                Ok(x) => x,
                Err(why) => panic!("Error: {:?}", why),
            };
            println!("Testing {:?}", path);

            let file = File::open(path.clone()).unwrap();

            let mut reader = BufReader::new(file);
            let mut source = String::new();
            reader.read_to_string(&mut source).unwrap();

            let stdlib = std::fs::canonicalize("../zokrates_stdlib/stdlib").unwrap();
            let resolver = FileSystemResolver::with_stdlib_root(stdlib.to_str().unwrap());

            let artifacts: CompilationArtifacts<Bn128Field> =
                compile(source, path, Some(&resolver), &CompileConfig::default()).unwrap();

            let interpreter = ir::Interpreter::default();

            let _ = interpreter
                .execute(&artifacts.prog(), &vec![Bn128Field::from(0)])
                .unwrap();
        }
    }

    #[test]
    fn execute_examples_err() {
        //these examples should compile but not run
        for p in glob("./examples/runtime_errors/*").expect("Failed to read glob pattern") {
            let path = match p {
                Ok(x) => x,
                Err(why) => panic!("Error: {:?}", why),
            };
            println!("Testing {:?}", path);

            let file = File::open(path.clone()).unwrap();

            let mut reader = BufReader::new(file);
            let mut source = String::new();
            reader.read_to_string(&mut source).unwrap();

            let stdlib = std::fs::canonicalize("../zokrates_stdlib/stdlib").unwrap();
            let resolver = FileSystemResolver::with_stdlib_root(stdlib.to_str().unwrap());

            let artifacts: CompilationArtifacts<Bn128Field> =
                compile(source, path, Some(&resolver), &CompileConfig::default()).unwrap();

            let interpreter = ir::Interpreter::default();

            let res = interpreter.execute(&artifacts.prog(), &vec![Bn128Field::from(0)]);

            assert!(res.is_err());
        }
    }
}

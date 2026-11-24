use std::process::ExitCode;

fn print_usage() {
    println!(
        "manis {} — Declarative Linux hardening audit CLI (CIS, ANSSI-BP-028, NIST)\n\n\
         Usage:\n  \
           manis <command> [options]\n\n\
         Commands:\n  \
           audit      Run compliance checks against the host or a --root fixture\n  \
           list       List available rules and profiles\n  \
           explain    Show benchmark references and remediation for a rule\n  \
           diff       Compare two JSON audit reports for hardening drift\n\n\
         Run 'manis --help' or see docs/SPEC.md for details.",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("-h" | "--help") => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("manis {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(cmd) => {
            eprintln!("manis: command '{cmd}' is not implemented yet (see docs/SPEC.md).");
            ExitCode::from(2)
        }
    }
}

// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use syntax::diagnostic;

use back::link;
use driver::driver::{Input, FileInput, StrInput};
use driver::session::{Session, build_session};
use lint::Lint;
use lint;
use metadata;

use std::any::AnyRefExt;
use std::io;
use std::os;
use std::task::TaskBuilder;

use syntax::ast;
use syntax::parse;
use syntax::diagnostic::Emitter;
use syntax::diagnostics;

use getopts;

pub mod driver;
pub mod session;
pub mod config;
pub mod pretty;

// crf: This is where the very entry point from command line calls to. This is compilation just getting started.
pub fn run(args: Vec<String>) -> int {
    monitor(proc() run_compiler(args.as_slice()));
    0
}

static BUG_REPORT_URL: &'static str =
    "http://doc.rust-lang.org/complement-bugreport.html";


// crf: very early in compilation process.
fn run_compiler(args: &[String]) {
    // crf: as you suspect, handle_options interprets compiler options. Returns None if they are flawed or compilation should stop.
    let matches = match handle_options(Vec::from_slice(args)) {
        Some(matches) => matches,
        None => return
    };

    // crf: ignoring this for now.
    let descriptions = diagnostics::registry::Registry::new(super::DIAGNOSTICS);


    // crf: lets dig into this. getopts is an extern crate defined at libgetopts/lib.rs. And handle_options returns a
    //  get_opts::matches. That type will have opt_str on it.
    // Yes. So if there is an "explain" option in the command line args, return the value of that arg. If any of those
    // diagnostic descripotions i skipped over above match the value (it calls "find_description" so some logic might apply),
    // then print the description.
    match matches.opt_str("explain") {
        Some(ref code) => {
            match descriptions.find_description(code.as_slice()) {
                Some(ref description) => {
                    println!("{}", description);
                }
                None => {
                    early_error(format!("no extended information for {}", code).as_slice());
                }
            }
            return;
        },
        None => ()
    }

    // crf: lets dig into what session is, starting with understanding these session opts. No big deal really. All the options about
    //  what kind of output to make, whether to include debugging info, etc.
    let sopts = config::build_session_options(&matches);
    // crf: what is matches.free? you can just type free strings on the command line that are not associated with an arg.
    let (input, input_file_path) = match matches.free.len() {
        0u => {
            // crf: if you did NOT type any free strings on command line, but "help" was included for at least 1 of the lint levels,
            //  then we instantiate a "LintStore". this is in lint::context.rs. Starts out with merely empty initialized data members.
            if sopts.describe_lints {
                let mut ls = lint::LintStore::new();
                // crf: next line doesn't do what you might think. It actually has a HARDWIRED LIST of builtin lints, and it
                //  registers them all.
                //
                // crf: in the case of unused_imports, it has done 2 things:
                // 1. Added a LintPass called GatherNodeLevels to LintStore.passes
                // 2. Added a lint_group called "unused" to LintStore.lint_groups
                ls.register_builtin(None);

                // crf: So what does describe_lints do?
                // Produces a detailed description of all the lints and dumps it out.
                describe_lints(&ls, false);

                // crf: KEEP IN MIND: If they did not ask for "help" on the cmd line, then the lints would not even be loaded yet,
                //  (for example, register_builtin would not have even been called)
                return;
            }
            early_error("no input filename given");
        }
        1u => {
            let ifile = matches.free.get(0).as_slice();
            // crf: this is cool, lets the compiler read its input from stdin.
            if ifile == "-" {
                let contents = io::stdin().read_to_end().unwrap();
                let src = String::from_utf8(contents).unwrap();
                // crf: this sets input to the string from stdin, and filepath to none
                (StrInput(src), None)
            } else {
                // crf: this sets input to a FileInput of the source file, and filepath to the source of the file.
                (FileInput(Path::new(ifile)), Some(Path::new(ifile)))
            }
        }
        _ => early_error("multiple input filenames provided")
    };

    // crf: now it's time to build_session. What happens here?
    // It's driver::session::build_session
    // It just builds a big struct called session, but it also sets up the LintStore and calls register_builtin

    let cfg = config::build_configuration(&sess);
    let odir = matches.opt_str("out-dir").map(|o| Path::new(o));
    let ofile = matches.opt_str("o").map(|o| Path::new(o));

    let pretty = matches.opt_default("pretty", "normal").map(|a| {
        pretty::parse_pretty(&sess, a.as_slice())
    });
    match pretty {
        Some((ppm, opt_uii)) => {
            pretty::pretty_print_input(sess, cfg, &input, ppm, opt_uii, ofile);
            return;
        }
        None => {/* continue */ }
    }

    let r = matches.opt_strs("Z");
    if r.contains(&("ls".to_string())) {
        match input {
            // crf: if you passed in a Z option and it contains "ls", then we are going to list metadata.
            //  We might be an rlib or something, so there could be interesting info i guess
            FileInput(ref ifile) => {
                let mut stdout = io::stdout();
                list_metadata(&sess, &(*ifile), &mut stdout).unwrap();
            }
            StrInput(_) => {
                early_error("can not list metadata for stdin");
            }
        }
        return;
    }

    if print_crate_info(&sess, &input, &odir, &ofile) {
        return;
    }

    // crf: And now! We call driver::compile_input.
    driver::compile_input(sess, cfg, &input, &odir, &ofile, None);
}

/// Returns a version string such as "0.12.0-dev".
pub fn release_str() -> Option<&'static str> {
    option_env!("CFG_RELEASE")
}

/// Returns the full SHA1 hash of HEAD of the Git repo from which rustc was built.
pub fn commit_hash_str() -> Option<&'static str> {
    option_env!("CFG_VER_HASH")
}

/// Returns the "commit date" of HEAD of the Git repo from which rustc was built as a static string.
pub fn commit_date_str() -> Option<&'static str> {
    option_env!("CFG_VER_DATE")
}

/// Prints version information and returns None on success or an error
/// message on failure.
pub fn version(binary: &str, matches: &getopts::Matches) -> Option<String> {
    let verbose = match matches.opt_str("version").as_ref().map(|s| s.as_slice()) {
        None => false,
        Some("verbose") => true,
        Some(s) => return Some(format!("Unrecognized argument: {}", s))
    };

    println!("{} {}", binary, option_env!("CFG_VERSION").unwrap_or("unknown version"));
    if verbose {
        fn unw(x: Option<&str>) -> &str { x.unwrap_or("unknown") }
        println!("binary: {}", binary);
        println!("commit-hash: {}", unw(commit_hash_str()));
        println!("commit-date: {}", unw(commit_date_str()));
        println!("host: {}", driver::host_triple());
        println!("release: {}", unw(release_str()));
    }
    None
}

fn usage() {
    let message = format!("Usage: rustc [OPTIONS] INPUT");
    println!("{}\n\
Additional help:
    -C help             Print codegen options
    -W help             Print 'lint' options and default settings
    -Z help             Print internal options for debugging rustc\n",
              getopts::usage(message.as_slice(),
                             config::optgroups().as_slice()));
}

fn describe_lints(lint_store: &lint::LintStore, loaded_plugins: bool) {
    println!("
Available lint options:
    -W <foo>           Warn about <foo>
    -A <foo>           Allow <foo>
    -D <foo>           Deny <foo>
    -F <foo>           Forbid <foo> (deny, and deny all overrides)

");

    fn sort_lints(lints: Vec<(&'static Lint, bool)>) -> Vec<&'static Lint> {
        let mut lints: Vec<_> = lints.into_iter().map(|(x, _)| x).collect();
        lints.sort_by(|x: &&Lint, y: &&Lint| {
            match x.default_level.cmp(&y.default_level) {
                // The sort doesn't case-fold but it's doubtful we care.
                Equal => x.name.cmp(&y.name),
                r => r,
            }
        });
        lints
    }

    fn sort_lint_groups(lints: Vec<(&'static str, Vec<lint::LintId>, bool)>)
                     -> Vec<(&'static str, Vec<lint::LintId>)> {
        let mut lints: Vec<_> = lints.into_iter().map(|(x, y, _)| (x, y)).collect();
        lints.sort_by(|&(x, _): &(&'static str, Vec<lint::LintId>),
                       &(y, _): &(&'static str, Vec<lint::LintId>)| {
            x.cmp(&y)
        });
        lints
    }

    let (plugin, builtin) = lint_store.get_lints().partitioned(|&(_, p)| p);
    let plugin = sort_lints(plugin);
    let builtin = sort_lints(builtin);

    let (plugin_groups, builtin_groups) = lint_store.get_lint_groups().partitioned(|&(_, _, p)| p);
    let plugin_groups = sort_lint_groups(plugin_groups);
    let builtin_groups = sort_lint_groups(builtin_groups);

    let max_name_len = plugin.iter().chain(builtin.iter())
        .map(|&s| s.name.width(true))
        .max().unwrap_or(0);
    let padded = |x: &str| {
        " ".repeat(max_name_len - x.char_len()).append(x)
    };

    println!("Lint checks provided by rustc:\n");
    println!("    {}  {:7.7s}  {}", padded("name"), "default", "meaning");
    println!("    {}  {:7.7s}  {}", padded("----"), "-------", "-------");

    let print_lints = |lints: Vec<&Lint>| {
        for lint in lints.into_iter() {
            let name = lint.name_lower().replace("_", "-");
            println!("    {}  {:7.7s}  {}",
                     padded(name.as_slice()), lint.default_level.as_str(), lint.desc);
        }
        println!("\n");
    };

    print_lints(builtin);



    let max_name_len = plugin_groups.iter().chain(builtin_groups.iter())
        .map(|&(s, _)| s.width(true))
        .max().unwrap_or(0);
    let padded = |x: &str| {
        " ".repeat(max_name_len - x.char_len()).append(x)
    };

    println!("Lint groups provided by rustc:\n");
    println!("    {}  {}", padded("name"), "sub-lints");
    println!("    {}  {}", padded("----"), "---------");

    let print_lint_groups = |lints: Vec<(&'static str, Vec<lint::LintId>)>| {
        for (name, to) in lints.into_iter() {
            let name = name.chars().map(|x| x.to_lowercase())
                           .collect::<String>().replace("_", "-");
            let desc = to.into_iter().map(|x| x.as_str()).collect::<Vec<String>>().connect(", ");
            println!("    {}  {}",
                     padded(name.as_slice()), desc);
        }
        println!("\n");
    };

    print_lint_groups(builtin_groups);

    match (loaded_plugins, plugin.len(), plugin_groups.len()) {
        (false, 0, _) | (false, _, 0) => {
            println!("Compiler plugins can provide additional lints and lint groups. To see a \
                      listing of these, re-run `rustc -W help` with a crate filename.");
        }
        (false, _, _) => fail!("didn't load lint plugins but got them anyway!"),
        (true, 0, 0) => println!("This crate does not load any lint plugins or lint groups."),
        (true, l, g) => {
            if l > 0 {
                println!("Lint checks provided by plugins loaded by this crate:\n");
                print_lints(plugin);
            }
            if g > 0 {
                println!("Lint groups provided by plugins loaded by this crate:\n");
                print_lint_groups(plugin_groups);
            }
        }
    }
}

fn describe_debug_flags() {
    println!("\nAvailable debug options:\n");
    let r = config::debugging_opts_map();
    for tuple in r.iter() {
        match *tuple {
            (ref name, ref desc, _) => {
                println!("    -Z {:>20s} -- {}", *name, *desc);
            }
        }
    }
}

fn describe_codegen_flags() {
    println!("\nAvailable codegen options:\n");
    let mut cg = config::basic_codegen_options();
    for &(name, parser, desc) in config::CG_OPTIONS.iter() {
        // we invoke the parser function on `None` to see if this option needs
        // an argument or not.
        let (width, extra) = if parser(&mut cg, None) {
            (25, "")
        } else {
            (21, "=val")
        };
        println!("    -C {:>width$s}{} -- {}", name.replace("_", "-"),
                 extra, desc, width=width);
    }
}

/// Process command line options. Emits messages as appropriate. If compilation
/// should continue, returns a getopts::Matches object parsed from args, otherwise
/// returns None.
pub fn handle_options(mut args: Vec<String>) -> Option<getopts::Matches> {
    // Throw away the first argument, the name of the binary
    let _binary = args.shift().unwrap();

    if args.is_empty() {
        usage();
        return None;
    }

    let matches =
        match getopts::getopts(args.as_slice(), config::optgroups().as_slice()) {
            Ok(m) => m,
            Err(f) => {
                early_error(f.to_string().as_slice());
            }
        };

    if matches.opt_present("h") || matches.opt_present("help") {
        usage();
        return None;
    }

    // Don't handle -W help here, because we might first load plugins.

    let r = matches.opt_strs("Z");
    if r.iter().any(|x| x.as_slice() == "help") {
        describe_debug_flags();
        return None;
    }

    let cg_flags = matches.opt_strs("C");
    if cg_flags.iter().any(|x| x.as_slice() == "help") {
        describe_codegen_flags();
        return None;
    }

    if cg_flags.contains(&"passes=list".to_string()) {
        unsafe { ::llvm::LLVMRustPrintPasses(); }
        return None;
    }

    if matches.opt_present("version") {
        match version("rustc", &matches) {
            Some(err) => early_error(err.as_slice()),
            None => return None
        }
    }

    Some(matches)
}

fn print_crate_info(sess: &Session,
                    input: &Input,
                    odir: &Option<Path>,
                    ofile: &Option<Path>)
                    -> bool {
    let (crate_name, crate_file_name) = sess.opts.print_metas;
    // these nasty nested conditions are to avoid doing extra work
    if crate_name || crate_file_name {
        let attrs = parse_crate_attrs(sess, input);
        let t_outputs = driver::build_output_filenames(input,
                                                       odir,
                                                       ofile,
                                                       attrs.as_slice(),
                                                       sess);
        let id = link::find_crate_name(Some(sess), attrs.as_slice(), input);

        if crate_name {
            println!("{}", id);
        }
        if crate_file_name {
            let crate_types = driver::collect_crate_types(sess, attrs.as_slice());
            let metadata = driver::collect_crate_metadata(sess, attrs.as_slice());
            *sess.crate_metadata.borrow_mut() = metadata;
            for &style in crate_types.iter() {
                let fname = link::filename_for_input(sess, style, id.as_slice(),
                                                     &t_outputs.with_extension(""));
                println!("{}", fname.filename_display());
            }
        }

        true
    } else {
        false
    }
}

fn parse_crate_attrs(sess: &Session, input: &Input) ->
                     Vec<ast::Attribute> {
    let result = match *input {
        FileInput(ref ifile) => {
            parse::parse_crate_attrs_from_file(ifile,
                                               Vec::new(),
                                               &sess.parse_sess)
        }
        StrInput(ref src) => {
            parse::parse_crate_attrs_from_source_str(
                driver::anon_src().to_string(),
                src.to_string(),
                Vec::new(),
                &sess.parse_sess)
        }
    };
    result.into_iter().collect()
}

pub fn early_error(msg: &str) -> ! {
    let mut emitter = diagnostic::EmitterWriter::stderr(diagnostic::Auto, None);
    emitter.emit(None, msg, None, diagnostic::Fatal);
    fail!(diagnostic::FatalError);
}

pub fn early_warn(msg: &str) {
    let mut emitter = diagnostic::EmitterWriter::stderr(diagnostic::Auto, None);
    emitter.emit(None, msg, None, diagnostic::Warning);
}

pub fn list_metadata(sess: &Session, path: &Path,
                     out: &mut io::Writer) -> io::IoResult<()> {
    metadata::loader::list_file_metadata(sess.targ_cfg.os, path, out)
}

/// Run a procedure which will detect failures in the compiler and print nicer
/// error messages rather than just failing the test.
///
/// The diagnostic emitter yielded to the procedure should be used for reporting
/// errors of the compiler.
pub fn monitor(f: proc():Send) {
    // FIXME: This is a hack for newsched since it doesn't support split stacks.
    // rustc needs a lot of stack! When optimizations are disabled, it needs
    // even *more* stack than usual as well.
    #[cfg(rtopt)]
    static STACK_SIZE: uint = 6000000;  // 6MB
    #[cfg(not(rtopt))]
    static STACK_SIZE: uint = 20000000; // 20MB

    let (tx, rx) = channel();
    let w = io::ChanWriter::new(tx);
    let mut r = io::ChanReader::new(rx);

    let mut task = TaskBuilder::new().named("rustc").stderr(box w);

    // FIXME: Hacks on hacks. If the env is trying to override the stack size
    // then *don't* set it explicitly.
    if os::getenv("RUST_MIN_STACK").is_none() {
        task = task.stack_size(STACK_SIZE);
    }

    match task.try(f) {
        Ok(()) => { /* fallthrough */ }
        Err(value) => {
            // Task failed without emitting a fatal diagnostic
            if !value.is::<diagnostic::FatalError>() {
                let mut emitter = diagnostic::EmitterWriter::stderr(diagnostic::Auto, None);

                // a .span_bug or .bug call has already printed what
                // it wants to print.
                if !value.is::<diagnostic::ExplicitBug>() {
                    emitter.emit(
                        None,
                        "unexpected failure",
                        None,
                        diagnostic::Bug);
                }

                let xs = [
                    "the compiler hit an unexpected failure path. this is a bug.".to_string(),
                    format!("we would appreciate a bug report: {}",
                            BUG_REPORT_URL),
                    "run with `RUST_BACKTRACE=1` for a backtrace".to_string(),
                ];
                for note in xs.iter() {
                    emitter.emit(None, note.as_slice(), None, diagnostic::Note)
                }

                match r.read_to_string() {
                    Ok(s) => println!("{}", s),
                    Err(e) => {
                        emitter.emit(None,
                                     format!("failed to read internal \
                                              stderr: {}",
                                             e).as_slice(),
                                     None,
                                     diagnostic::Error)
                    }
                }
            }

            // Fail so the process returns a failure code, but don't pollute the
            // output with some unnecessary failure messages, we've already
            // printed everything that we needed to.
            io::stdio::set_stderr(box io::util::NullWriter);
            fail!();
        }
    }
}

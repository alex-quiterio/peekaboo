#[allow(clippy::disallowed_methods)] // the entry point is where arguments are read
fn main() {
    std::process::exit(peekaboo::apps::run(std::env::args().skip(1).collect()));
}

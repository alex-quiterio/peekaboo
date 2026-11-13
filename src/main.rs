fn main() {
    std::process::exit(peekaboo::apps::run(std::env::args().skip(1).collect()));
}

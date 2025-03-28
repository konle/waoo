use clap::{ Parser, Subcommand};


#[derive(Parser, Debug)]
#[command(about = "A simple eBPF program")]
pub struct Argument{
    // #[clap(flatten)]
    // pub global_opts: GlobalOpts,
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about="Tracing open syscalls")]
    Opensnoop{},
    #[command(about="Tracing kill syscalls")]
    Killsnoop{},
}

// #[derive(Debug, Args)]
// pub struct GlobalOpts {
//     /// Verbosity level (can be specified multiple times)
//     #[clap(long, short, global = true, action= ArgAction::Count)]
//     pub verbose: u8,
// }

pub fn parse()->Argument{
    Argument::parse()
}
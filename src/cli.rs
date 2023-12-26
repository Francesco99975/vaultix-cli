use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Signup to Vaultix")]
    Signup {
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
    },
    #[command(about = "Login to Vaultix")]
    Login {
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
    },
    #[command(about = "List all stored encrypted credentials")]
    List,
    #[command(about = "Encrypt and store credential")]
    Store {
        service: Option<String>,
        credentials: Option<Vec<String>>,
    },
    #[command(about = "Decrypt and display specified credential")]
    Show { credential: Option<String> },
}

#[derive(Parser, Debug)]
#[command(author = "Francesco Michele Barranca (kalairendev)", version = "1.0", about = "Vaultix Credentials Manager", long_about = None)]
#[command(propagate_version = true)]
pub struct Vaultix {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

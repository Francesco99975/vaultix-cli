use auth::{login, signup};
use clap::Parser;
use cli::{Commands, Vaultix};

mod auth;
mod cli;
mod crypto;
mod endpoints;
mod errors;
mod http;
mod keystore;
mod models;
mod udid;

#[tokio::main]
async fn main() {
    let args = Vaultix::parse();

    match &args.command {
        Some(Commands::Signup { password }) => {
            match password {
                Some(password) => match signup(&password).await {
                    Ok(()) => {
                        println!("Successfully Signed Up! You can now login")
                    }
                    Err(err) => {
                        eprintln!("Could not Signup: {:?}", err.to_string())
                    }
                },
                None => {
                    eprintln!(
                        "No Password specified. Use vaultix signup -p <your-password> to signup"
                    )
                }
            };
        }
        Some(Commands::Login { password }) => {
            match password {
                Some(password) => match login(&password).await {
                    Ok(token) => {
                        println!("{}", token)
                    }
                    Err(err) => eprintln!("Could not Login: {:?}", err.to_string()),
                },
                None => {
                    eprintln!(
                        "No Password specified. Use vaultix login -p <your-password> to signup"
                    )
                }
            };
        }
        Some(Commands::List) => {}
        Some(Commands::Store {
            service,
            credentials,
        }) => {
            match service {
                Some(service) => {
                    println!("{}", service);
                    match credentials {
                        Some(credentials) => {
                            if credentials
                                .iter()
                                .all(|cred| cred.chars().filter(|&ch| ch == ':').count() == 1)
                            {
                                println!("{:?}", credentials);
                            } else {
                                eprintln!("Invalid Credential format used.");
                            }
                        }
                        None => {
                            eprintln!(
                            "No Credentials specified. Use vaultix store <your-service> <your-field>:<your-secret> <your-field2>:<your-secret2> to store credentials"
                        );
                        }
                    }
                }
                None => {
                    eprintln!(
                        "No Service specified. Use vaultix store <your-service> <your-field>:<your-secret> <your-field2>:<your-secret2> to store credentials"
                    );
                }
            };
        }
        Some(Commands::Show { credential }) => match credential {
            Some(credential) => {
                println!("{}", credential);
            }
            None => {
                eprintln!(
                    "No Credential specified. Use vaultix show <your-credential> to display credential"
                );
            }
        },
        None => eprintln!("Invalid Command or No action specified. Try vaultix --help"),
    }
}

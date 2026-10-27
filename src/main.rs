mod crypto;
mod logger;

use clap::{Parser, Subcommand};
use crypto::{decrypt_data, encrypt_data};
use logger::{AuditLogger, Operation};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "simple_file_encryptor",
    author = "Student",
    version = "1.0.0",
    about = "Simple File Encryptor / Decryptor (AES-256-GCM + PBKDF2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Зашифрувати файл
    Encrypt {
        /// Шлях до вхідного файлу
        #[arg(short, long)]
        input: PathBuf,

        /// Шлях до вихідного зашифрованого файлу (за замовчуванням: <ім'я>.enc)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Парольна фраза (якщо не вказано, запитується інтерактивно)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Розшифрувати файл
    Decrypt {
        /// Шлях до зашифрованого файлу (.enc)
        #[arg(short, long)]
        input: PathBuf,

        /// Шлях до відновленого файлу
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Парольна фраза (якщо не вказано, запитується інтерактивно)
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn get_password(cli_pwd: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    match cli_pwd {
        Some(p) => Ok(p),
        None => {
            let pass = rpassword::prompt_password("Введіть пароль: ")?;
            if pass.trim().is_empty() {
                return Err("Пароль не може бути порожнім.".into());
            }
            Ok(pass)
        }
    }
}

fn determine_encrypt_output(input: &Path, output: Option<PathBuf>) -> PathBuf {
    if let Some(out) = output {
        out
    } else {
        let mut new_name = input.as_os_str().to_os_string();
        new_name.push(".enc");
        PathBuf::from(new_name)
    }
}

fn determine_decrypt_output(input: &Path, output: Option<PathBuf>) -> PathBuf {
    if let Some(out) = output {
        out
    } else {
        let str_path = input.to_string_lossy();
        if str_path.ends_with(".enc") {
            PathBuf::from(&str_path[..str_path.len() - 4])
        } else {
            let mut new_name = input.as_os_str().to_os_string();
            new_name.push(".dec");
            PathBuf::from(new_name)
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
        } => {
            let out_path = determine_encrypt_output(&input, output);
            let mut pwd = match get_password(password) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Помилка: {}", e);
                    std::process::exit(1);
                }
            };

            let in_data = match fs::read(&input) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Помилка читання файлу {:?}: {}", input, e);
                    AuditLogger::log_event(
                        Operation::Encrypt,
                        &input,
                        0,
                        false,
                        &format!("Помилка читання: {}", e),
                    );
                    std::process::exit(1);
                }
            };

            let in_size = in_data.len() as u64;

            match encrypt_data(in_data, pwd.as_bytes()) {
                Ok(encrypted) => {
                    if let Err(e) = fs::write(&out_path, &encrypted) {
                        eprintln!("Помилка запису результату {:?}: {}", out_path, e);
                        AuditLogger::log_event(
                            Operation::Encrypt,
                            &input,
                            in_size,
                            false,
                            &format!("Помилка запису: {}", e),
                        );
                        std::process::exit(1);
                    }
                    println!("Файл успішно зашифровано: {:?}", out_path);
                    AuditLogger::log_event(
                        Operation::Encrypt,
                        &input,
                        in_size,
                        true,
                        &format!("Збережено у {:?}", out_path),
                    );
                }
                Err(e) => {
                    eprintln!("Помилка шифрування: {}", e);
                    AuditLogger::log_event(
                        Operation::Encrypt,
                        &input,
                        in_size,
                        false,
                        &format!("Криптографічний збій: {}", e),
                    );
                    std::process::exit(1);
                }
            }
            pwd.zeroize();
        }

        Commands::Decrypt {
            input,
            output,
            password,
        } => {
            let out_path = determine_decrypt_output(&input, output);
            let mut pwd = match get_password(password) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Помилка: {}", e);
                    std::process::exit(1);
                }
            };

            let enc_data = match fs::read(&input) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Помилка читання файлу {:?}: {}", input, e);
                    AuditLogger::log_event(
                        Operation::Decrypt,
                        &input,
                        0,
                        false,
                        &format!("Помилка читання: {}", e),
                    );
                    std::process::exit(1);
                }
            };

            let enc_size = enc_data.len() as u64;

            match decrypt_data(&enc_data, pwd.as_bytes()) {
                Ok(mut decrypted) => {
                    if let Err(e) = fs::write(&out_path, &decrypted) {
                        eprintln!("Помилка запису файлу {:?}: {}", out_path, e);
                        AuditLogger::log_event(
                            Operation::Decrypt,
                            &input,
                            enc_size,
                            false,
                            &format!("Помилка запису: {}", e),
                        );
                        std::process::exit(1);
                    }
                    decrypted.zeroize();
                    println!("Файл успішно дешифровано: {:?}", out_path);
                    AuditLogger::log_event(
                        Operation::Decrypt,
                        &input,
                        enc_size,
                        true,
                        &format!("Відновлено у {:?}", out_path),
                    );
                }
                Err(e) => {
                    eprintln!("Помилка дешифрування: {}", e);
                    AuditLogger::log_event(
                        Operation::Decrypt,
                        &input,
                        enc_size,
                        false,
                        &format!("Відмова автентифікації/помилка: {}", e),
                    );
                    std::process::exit(1);
                }
            }
            pwd.zeroize();
        }
    }
}

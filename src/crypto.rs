use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC_HEADER: &[u8; 4] = b"SENC";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MIN_CONTAINER_LEN: usize = 4 + SALT_LEN + NONCE_LEN + TAG_LEN; // 48 байт
pub const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug)]
pub enum CryptoError {
    InvalidMagic,
    FileTooSmall,
    AuthenticationFailed,
    Io(std::io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidMagic => write!(f, "Невірний формат файлу (відсутня сигнатура SENC)"),
            CryptoError::FileTooSmall => write!(f, "Розмір файлу менший за мінімальний заголовок (48 байт)"),
            CryptoError::AuthenticationFailed => write!(
                f,
                "Автентифікація не вдалася: невірний пароль або файл було пошкоджено/модифіковано"
            ),
            CryptoError::Io(e) => write!(f, "Помилка введення/виведення: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Io(err)
    }
}

/// Деривація 256-бітного симетричного ключа за допомогою PBKDF2-HMAC-SHA-256
fn derive_key(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, &mut *key);
    key
}

/// Автентифіковане шифрування відкритого масиву
pub fn encrypt_data(mut plaintext: Vec<u8>, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut rng = rand::thread_rng();

    // 1. Генерація солі (16 байт) та вектора Nonce (12 байт)
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    // 2. Деривація сеансового ключа
    let key = derive_key(password, &salt);

    // 3. Ініціалізація AES-256-GCM
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4. Додаткові асоційовані дані (AAD) для захисту сигнатури
    let payload = Payload {
        msg: &plaintext,
        aad: MAGIC_HEADER,
    };

    // 5. Шифрування + генерація 16-байтного тегу автентичності
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // Безпечне затирання відкритого тексту
    plaintext.zeroize();

    // 6. Формування двійкового контейнера: [SENC][SALT][NONCE][CIPHERTEXT + TAG]
    let mut container = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + ciphertext.len());
    container.extend_from_slice(MAGIC_HEADER);
    container.extend_from_slice(&salt);
    container.extend_from_slice(&nonce_bytes);
    container.extend_from_slice(&ciphertext);

    Ok(container)
}

/// Автентифіковане дешифрування контейнера
pub fn decrypt_data(container: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // 1. Гранична перевірка розміру
    if container.len() < MIN_CONTAINER_LEN {
        return Err(CryptoError::FileTooSmall);
    }

    // 2. Валідація сигнатури SENC
    if &container[0..4] != MAGIC_HEADER {
        return Err(CryptoError::InvalidMagic);
    }

    // 3. Вилучення солі, nonce та шифротексту
    let salt = &container[4..20];
    let nonce_bytes = &container[20..32];
    let ciphertext_with_tag = &container[32..];

    // 4. Відновлення ключа
    let key = derive_key(password, salt);

    // 5. Дешифрування та поліноміальна верифікація тегу GHASH
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: MAGIC_HEADER,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(plaintext)
}

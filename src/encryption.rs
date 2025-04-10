use std::{fs::OpenOptions, io::Write, path::PathBuf};

use bincode::config;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tenacity_utils::security::{middleware::traits::VersionTrait, TenacityMiddleware, Version};

#[derive(Serialize, Deserialize, Debug)]
pub struct ChipaFile {
    version: Version,
    body: Bytes,
}

#[derive(thiserror::Error, Debug)]
pub enum ChipaError {
    #[error("Encode error, {0}")]
    Encode(String),
    #[error("Decode error, {0}")]
    Decode(String),
    #[error("Encryption error, {0}")]
    Encryption(anyhow::Error),
    #[error("Decryption error, {0}")]
    Decryption(anyhow::Error),
    #[error("File creation error, couldn't create .chipa file, {0}")]
    FileCreation(#[from] std::io::Error),
    #[error("Invalid file format, {0}")]
    InvalidFileFormat(String),
}

type ChipaResult<T> = Result<T, ChipaError>;

impl ChipaFile {
    fn encrypt_body(&self, key: &str) -> ChipaResult<Bytes> {
        let encryptor = self.version.encryptor();
        encryptor.encrypt_bytes(key, &self.body).map_err(ChipaError::Encryption)
    }

    fn decrypt_body(&self, key: &str) -> ChipaResult<Bytes> {
        let encryptor = self.version.encryptor();
        encryptor.decrypt_bytes(key, &self.body).map_err(ChipaError::Decryption)
    }

    pub fn new<T: Serialize>(version: Version, body: &T) -> ChipaResult<Self> {
        let body = bincode::serde::encode_to_vec(body, config::standard()).map_err(|e| ChipaError::Encode(e.to_string()))?;
        Ok(Self { version, body: Bytes::from(body) })
    }

    pub fn save(&self, path: &str, key: &str) -> ChipaResult<Bytes> {
        let mut path = PathBuf::from(path);
        match path.extension()  {
            Some(e) => {
                if e != "chipa" {
                    path.set_extension("chipa");
                }
            },
            None => {
                path.set_extension("chipa");
            }
        }
        let start = bincode::serde::encode_to_vec(u16::from(self.version), config::standard()).map_err(|e| ChipaError::Encode(e.to_string()))?;
        let file = ChipaFile {
            version: self.version,
            body: self.encrypt_body(key)?,
        };
        let data = bincode::serde::encode_to_vec(file, config::standard()).map_err(|e| ChipaError::Encode(e.to_string()))?;
        let data_encrypted = self.version.base_encrypt_bytes(&data).map_err(ChipaError::Encryption)?;
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        file.write_all(start.as_slice())?;
        file.write_all(data_encrypted.as_ref())?;
        file.flush()?;
        Ok(data_encrypted)
    }

    pub fn load(path: &str, key: &str) -> ChipaResult<Self> {
        let path = PathBuf::from(path);
        match path.extension()  {
            Some(e) => 
                if e != "chipa" {
                    return Err(ChipaError::InvalidFileFormat(format!("Expected file to end with .chipa, found '{:?}'", e)));
                }
            ,
            None => return Err(ChipaError::InvalidFileFormat("Expected file to end with .chipa, found 'none'".to_string())),
        }
        let mut file = std::fs::read(path)?;
        if file.len() < 2 {
            return Err(ChipaError::InvalidFileFormat("File is too small".to_string()));
        }        
        let (version, _): (u16, usize) = bincode::serde::decode_from_slice(file.drain(..2).as_slice(), config::standard()).map_err(|e| ChipaError::Decode(e.to_string()))?;
        let version = Version::try_from(version).map_err(ChipaError::Decryption)?;
        let slice = version.base_decrypt_bytes(file.as_slice()).map_err(ChipaError::Decryption)?;
        let (chipa_file, _): (ChipaFile, _) = bincode::serde::decode_from_slice(slice.as_ref(), config::standard()).map_err(|e| ChipaError::Decode(e.to_string()))?;
        let chipa_file = ChipaFile { 
            version: chipa_file.version,
            body: chipa_file.decrypt_body(key)?,
        };
        Ok(chipa_file)
    }

    pub fn read<T: DeserializeOwned>(&self) -> ChipaResult<T> {
        let (data, _) = bincode::serde::decode_from_slice(self.body.as_ref(), config::standard()).map_err(|e| ChipaError::Decode(e.to_string()))?;
        Ok(data)
    }

    pub fn write<T: Serialize>(&mut self, data: &T) -> ChipaResult<()> {
        let data = bincode::serde::encode_to_vec(data, config::standard()).map_err(|e| ChipaError::Encode(e.to_string()))?;
        self.body = Bytes::from(data);
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use bincode::config::{Config, Configuration};

    use super::*;
    
    #[test]
    fn test_different_data_types() {
        let file_path = "test_types.chipa";
        let key = "test_key_123";

        // Test with String
        let string_data = "Hello, World!".to_string();
        let chipa_file = ChipaFile::new(Version::V1, &string_data).unwrap();
        let data = chipa_file.save(file_path, key).unwrap();
        let decrypted = Version::V1.base_decrypt_bytes(&data).unwrap();
        let (pseudo, _) = dbg!(bincode::serde::decode_from_slice::<ChipaFile, Configuration>(decrypted.as_ref(), config::standard()).unwrap());
        let enc = Version::V1.encryptor();
        dbg!(enc.decrypt_bytes(key, pseudo.body.as_ref()));
        let loaded_file = ChipaFile::load(file_path, key).unwrap();
        let loaded_string: String = loaded_file.read().unwrap();
        assert_eq!(loaded_string, string_data);

        // Test with Vec<i32>
        let vec_data = vec![1, 2, 3, 4, 5];
        let chipa_file = ChipaFile::new(Version::V1, &vec_data).unwrap();
        chipa_file.save(file_path, key).unwrap();
        
        let loaded_file = ChipaFile::load(file_path, key).unwrap();
        let loaded_vec: Vec<i32> = loaded_file.read().unwrap();
        assert_eq!(loaded_vec, vec_data);

        // Cleanup
        // std::fs::remove_file(file_path)?;

    }

    #[test]
    fn test_check() {
        let  mut arr = vec![1, 2, 3, 4, 5];
        println!("{:?}", arr.drain(..2).as_slice());
        println!("{:?}", arr);
    }

}
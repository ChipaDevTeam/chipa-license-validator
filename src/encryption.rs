use std::{fs::OpenOptions, io::Write, path::PathBuf};

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
        encryptor
            .encrypt_bytes(key, &self.body)
            .map_err(ChipaError::Encryption)
    }

    fn decrypt_body(&self, key: &str) -> ChipaResult<Bytes> {
        let encryptor = self.version.encryptor();
        encryptor
            .decrypt_bytes(key, &self.body)
            .map_err(ChipaError::Decryption)
    }

    pub fn new<T: Serialize>(version: Version, body: &T) -> ChipaResult<Self> {
        let body = rmp_serde::to_vec(body)
            .map_err(|e| ChipaError::Encode(e.to_string()))?;
        Ok(Self {
            version,
            body: Bytes::from(body),
        })
    }

    pub fn save(&self, path: &str, key: &str) -> ChipaResult<()> {
        let mut path = PathBuf::from(path);
        match path.extension() {
            Some(e) => {
                if e != "chipa" {
                    path.set_extension("chipa");
                }
            }
            None => {
                path.set_extension("chipa");
            }
        }
        let start = u16::from(self.version).to_be_bytes();
        let file = ChipaFile {
            version: self.version,
            body: self.encrypt_body(key)?,
        };
        let data = rmp_serde::encode::to_vec(&file)
            .map_err(|e| ChipaError::Encode(e.to_string()))?;
        let data_encrypted = self
            .version
            .base_encrypt_bytes(&data)
            .map_err(ChipaError::Encryption)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.write_all(start.as_slice())?;
        file.flush()?;
        file.write_all(data_encrypted.as_ref())?;
        file.flush()?;
        Ok(())
    }

    pub fn load(path: &str, key: &str) -> ChipaResult<Self> {
        let path = PathBuf::from(path);
        match path.extension() {
            Some(e) => {
                if e != "chipa" {
                    return Err(ChipaError::InvalidFileFormat(format!(
                        "Expected file to end with .chipa, found '{:?}'",
                        e
                    )));
                }
            }
            None => {
                return Err(ChipaError::InvalidFileFormat(
                    "Expected file to end with .chipa, found 'none'".to_string(),
                ))
            }
        }
        let file = std::fs::read(path)?;
        if file.len() < 2 {
            return Err(ChipaError::InvalidFileFormat(
                "File is too small".to_string(),
            ));
        }
        let version: u16 = file[0] as u16 * 256  + file[1] as u16;
        let version = Version::try_from(version).map_err(ChipaError::Decryption)?;
        let slice = version
            .base_decrypt_bytes(&file[2..])
            .map_err(ChipaError::Decryption)?;
        let chipa_file: ChipaFile =
            rmp_serde::from_slice(slice.as_ref())
                .map_err(|e| ChipaError::Decode(e.to_string()))?;
        let chipa_file = ChipaFile {
            version: chipa_file.version,
            body: chipa_file.decrypt_body(key)?,
        };
        Ok(chipa_file)
    }

    pub fn read<T: DeserializeOwned>(&self) -> ChipaResult<T> {
        let data= rmp_serde::from_slice(self.body.as_ref())
            .map_err(|e| ChipaError::Decode(e.to_string()))?;
        Ok(data)
    }

    pub fn write<T: Serialize>(&mut self, data: &T) -> ChipaResult<()> {
        let data = rmp_serde::to_vec(data)
            .map_err(|e| ChipaError::Encode(e.to_string()))?;
        self.body = Bytes::from(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use bincode::config::{Config, Configuration};

    use serde_json::{json, Value};
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet, LinkedList, VecDeque},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        num::{
            NonZeroI128, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI8, NonZeroU128, NonZeroU16,
            NonZeroU32, NonZeroU64, NonZeroU8,
        },
        path::PathBuf,
        time::Duration,
    };
    use uuid::Uuid;

    use super::*;

    #[test]
    fn test_different_data_types() {
        let file_path = "test_types.chipa";
        let key = "test_key_123";

        // Test with String
        let string_data = "Hello, World!".to_string();
        let chipa_file = ChipaFile::new(Version::V1, &string_data).unwrap();
        chipa_file.save(file_path, key).unwrap();
        // let decrypted = Version::V1.base_decrypt_bytes(&data).unwrap();
        // let (pseudo, _) = dbg!(bincode::serde::decode_from_slice::<ChipaFile, Configuration>(decrypted.as_ref(), config::standard()).unwrap());
        // let enc = Version::V1.encryptor();
        let loaded_file = ChipaFile::load(file_path, key).unwrap();
        let loaded_string: String = loaded_file.read().unwrap();
        println!("Loaded String: {}", loaded_string);
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


    fn complex() -> Value {
        json!({
            "company": {
                "name": "TechCorp Industries",
                "founded": 1995,
                "active": true,
                "stock_price": 156.78,
                "headquarters": {
                    "address": "123 Innovation Way",
                    "city": "Silicon Valley",
                    "country": "USA",
                    "coordinates": {
                        "latitude": 37.7749,
                        "longitude": -122.4194
                    }
                }
            },
            "employees": [
                {
                    "id": 1,
                    "name": "John Doe",
                    "title": "Senior Developer",
                    "department": "Engineering",
                    "skills": ["Rust", "Python", "DevOps"],
                    "projects": [
                        {
                            "name": "Project Alpha",
                            "status": "completed",
                            "duration_months": 6,
                            "team_size": 8
                        },
                        {
                            "name": "Project Beta",
                            "status": "in_progress",
                            "duration_months": 3,
                            "team_size": 5
                        }
                    ],
                    "contact": {
                        "email": "john.doe@techcorp.com",
                        "phone": "+1-555-0123",
                        "emergency": {
                            "name": "Jane Doe",
                            "relationship": "spouse",
                            "phone": "+1-555-0124"
                        }
                    }
                },
                {
                    "id": 2,
                    "name": "Alice Smith",
                    "title": "Product Manager",
                    "department": "Product",
                    "skills": ["Strategy", "Agile", "Leadership"],
                    "projects": [
                        {
                            "name": "Project Gamma",
                            "status": "planning",
                            "duration_months": 12,
                            "team_size": 15
                        }
                    ],
                    "contact": {
                        "email": "alice.smith@techcorp.com",
                        "phone": "+1-555-0125",
                        "emergency": {
                            "name": "Bob Smith",
                            "relationship": "partner",
                            "phone": "+1-555-0126"
                        }
                    }
                }
            ],
            "metrics": {
                "revenue": {
                    "2021": 1500000.00,
                    "2022": 2300000.00,
                    "2023": 3100000.00
                },
                "growth_rate": 34.5,
                "departments": {
                    "Engineering": {
                        "headcount": 50,
                        "budget": 5000000,
                        "projects_completed": 12
                    },
                    "Product": {
                        "headcount": 20,
                        "budget": 2000000,
                        "projects_completed": 8
                    },
                    "Marketing": {
                        "headcount": 15,
                        "budget": 1500000,
                        "projects_completed": 6
                    }
                }
            },
            "settings": {
                "notifications": {
                    "email": true,
                    "slack": true,
                    "sms": false
                },
                "security": {
                    "two_factor": true,
                    "ip_whitelist": ["192.168.1.1", "10.0.0.1"],
                    "allowed_domains": ["techcorp.com", "tech-corp.org"]
                },
                "system": {
                    "backup_frequency": "daily",
                    "retention_days": 90,
                    "maintenance_windows": [
                        {"day": "Sunday", "time": "02:00", "duration": 120},
                        {"day": "Wednesday", "time": "03:00", "duration": 60}
                    ]
                }
            },
            "metadata": {
                "last_updated": "2024-01-20T15:30:00Z",
                "version": "2.1.0",
                "generated_by": "system",
                "tags": ["corporate", "confidential", "2024"],
                "flags": {
                    "beta_features": true,
                    "maintenance_mode": false,
                    "read_only": false
                }
            }
        })
    }

    #[test]
    fn test_complex_json() {
        let file_path = "test_complex.chipa";
        let key = "test_key_123";

        // Create and save complex JSON
        let chipa_file = ChipaFile::new(Version::V1, &complex()).unwrap();
        chipa_file.save(file_path, key).unwrap();
        // Load and verify
        let loaded_file = ChipaFile::load(file_path, "test_key_123").unwrap();
        let loaded_data: Value = loaded_file.read().unwrap();
        // Verify specific nested values
        dbg!(complex().to_string().len());
        dbg!(std::fs::read(file_path).unwrap().len());

        assert_eq!(loaded_data["company"]["name"], "TechCorp Industries");
        assert_eq!(loaded_data["employees"][0]["name"], "John Doe");
        assert_eq!(loaded_data["metrics"]["revenue"]["2023"], 3100000.00);
        assert_eq!(
            loaded_data["settings"]["security"]["ip_whitelist"][1].as_str().unwrap(),
            "10.0.0.1"
        );
        assert_eq!(
            loaded_data["employees"][1]["contact"]["emergency"]["relationship"],
            "partner"
        );

        // Verify array lengths
        assert_eq!(loaded_data["employees"].as_array().unwrap().len(), 2);
        assert_eq!(
            loaded_data["employees"][0]["skills"].as_array().unwrap().len(),
            3
        );

        // Verify numeric values
        assert_eq!(
            loaded_data["metrics"]["departments"]["Engineering"]["budget"].as_i64().unwrap(),
            5000000
        );
        assert_eq!(
            loaded_data["metrics"]["growth_rate"].as_f64().unwrap(),
            34.5
        );

        // Cleanup
        // let _ = std::fs::remove_file(file_path);
    }

    const TEST_FILE_PATH: &str = "chipa/test_data.chipa";
    const TEST_PRIMITIVE_PATH: &str = "chipa/test_primitive.chipa";
    const TEST_COMPOUND_PATH: &str = "chipa/test_compound_types.chipa";
    const TEST_STANDARD_PATH: &str = "chipa/test_standard_types.chipa";
    const TEST_NON_ZERO_PATH: &str = "chipa/test_non_zero_types.chipa";
    const TEST_STRUCT_PATH: &str = "chipa/test_struct.chipa";
    const TEST_ENUM_PATH: &str = "chipa/test_enum.chipa";
    const TEST_KEY: &str = "test_encryption_key";

    fn cleanup_file() {
        let _ = std::fs::remove_file(TEST_FILE_PATH);
    }

    // Helper function to perform the save and load test
    fn test_serde_roundtrip<T>(path: &str, data: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug + 'static,
    {
        cleanup_file();

        let chipa_file = ChipaFile::new(Version::V1, data).unwrap();
        chipa_file.save(path, TEST_KEY).unwrap();

        let loaded_file = ChipaFile::load(path, TEST_KEY).unwrap();
        let loaded_data: T = loaded_file.read().unwrap();

        assert_eq!(data, &loaded_data);

        cleanup_file();
    }

    #[test]
    fn test_primitive_types() {
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &true);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &false);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123i8);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &-123i8);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123u8);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123i16);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &-123i16);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123u16);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123i32);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &-123i32);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123u32);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123i64);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &-123i64);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123u64);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123i128);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &-123i128);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123u128);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123.456f32);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &123.456f64);
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &'a');
        test_serde_roundtrip(TEST_PRIMITIVE_PATH, &"hello".to_string());
    }

    #[test]
    fn test_compound_types() {
        test_serde_roundtrip(TEST_COMPOUND_PATH, &[1, 2, 3]);
        test_serde_roundtrip(TEST_COMPOUND_PATH, &vec![1, 2, 3]);
        test_serde_roundtrip(TEST_COMPOUND_PATH, &("hello".to_string(), 123));
        test_serde_roundtrip(TEST_COMPOUND_PATH, &Some("world".to_string()));
        test_serde_roundtrip(TEST_COMPOUND_PATH, &None::<String>);
        let mut map = HashMap::new();
        map.insert("key1".to_string(), 1);
        map.insert("key2".to_string(), 2);
        test_serde_roundtrip(TEST_COMPOUND_PATH, &map);
        let mut set = HashSet::new();
        set.insert(1);
        set.insert(2);
        test_serde_roundtrip(TEST_COMPOUND_PATH, &set);
        test_serde_roundtrip(TEST_COMPOUND_PATH, &BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)]));
        test_serde_roundtrip(TEST_COMPOUND_PATH, &BTreeSet::from([1, 2, 3]));
        test_serde_roundtrip(TEST_COMPOUND_PATH, &LinkedList::from([1, 2, 3]));
        test_serde_roundtrip(TEST_COMPOUND_PATH, &VecDeque::from([1, 2, 3]));
    } 

    #[test]
    fn test_other_standard_types() {
        test_serde_roundtrip(TEST_STANDARD_PATH, &Bytes::from_static(b"some bytes"));
        test_serde_roundtrip(TEST_STANDARD_PATH, &PathBuf::from("a/b/c"));
        test_serde_roundtrip(TEST_STANDARD_PATH, &Duration::from_secs(60));
        // Cannot directly test Instant or SystemTime due to their nature
        test_serde_roundtrip(TEST_STANDARD_PATH, &Uuid::new_v4());
        test_serde_roundtrip(TEST_STANDARD_PATH, &IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        test_serde_roundtrip(TEST_STANDARD_PATH, &IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff,
        )));
        test_serde_roundtrip(TEST_STANDARD_PATH, &SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        )));
        test_serde_roundtrip(TEST_STANDARD_PATH, &SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
            8081,
            0,
            0,
        )));
    }

    #[test]
    fn test_non_zero_types() {
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroI8::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroU8::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroI16::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroU16::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroI32::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroU32::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroI64::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroU64::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroI128::new(1).unwrap());
        test_serde_roundtrip(TEST_NON_ZERO_PATH, &NonZeroU128::new(1).unwrap());
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct CustomStruct {
        name: String,
        age: u32,
        data: Vec<i32>,
    }

    #[test]
    fn test_custom_struct() {
        let custom_data = CustomStruct {
            name: "Test Struct".to_string(),
            age: 30,
            data: vec![10, 20, 30],
        };
        test_serde_roundtrip(TEST_STRUCT_PATH, &custom_data);
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum CustomEnum {
        A,
        B(i32),
        C { value: String },
    }

    #[test]
    fn test_custom_enum() {
        test_serde_roundtrip(TEST_ENUM_PATH, &CustomEnum::A);
        test_serde_roundtrip(TEST_ENUM_PATH, &CustomEnum::B(42));
        test_serde_roundtrip(TEST_ENUM_PATH, &CustomEnum::C {
            value: "hello".to_string(),
        });
    }
}

use half::f16;

use crate::error::CrownError;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 0xF4;
const SIMPLE_TRUE: u8 = 0xF5;
const SIMPLE_NULL: u8 = 0xF6;

#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(String, CborValue)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl CborValue {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        write_value(self, &mut out);
        out
    }
}

fn write_value(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Uint(number) => write_head(MAJOR_UINT, *number, out),
        CborValue::Bytes(bytes) => {
            write_head(MAJOR_BYTES, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            let bytes = text.as_bytes();
            write_head(MAJOR_TEXT, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Array(items) => {
            write_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                write_value(item, out);
            }
        }
        CborValue::Map(pairs) => {
            write_head(MAJOR_MAP, pairs.len() as u64, out);
            let mut indices: Vec<usize> = (0..pairs.len()).collect();
            let encoded_keys: Vec<Vec<u8>> = pairs
                .iter()
                .map(|(key, _)| {
                    let mut buf = Vec::with_capacity(key.len() + 2);
                    let bytes = key.as_bytes();
                    write_head(MAJOR_TEXT, bytes.len() as u64, &mut buf);
                    buf.extend_from_slice(bytes);
                    buf
                })
                .collect();
            indices.sort_by(|left, right| encoded_keys[*left].cmp(&encoded_keys[*right]));
            for index in indices {
                out.extend_from_slice(&encoded_keys[index]);
                write_value(&pairs[index].1, out);
            }
        }
        CborValue::Bool(true) => out.push(SIMPLE_TRUE),
        CborValue::Bool(false) => out.push(SIMPLE_FALSE),
        CborValue::Null => out.push(SIMPLE_NULL),
        CborValue::Float(number) => write_float(*number, out),
    }
}

fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    if arg < 24 {
        out.push(prefix | (arg as u8));
    } else if arg <= 0xFF {
        out.push(prefix | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(prefix | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(prefix | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn write_float(number: f64, out: &mut Vec<u8>) {
    assert!(number.is_finite(), "non-finite floats are not supported");

    let half = f16::from_f64(number);
    if half.to_f64() == number {
        out.push((MAJOR_SIMPLE << 5) | 25);
        out.extend_from_slice(&half.to_bits().to_be_bytes());
        return;
    }

    let single = number as f32;
    if (single as f64) == number {
        out.push((MAJOR_SIMPLE << 5) | 26);
        out.extend_from_slice(&single.to_bits().to_be_bytes());
        return;
    }

    out.push((MAJOR_SIMPLE << 5) | 27);
    out.extend_from_slice(&number.to_bits().to_be_bytes());
}

pub fn decode(bytes: &[u8]) -> Result<CborValue, CrownError> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let value = read_value(&mut cursor)?;
    if cursor.pos != bytes.len() {
        return Err(CrownError::Decode(format!(
            "trailing bytes at offset {}",
            cursor.pos
        )));
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], CrownError> {
        if self.pos + count > self.bytes.len() {
            return Err(CrownError::Decode("unexpected eof".to_string()));
        }

        let slice = &self.bytes[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, CrownError> {
        Ok(self.take(1)?[0])
    }
}

fn read_value(cursor: &mut Cursor<'_>) -> Result<CborValue, CrownError> {
    let first = cursor.take_u8()?;
    let major = first >> 5;
    let info = first & 0x1F;

    if first == SIMPLE_TRUE {
        return Ok(CborValue::Bool(true));
    }
    if first == SIMPLE_FALSE {
        return Ok(CborValue::Bool(false));
    }
    if first == SIMPLE_NULL {
        return Ok(CborValue::Null);
    }

    if major == MAJOR_SIMPLE {
        return read_float(cursor, info);
    }

    let arg = read_arg(cursor, info)?;
    match major {
        MAJOR_UINT => Ok(CborValue::Uint(arg)),
        MAJOR_BYTES => Ok(CborValue::Bytes(cursor.take(arg as usize)?.to_vec())),
        MAJOR_TEXT => {
            let bytes = cursor.take(arg as usize)?.to_vec();
            let text = String::from_utf8(bytes)
                .map_err(|error| CrownError::Decode(format!("invalid utf8: {error}")))?;
            Ok(CborValue::Text(text))
        }
        MAJOR_ARRAY => {
            let mut items = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                items.push(read_value(cursor)?);
            }
            Ok(CborValue::Array(items))
        }
        MAJOR_MAP => {
            let mut pairs = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                let key = read_value(cursor)?;
                let value = read_value(cursor)?;
                match key {
                    CborValue::Text(text) => pairs.push((text, value)),
                    _ => {
                        return Err(CrownError::Decode(
                            "non-text map keys are not supported".to_string(),
                        ))
                    }
                }
            }
            Ok(CborValue::Map(pairs))
        }
        _ => Err(CrownError::Decode(format!(
            "unsupported major type {major}"
        ))),
    }
}

fn read_arg(cursor: &mut Cursor<'_>, info: u8) -> Result<u64, CrownError> {
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => {
            let value = u64::from(cursor.take_u8()?);
            if value < 24 {
                return Err(CrownError::Decode("non-canonical integer head".to_string()));
            }
            Ok(value)
        }
        25 => {
            let bytes = cursor.take(2)?;
            let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            if value <= 0xFF {
                return Err(CrownError::Decode("non-canonical integer head".to_string()));
            }
            Ok(value)
        }
        26 => {
            let bytes = cursor.take(4)?;
            let value = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            if value <= 0xFFFF {
                return Err(CrownError::Decode("non-canonical integer head".to_string()));
            }
            Ok(value)
        }
        27 => {
            let bytes = cursor.take(8)?;
            let value = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if value <= 0xFFFF_FFFF {
                return Err(CrownError::Decode("non-canonical integer head".to_string()));
            }
            Ok(value)
        }
        _ => Err(CrownError::Decode(format!(
            "reserved info value {info} not allowed in canonical cbor"
        ))),
    }
}

fn read_float(cursor: &mut Cursor<'_>, info: u8) -> Result<CborValue, CrownError> {
    match info {
        25 => {
            let bytes = cursor.take(2)?;
            let bits = u16::from_be_bytes([bytes[0], bytes[1]]);
            Ok(CborValue::Float(f16::from_bits(bits).to_f64()))
        }
        26 => {
            let bytes = cursor.take(4)?;
            let number =
                f32::from_bits(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            if !number.is_finite() {
                return Err(CrownError::Decode(
                    "non-finite floats are not supported".to_string(),
                ));
            }
            let as_f64 = number as f64;
            let half = f16::from_f64(as_f64);
            if half.to_f64() == as_f64 {
                return Err(CrownError::Decode(
                    "non-canonical float encoding".to_string(),
                ));
            }
            Ok(CborValue::Float(as_f64))
        }
        27 => {
            let bytes = cursor.take(8)?;
            let number = f64::from_bits(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]));
            if !number.is_finite() {
                return Err(CrownError::Decode(
                    "non-finite floats are not supported".to_string(),
                ));
            }
            let half = f16::from_f64(number);
            let single = number as f32;
            if half.to_f64() == number || (single as f64) == number {
                return Err(CrownError::Decode(
                    "non-canonical float encoding".to_string(),
                ));
            }
            Ok(CborValue::Float(number))
        }
        _ => Err(CrownError::Decode(format!(
            "unsupported simple value {info}"
        ))),
    }
}

pub fn to_canonical_json(value: &CborValue) -> String {
    let json = to_json_value(value);
    serde_json::to_string(&json).expect("known JSON value should serialize")
}

fn to_json_value(value: &CborValue) -> serde_json::Value {
    match value {
        CborValue::Uint(number) => serde_json::Value::Number((*number).into()),
        CborValue::Bytes(bytes) => serde_json::Value::String(hex::encode(bytes)),
        CborValue::Text(text) => serde_json::Value::String(text.clone()),
        CborValue::Array(items) => {
            serde_json::Value::Array(items.iter().map(to_json_value).collect())
        }
        CborValue::Map(pairs) => {
            let mut sorted = pairs.clone();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));

            let mut map = serde_json::Map::with_capacity(sorted.len());
            for (key, value) in sorted {
                map.insert(key, to_json_value(&value));
            }
            serde_json::Value::Object(map)
        }
        CborValue::Bool(boolean) => serde_json::Value::Bool(*boolean),
        CborValue::Null => serde_json::Value::Null,
        CborValue::Float(number) => serde_json::Value::Number(
            serde_json::Number::from_f64(*number).expect("finite float should serialize"),
        ),
    }
}

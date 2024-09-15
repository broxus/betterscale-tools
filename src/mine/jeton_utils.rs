use anyhow::anyhow;
use anyhow::Result;
use num_bigint::BigUint;
use num_traits::Zero;
use ton_block::MsgAddressInt;
use ton_types::{BuilderData, Cell, IBitstring, SliceData, UInt256};
pub trait IBitstringExt: IBitstring {
    fn append_raw_address(&mut self, val: &MsgAddressInt) -> anyhow::Result<&mut Self>;

    /// Stores address optimizing hole address two to bits
    fn append_address(&mut self, val: &MsgAddressInt) -> anyhow::Result<&mut Self>;

    fn append_uint(&mut self, val: &BigUint, bit_len: usize) -> anyhow::Result<&mut Self>;
    fn append_coins(&mut self, val: &BigUint) -> anyhow::Result<&mut Self>;
}

impl IBitstringExt for BuilderData {
    fn append_raw_address(&mut self, val: &MsgAddressInt) -> anyhow::Result<&mut Self> {
        self.append_bits(0b10u8 as usize, 2)?;
        self.append_bit_bool(false)?;
        let wc = (val.workchain_id() & 0xff) as u8;
        self.append_u8(wc)?;
        let _x = val.address().get_bytestring(0);
        for byte in _x {
            self.append_u8(byte).unwrap();
        }
        Ok(self)
    }
    fn append_address(&mut self, val: &MsgAddressInt) -> anyhow::Result<&mut Self> {
        if *val == MsgAddressInt::with_variant(None, 0, SliceData::from([0; 32])).unwrap() {
            self.append_bits(0, 2)
        } else {
            self.append_raw_address(val)
        }
    }

    fn append_uint(&mut self, val: &BigUint, bit_len: usize) -> anyhow::Result<&mut Self> {
        if val.bits() as usize > bit_len {
            return Err(anyhow!(format!(
                "Value {} doesn't fit in {} bits",
                val, bit_len
            )));
        }
        let bytes = val.to_bytes_be();
        let num_full_bytes = bit_len / 8;
        let num_bits_in_high_byte = bit_len % 8;
        if bytes.len() > num_full_bytes + 1 {
            return Err(anyhow!(format!(
                "Internal Error: Value {} doesn't fit in {} bits",
                val, bit_len
            )));
        }
        if num_bits_in_high_byte > 0 {
            let high_byte: usize = if bytes.len() == num_full_bytes + 1 {
                bytes[0] as usize
            } else {
                0
            };
            self.append_bits(high_byte, num_bits_in_high_byte)?;
        }
        let num_empty_bytes = num_full_bytes - bytes.len();
        for _ in 0..num_empty_bytes {
            self.append_u8(0)?;
        }
        for b in bytes {
            self.append_u8(b)?;
        }
        Ok(self)
    }

    fn append_coins(&mut self, val: &BigUint) -> anyhow::Result<&mut Self> {
        // let val = BigUint::from_bytes_be(val.as_array());
        if val.is_zero() {
            self.append_bits(0, 4)
        } else {
            let num_bytes = (val.bits() as usize + 7) / 8;
            self.append_bits(num_bytes, 4)?;
            self.append_uint(&val, num_bytes * 8)
        }
    }
}

pub fn make_state_init(code: Cell, data: Cell) -> Result<ton_block::StateInit> {
    Ok(ton_block::StateInit {
        code: Some(code),
        data: Some(data),
        ..Default::default()
    })
}

pub fn cell_from_base_64(base64: &str) -> Result<Cell> {
    let bytes = base64::decode(base64)?;
    Ok(ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?)
}

pub fn cell_from_hex(hex: &str) -> Result<Cell> {
    let bytes = hex::decode(hex)?;
    Ok(ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?)
}

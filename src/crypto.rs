use aes::cipher::{
    generic_array::GenericArray, typenum, BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit,
};

pub type GenericArray16 = GenericArray<u8, typenum::U16>;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_128_KEY_SIZE: usize = 16;

type Aes128Decrypt = cbc::Decryptor<aes::Aes128Dec>;
type Padding = cbc::cipher::block_padding::Pkcs7;

/// Take a key and a mutable array of 16 byte chunks and decrypt the data in place.
///
/// This method does not allow setting an IV. If this is needed, then use [`decrypt_aes_with_iv`].
#[inline]
pub fn decrypt_aes(
    key: &[u8; AES_128_KEY_SIZE],
    data: &mut [GenericArray16],
) -> Result<(), aes::cipher::InvalidLength> {
    let cipher = aes::Aes128::new_from_slice(key)?;
    cipher.decrypt_blocks(data);

    Ok(())
}

/// Take a key, an IV and a mutable array of 16 byte chunks and decrypt the data in place.
///
/// This method returns the un-padded data as a slice, along with modifying the original slice
#[inline]
pub fn decrypt_aes_with_iv<'a>(
    key: &GenericArray16,
    iv: &GenericArray16,
    data: &'a mut [u8],
) -> Result<&'a [u8], cbc::cipher::block_padding::UnpadError> {
    let decryptor = Aes128Decrypt::new(key, iv);
    decryptor.decrypt_padded_mut::<Padding>(data)
}

#[cfg(test)]
mod test {
    use aes::cipher::{
        generic_array::GenericArray, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
    };

    use crate::crypto::{AES_BLOCK_SIZE, AES_128_KEY_SIZE};

    use super::{decrypt_aes, decrypt_aes_with_iv, Padding};

    #[test]
    fn test_decrypt() {
        let key = [1u8; AES_128_KEY_SIZE];
        let chipher = aes::Aes128::new_from_slice(&key).unwrap();

        let data = [[0u8; AES_BLOCK_SIZE]; 4];
        let mut data = data
            .into_iter()
            .map(|v| GenericArray::from(v))
            .collect::<Vec<_>>();
        let data = data.as_mut_slice();
        chipher.encrypt_blocks(data);

        decrypt_aes(&key, data).unwrap();
        let data = data.into_iter().flatten().map(|v| *v).collect::<Vec<_>>();

        assert_eq!(data, vec![0u8; 64])
    }

    #[test]
    fn test_decrypt_with_iv() {
        let key = GenericArray::from([1u8; AES_128_KEY_SIZE]);
        let iv = GenericArray::from([2u8; AES_128_KEY_SIZE]);
        let encryptor: cbc::Encryptor<aes::Aes128Enc> = cbc::Encryptor::new(&key, &iv);

        let plaintext_bytes = b"Hello, world!";

        let mut data = [0u8; 16];
        data[0..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);

        let _ = encryptor
            .encrypt_padded_mut::<Padding>(&mut data, plaintext_bytes.len())
            .unwrap();

        let decrypted = decrypt_aes_with_iv(&key, &iv, &mut data).unwrap();

        assert_eq!(decrypted, plaintext_bytes)
    }
}

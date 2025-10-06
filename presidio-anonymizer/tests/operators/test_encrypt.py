from unittest import mock
import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": b"1111111111111111"})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    # 16-char string -> 128-bit key
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    # 16-byte key -> 128-bit key
    Encrypt().validate(params={"key": b"1111111111111111"})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        # Too short string -> invalid length
        Encrypt().validate(params={"key": "key"})


# ---- REQUIRED FIXED TEST (correct patch target, renamed mock var, return_value set) ----
@mock.patch.object(AESCipher, "get_key_bytes")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_get_key_bytes):
    """
    Ensure that when a bytes key ultimately resolves to an invalid length (not 16/24/32),
    validate() raises InvalidParamError. We force this by making get_key_bytes return 1 byte.
    """
    # Make validate() see an invalid-length key (1 byte instead of 16/24/32)
    mock_get_key_bytes.return_value = b"x"

    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        # The provided key is valid length, but validate() uses the mocked value above
        Encrypt().validate(params={"key": b"1111111111111111"})


def test_operator_name():
    operator = Encrypt()
    assert operator.operator_name() == "encrypt"


def test_operator_type():
    operator = Encrypt()
    op_type = operator.operator_type()
    # Works whether operator_type returns an Enum or a plain string
    assert (getattr(op_type, "name", op_type)) == "Anonymize"


# ---- Black-box test for valid keys (strings & bytes) ----
@pytest.mark.parametrize(
    "key",
    [
        # String keys
        "A" * 16,  # 128 bits
        "B" * 24,  # 192 bits
        "C" * 32,  # 256 bits
        # Bytes keys
        b"A" * 16,  # 128 bits
        b"B" * 24,  # 192 bits
        b"C" * 32,  # 256 bits
    ],
)
def test_valid_keys(key):
    """Validate should succeed for string/bytes keys of valid bit lengths."""
    Encrypt().validate(params={"key": key})

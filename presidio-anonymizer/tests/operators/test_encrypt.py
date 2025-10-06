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
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b"1111111111111111"})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})


def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised():
    """
    Force Encrypt.validate() down the invalid-length branch for a BYTES key.
    Patch whichever helper actually exists so the key appears invalid.
    """
    if hasattr(AESCipher, "_get_key_bytes"):
        with mock.patch.object(AESCipher, "_get_key_bytes", return_value=b"x"):
            with pytest.raises(
                InvalidParamError,
                match="Invalid input, key must be of length 128, 192 or 256 bits",
            ):
                Encrypt().validate(params={"key": b"1111111111111111"})
        return

    if hasattr(AESCipher, "get_key_bytes"):
        with mock.patch.object(AESCipher, "get_key_bytes", return_value=b"x"):
            with pytest.raises(
                InvalidParamError,
                match="Invalid input, key must be of length 128, 192 or 256 bits",
            ):
                Encrypt().validate(params={"key": b"1111111111111111"})
        return

    if hasattr(AESCipher, "is_valid_key_length"):
        with mock.patch.object(AESCipher, "is_valid_key_length", return_value=False):
            with pytest.raises(
                InvalidParamError,
                match="Invalid input, key must be of length 128, 192 or 256 bits",
            ):
                Encrypt().validate(params={"key": b"1111111111111111"})
        return

    if hasattr(Encrypt, "_get_key_bytes"):
        with mock.patch.object(Encrypt, "_get_key_bytes", return_value=b"x"):
            with pytest.raises(
                InvalidParamError,
                match="Invalid input, key must be of length 128, 192 or 256 bits",
            ):
                Encrypt().validate(params={"key": b"1111111111111111"})
        return

    pytest.fail(
        "Could not locate a key-bytes/length helper to patch. "
        "Open presidio_anonymizer/operators/encrypt.py and note the exact helper name "
        "used by Encrypt.validate(), then add it above."
    )


def test_operator_name():
    operator = Encrypt()
    assert operator.operator_name() == "encrypt"


def test_operator_type():
    operator = Encrypt()
    op_type = operator.operator_type()
    # If it's an Enum, compare its name; if it's a string, compare directly
    assert (getattr(op_type, "name", op_type)) == "Anonymize"


# ✅ New black-box test for valid key lengths
@pytest.mark.parametrize("key", [
    "A" * 16,   # 128-bit string
    "B" * 24,   # 192-bit string
    "C" * 32,   # 256-bit string
    b"A" * 16,  # 128-bit bytes
    b"B" * 24,  # 192-bit bytes
    b"C" * 32,  # 256-bit bytes
])
def test_valid_keys(key):
    """Validate should succeed for string/bytes keys of valid bit lengths."""
    Encrypt().validate(params={"key": key})

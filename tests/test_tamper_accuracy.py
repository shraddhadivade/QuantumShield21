
from backend.crypto.aes_gcm import AES256GCMCipher, TamperDetectedException

def test_tamper_detection_rate():
    session_key = b"\x02" * 32
    cipher = AES256GCMCipher(session_key)

    total_attacks = 100
    detected_attacks = 0

    for i in range(total_attacks):
        payload = cipher.encrypt(f"Secret message {i}")

        tampered = bytearray(payload.ciphertext)
        tampered[0] ^= 0x01

        try:
            cipher.decrypt(
                payload.nonce,
                bytes(tampered),
                payload.tag
            )
        except TamperDetectedException:
            detected_attacks += 1

    detection_rate = (detected_attacks / total_attacks) * 100

    print("\n===== QUANTUMSHIELD TAMPER TEST =====")
    print(f"Total attacks: {total_attacks}")
    print(f"Detected attacks: {detected_attacks}")
    print(f"Undetected attacks: {total_attacks - detected_attacks}")
    print(f"Tamper detection rate: {detection_rate:.2f}%")

    assert detected_attacks == total_attacks

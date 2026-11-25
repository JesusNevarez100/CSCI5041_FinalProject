
import inspect
import secrets

from charm.toolbox.pairinggroup import PairingGroup, G1, pair
from charm.schemes.ibenc import ibenc_bf01 as bf


def main():
    group = PairingGroup("MNT224", secparam=1024)
    ibe = bf.IBE_BonehFranklin(group)

    public, master = ibe.setup()

    print("=== Hash implementation ===")
    print(inspect.getsource(type(bf.h).hashToZn))

    print("\n=== Group configuration ===")
    print("Security parameter:", group.secparam)
    print("Message size:", group.messageSize())

    trials = 20

    sigma_lengths = []
    sigma_mask_lengths = []
    message_mask_lengths = []

    for _ in range(trials):
        key = secrets.token_bytes(32)
        encoded = b"\x01" + key

        sigma = bf.integer(
            bf.randomBits(group.secparam)
        )

        r = bf.h.hashToZr(sigma, encoded)

        q_id = group.hash("bob@example.com", G1)
        g_id = pair(q_id, public["P2"])

        sigma_mask = bf.h.hashToZn(g_id ** r)
        message_mask = bf.h.hashToZn(sigma)

        sigma_lengths.append(int(sigma).bit_length())
        sigma_mask_lengths.append(
            int(sigma_mask).bit_length()
        )
        message_mask_lengths.append(
            int(message_mask).bit_length()
        )

    print("\n=== Masking results ===")
    print("Trials:", trials)

    for name, values in [
        ("Sigma", sigma_lengths),
        ("Sigma mask", sigma_mask_lengths),
        ("Message mask", message_mask_lengths),
    ]:
        print(f"\n{name}:")
        print("  Minimum bits:", min(values))
        print("  Maximum bits:", max(values))
        print("  Average bits:", sum(values) / len(values))

    print("\nEncoded AES key storage: 264 bits")
    print("Encoded AES key integer: 257 bits")
    print("Secret AES key: 256 bits")


if __name__ == "__main__":
    main()

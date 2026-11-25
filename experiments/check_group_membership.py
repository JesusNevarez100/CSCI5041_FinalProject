from charm.toolbox.pairinggroup import (
    PairingGroup,
    G1,
    G2, 
    GT,
    ZR,
)

def main():
    group = PairingGroup("MNT224", secparam=1024)

    groups = [
        ("ZR", ZR),
        ("G1", G1),
        ("G2", G2),
        ("GT", GT),
    ]

    trials = 20

    print("Group membership investigation")
    print("Parameters: MNT224, secparam=1024")
    print(f"Trials per group: {trials}")

    for name, element_type in groups:
        generated_pass = 0
        deserialized_pass = 0
        roundtrip_pass = 0

        for _ in range(trials):
            element = group.random(element_type)

            if group.ismember(element):
                generated_pass += 1

            serialized = group.serialize(element)
            restored = group.deserialize(serialized)

            if group.ismember(restored):
                deserialized_pass += 1

            if element == restored:
                roundtrip_pass += 1

        print(f"\n{name}:")
        print(
            f"  Generated membership: "
            f"{generated_pass}/{trials}"
        )
        print(
            f"  Deserialized membership: "
            f"{deserialized_pass}/{trials}"
        )
        print(
            f"  Serialization roundtrip: "
            f"{roundtrip_pass}/{trials}"
        )


if __name__ == "__main__":
    main()

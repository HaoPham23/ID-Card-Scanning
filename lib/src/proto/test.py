p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
K = GF(p)
a = K(0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9)
b = K(0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6)
E = EllipticCurve(K, (a, b))
G = E(0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262, 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997)

terminalPriv = 0x9c51b817c9dd0070870f51eef0e17c91cbf62deafefc3a89c663644cc399bb03
terminalG = G*terminalPriv
terminalPub = E(54110343543465300697552807268765137054999877396372072236405201592716717971739, 25204876543186704810668404423272398203888083382627002633509077734678149407147)

iccPriv = 0x8cf0da6b91c3eae8fe6d6df75464e1b00ba5f11c4ba91fb987ab438e9d633f28
iccPub = E(54110343543465300697552807268765137054999877396372072236405201592716717971739,25204876543186704810668404423272398203888083382627002633509077734678149407147)

H_0 = iccPub*terminalPriv
print(H)

# nonce = 0x3F00C4D39D153F2B2A214A078D899B22 
# G_hat = H + nonce*G
# print(G_hat)